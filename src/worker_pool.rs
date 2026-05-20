//! Worker pool that drives per-proposal apply + validate in parallel.
//!
//! ## Grain
//!
//! WorkUnit grain is **per-proposal** (plan §C.4 Conc-1). Workflows
//! within one proposal run sequentially against a single sandboxed tree;
//! workers don't share trees with each other. This eliminates intra-
//! sandbox races without giving up the parallelism that matters for
//! monorepos where N is "dozens of independent bumps."
//!
//! ## Concurrency primitives
//!
//! - **Per-ecosystem [`Semaphore`]** — defends against ecosystem-level
//!   shared mutable resources. Cargo defaults to cap=1 (its
//!   `.cargo/registry/.package-cache` is held in MutateExclusive mode
//!   during `cargo update`). GHA defaults to unbounded.
//! - **Global git mutex** — `git worktree add` writes to `.git/worktrees`
//!   and consults `.git/index.lock`; concurrent worktree-adds race. The
//!   pool serializes that one call (plan §C.4 Conc-2).
//! - **Fail-fast stop flag** — when `--fail-fast` is set, the first
//!   non-success outcome flips an `AtomicBool`. Workers check before
//!   pulling the next unit; in-flight units run to completion (no
//!   forced kill).
//!
//! ## What ships here
//!
//! [`Semaphore`] (cap-of-N counting semaphore via `Mutex` + `Condvar`),
//! [`WorkerPool`] (config struct), and [`WorkerPool::run`] (the
//! orchestrator). The CLI's apply-local / apply-pr flow wraps each
//! proposal in a closure and hands it to the pool.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

/// Counting semaphore. `acquire()` blocks until a permit is free; the
/// returned [`SemaphorePermit`] releases on drop.
///
/// `new(0)` constructs an *unlimited* semaphore (no waiting). Use this
/// shape for "this ecosystem has no shared resource we care about" —
/// the cap then comes entirely from `--threads`.
pub struct Semaphore {
    permits: Mutex<usize>,
    cv: Condvar,
    unlimited: bool,
}

impl Semaphore {
    pub fn new(initial: usize) -> Self {
        Self {
            permits: Mutex::new(initial),
            cv: Condvar::new(),
            unlimited: initial == 0,
        }
    }

    pub fn acquire(&self) -> SemaphorePermit<'_> {
        if self.unlimited {
            return SemaphorePermit { sem: None };
        }
        let mut permits = self.permits.lock().unwrap();
        while *permits == 0 {
            permits = self.cv.wait(permits).unwrap();
        }
        *permits -= 1;
        SemaphorePermit { sem: Some(self) }
    }
}

#[must_use = "drop the permit to release the semaphore"]
pub struct SemaphorePermit<'a> {
    sem: Option<&'a Semaphore>,
}

impl Drop for SemaphorePermit<'_> {
    fn drop(&mut self) {
        if let Some(sem) = self.sem {
            let mut permits = sem.permits.lock().unwrap();
            *permits += 1;
            sem.cv.notify_one();
        }
    }
}

/// Config for the worker pool.
#[derive(Debug, Clone)]
pub struct WorkerPool {
    /// How many worker threads to spawn. Capped at the workload size
    /// inside `run` so we don't spawn idle threads.
    pub threads: usize,
    /// When true, the first non-success WorkUnit outcome flips the stop
    /// flag and workers exit at the top of their next iteration.
    pub fail_fast: bool,
}

impl WorkerPool {
    /// Default thread count: `min(4, available_parallelism())`. Matches
    /// the plan's default and stays under desktop OS scheduling thresholds.
    pub fn default_threads() -> usize {
        thread::available_parallelism()
            .map(|n| n.get().min(4))
            .unwrap_or(4)
    }

    /// Drive `process` across `units` in parallel.
    ///
    /// `process(unit, ctx) -> R` runs in a worker thread. The `ctx`
    /// provides:
    /// - `is_red`: classifier the pool uses to decide whether to flip
    ///   the fail-fast stop flag
    /// - `ecosystem_name(unit)`: maps a unit to its ecosystem so the
    ///   per-ecosystem semaphore is selected correctly
    /// - `semaphores`: map of ecosystem name → semaphore handle
    /// - `git_mutex`: serializes git-modifying preflight
    ///
    /// Workers pull from a shared `Mutex<Vec<U>>` (pop-back so order
    /// doesn't matter; the post-loop step sorts deterministically).
    pub fn run<U, R, F, IsRed, EcoName>(
        &self,
        units: Vec<U>,
        ctx: WorkerContext<'_>,
        process: F,
        is_red: IsRed,
        ecosystem_name: EcoName,
    ) -> Vec<R>
    where
        U: Send,
        R: Send,
        F: Fn(U, &WorkerContext<'_>) -> R + Sync,
        IsRed: Fn(&R) -> bool + Sync,
        EcoName: Fn(&U) -> &'static str + Sync,
    {
        if units.is_empty() {
            return Vec::new();
        }
        let n_threads = self.threads.max(1).min(units.len());
        let stop_flag = AtomicBool::new(false);
        let work_queue: Mutex<Vec<U>> = Mutex::new(units);
        let results: Mutex<Vec<R>> = Mutex::new(Vec::new());

        thread::scope(|scope| {
            for _ in 0..n_threads {
                let work_queue = &work_queue;
                let results = &results;
                let stop_flag = &stop_flag;
                let process = &process;
                let is_red = &is_red;
                let ecosystem_name = &ecosystem_name;
                let ctx = &ctx;
                let fail_fast = self.fail_fast;
                scope.spawn(move || {
                    loop {
                        if stop_flag.load(Ordering::Acquire) {
                            break;
                        }
                        let unit = {
                            let mut queue = work_queue.lock().unwrap();
                            queue.pop()
                        };
                        let Some(unit) = unit else { break };
                        let eco = ecosystem_name(&unit);
                        let permit = ctx
                            .semaphores
                            .iter()
                            .find(|(name, _)| *name == eco)
                            .map(|(_, sem)| sem.acquire());
                        let result = process(unit, ctx);
                        drop(permit);
                        if fail_fast && is_red(&result) {
                            stop_flag.store(true, Ordering::Release);
                        }
                        results.lock().unwrap().push(result);
                    }
                });
            }
        });

        results.into_inner().unwrap()
    }
}

/// Shared context handed to each worker. Static lifetime over the pool's
/// scope; nothing inside is mutated except via the semaphores' interior
/// mutability.
pub struct WorkerContext<'a> {
    /// Map of ecosystem name → semaphore handle. Looked up at unit
    /// dispatch time; missing entries default to no acquire.
    pub semaphores: Vec<(&'static str, Arc<Semaphore>)>,
    /// Mutex around `git worktree add` (and any other git-mutating
    /// preflight). Workers must `git_mutex.lock()` around those calls.
    pub git_mutex: &'a Mutex<()>,
    /// When `true`, the worker filters gate workflows by workspace-
    /// member precision before invoking the validator (`--member-gate`
    /// CLI flag).
    pub member_gate: bool,
    /// Event sink for real-time progress notifications. Workers
    /// emit `ProposalValidating` + `ProposalCompleted` (or
    /// `CohortValidating` + `CohortCompleted` for cohort lockstep
    /// units) at the boundaries of their work. The default
    /// `NoopEventSink` drops events when the user didn't request
    /// `--format ndjson`. Borrowed for the worker scope; the sink
    /// must be `Send + Sync`.
    pub event_sink: &'a (dyn crate::events::EventSink + 'a),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    #[test]
    fn semaphore_serializes_under_cap_one() {
        let sem = Arc::new(Semaphore::new(1));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_in_flight = Arc::new(AtomicUsize::new(0));
        let n = 8;
        thread::scope(|s| {
            for _ in 0..n {
                let sem = sem.clone();
                let in_flight = in_flight.clone();
                let max_in_flight = max_in_flight.clone();
                s.spawn(move || {
                    let _permit = sem.acquire();
                    let curr = in_flight.fetch_add(1, Ordering::AcqRel) + 1;
                    max_in_flight.fetch_max(curr, Ordering::AcqRel);
                    // Hold the permit long enough that another thread would
                    // race past us if the semaphore were broken.
                    thread::sleep(Duration::from_millis(50));
                    in_flight.fetch_sub(1, Ordering::AcqRel);
                });
            }
        });
        assert_eq!(
            max_in_flight.load(Ordering::Acquire),
            1,
            "semaphore cap=1 must serialize all threads"
        );
    }

    #[test]
    fn semaphore_zero_is_unlimited() {
        let sem = Arc::new(Semaphore::new(0));
        let counter = Arc::new(AtomicUsize::new(0));
        thread::scope(|s| {
            for _ in 0..16 {
                let sem = sem.clone();
                let counter = counter.clone();
                s.spawn(move || {
                    let _permit = sem.acquire();
                    counter.fetch_add(1, Ordering::AcqRel);
                });
            }
        });
        // No assertion on max-in-flight — the unlimited path doesn't
        // count permits. Reaching here without deadlock is the contract.
        assert_eq!(counter.load(Ordering::Acquire), 16);
    }

    #[test]
    fn semaphore_cap_n_lets_n_threads_through_concurrently() {
        let sem = Arc::new(Semaphore::new(3));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_in_flight = Arc::new(AtomicUsize::new(0));
        thread::scope(|s| {
            for _ in 0..12 {
                let sem = sem.clone();
                let in_flight = in_flight.clone();
                let max_in_flight = max_in_flight.clone();
                s.spawn(move || {
                    let _permit = sem.acquire();
                    let curr = in_flight.fetch_add(1, Ordering::AcqRel) + 1;
                    max_in_flight.fetch_max(curr, Ordering::AcqRel);
                    thread::sleep(Duration::from_millis(50));
                    in_flight.fetch_sub(1, Ordering::AcqRel);
                });
            }
        });
        let observed = max_in_flight.load(Ordering::Acquire);
        assert!(
            (2..=3).contains(&observed),
            "cap=3 should let 2-3 threads run concurrently; observed {observed}"
        );
    }

    #[test]
    fn pool_processes_every_unit() {
        let units: Vec<usize> = (0..20).collect();
        let ctx = WorkerContext {
            semaphores: vec![],
            git_mutex: &Mutex::new(()),
            member_gate: false,
            event_sink: &crate::events::NoopEventSink,
        };
        let pool = WorkerPool {
            threads: 4,
            fail_fast: false,
        };
        let results = pool.run(units, ctx, |u, _| u * 2, |_| false, |_| "noop");
        let mut sorted = results;
        sorted.sort();
        let expected: Vec<usize> = (0..20).map(|n| n * 2).collect();
        assert_eq!(sorted, expected);
    }

    #[test]
    fn pool_default_threads_is_at_least_one() {
        assert!(WorkerPool::default_threads() >= 1);
        assert!(WorkerPool::default_threads() <= 4);
    }

    #[test]
    fn pool_caps_thread_count_at_workload_size() {
        // 2 units + 8 threads requested — only 2 actually spawn.
        let units = vec![1usize, 2];
        let ctx = WorkerContext {
            semaphores: vec![],
            git_mutex: &Mutex::new(()),
            member_gate: false,
            event_sink: &crate::events::NoopEventSink,
        };
        let pool = WorkerPool {
            threads: 8,
            fail_fast: false,
        };
        let results = pool.run(units, ctx, |u, _| u, |_| false, |_| "noop");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn pool_fail_fast_stops_pulling_after_first_failure() {
        // 20 units; every one returns true (= "red"). With fail-fast on
        // and 1 thread, we should see exactly one result (the first red
        // flips the flag, the worker exits before pulling the next).
        let units: Vec<usize> = (0..20).collect();
        let ctx = WorkerContext {
            semaphores: vec![],
            git_mutex: &Mutex::new(()),
            member_gate: false,
            event_sink: &crate::events::NoopEventSink,
        };
        let pool = WorkerPool {
            threads: 1,
            fail_fast: true,
        };
        let results = pool.run(
            units,
            ctx,
            |u, _| u, // pass-through
            |_| true, // every result is "red"
            |_| "noop",
        );
        assert_eq!(
            results.len(),
            1,
            "fail-fast with 1 thread should yield exactly 1 result"
        );
    }

    #[test]
    fn pool_fail_fast_off_processes_every_unit_even_with_failures() {
        let units: Vec<usize> = (0..20).collect();
        let ctx = WorkerContext {
            semaphores: vec![],
            git_mutex: &Mutex::new(()),
            member_gate: false,
            event_sink: &crate::events::NoopEventSink,
        };
        let pool = WorkerPool {
            threads: 4,
            fail_fast: false,
        };
        let results = pool.run(units, ctx, |u, _| u, |_| true, |_| "noop");
        assert_eq!(
            results.len(),
            20,
            "without fail-fast, every unit completes regardless of failure"
        );
    }

    #[test]
    fn pool_per_ecosystem_semaphore_serializes_units_from_that_ecosystem() {
        let cargo_sem = Arc::new(Semaphore::new(1));
        // 10 units, all "cargo". cap=1 means none overlap.
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_in_flight = Arc::new(AtomicUsize::new(0));
        let units: Vec<usize> = (0..10).collect();
        let ctx = WorkerContext {
            semaphores: vec![("cargo", cargo_sem.clone())],
            git_mutex: &Mutex::new(()),
            member_gate: false,
            event_sink: &crate::events::NoopEventSink,
        };
        let pool = WorkerPool {
            threads: 4,
            fail_fast: false,
        };
        let in_flight_for_closure = in_flight.clone();
        let max_in_flight_for_closure = max_in_flight.clone();
        pool.run(
            units,
            ctx,
            |u, _| {
                let curr = in_flight_for_closure.fetch_add(1, Ordering::AcqRel) + 1;
                max_in_flight_for_closure.fetch_max(curr, Ordering::AcqRel);
                thread::sleep(Duration::from_millis(20));
                in_flight_for_closure.fetch_sub(1, Ordering::AcqRel);
                u
            },
            |_| false,
            |_| "cargo",
        );
        assert_eq!(
            max_in_flight.load(Ordering::Acquire),
            1,
            "cap=1 must keep cargo units strictly serialized"
        );
    }

    #[test]
    fn pool_unrelated_ecosystems_run_in_parallel_despite_a_capped_one() {
        // 4 cargo units (cap=1) + 4 gha units (unbounded). 4 threads.
        // The 4 GHA units should overlap; cargo serializes.
        let cargo_sem = Arc::new(Semaphore::new(1));
        let gha_in_flight = Arc::new(AtomicUsize::new(0));
        let gha_max = Arc::new(AtomicUsize::new(0));
        let units: Vec<(&'static str, usize)> = (0..4)
            .map(|i| ("cargo", i))
            .chain((0..4).map(|i| ("gha", i)))
            .collect();
        let ctx = WorkerContext {
            semaphores: vec![("cargo", cargo_sem.clone())],
            git_mutex: &Mutex::new(()),
            member_gate: false,
            event_sink: &crate::events::NoopEventSink,
        };
        let pool = WorkerPool {
            threads: 4,
            fail_fast: false,
        };
        let gha_in_flight_c = gha_in_flight.clone();
        let gha_max_c = gha_max.clone();
        pool.run(
            units,
            ctx,
            |u, _| {
                if u.0 == "gha" {
                    let curr = gha_in_flight_c.fetch_add(1, Ordering::AcqRel) + 1;
                    gha_max_c.fetch_max(curr, Ordering::AcqRel);
                    thread::sleep(Duration::from_millis(50));
                    gha_in_flight_c.fetch_sub(1, Ordering::AcqRel);
                } else {
                    thread::sleep(Duration::from_millis(20));
                }
                u
            },
            |_| false,
            |u| u.0,
        );
        // `gha_max >= 2` directly proves the property under test: GHA
        // units overlapped despite the cargo semaphore serializing the
        // cargo arm. An earlier `elapsed < 300ms` wall-clock proxy was
        // flaky on slow shared CI runners (observed: 474ms on a
        // macos-latest GitHub-hosted runner) without proving anything
        // additional — full serialization would still register
        // `gha_max == 1`, which this assertion catches directly.
        assert!(
            gha_max.load(Ordering::Acquire) >= 2,
            "expected at least 2 GHA units to overlap; only saw {}",
            gha_max.load(Ordering::Acquire)
        );
    }
}
