//! Real-time event stream for the `--format ndjson` output mode.
//!
//! Each [`Event`] is one JSON object per line on stdout. The stream
//! is consumed by GUI front-ends (e.g. `assay-gui`) and live-
//! progress sidecars that update UI state as proposals flow through
//! the worker pool, so a user pointing assay at a repo can watch
//! the sweep complete in real time rather than waiting for the
//! end-of-run summary.
//!
//! Schema stability: under the 1.0 promise, new event variants and
//! new fields are additive minor changes; existing variants and
//! required fields don't change shape within a major version.
//! `#[serde(default, skip_serializing_if = "Option::is_none")]` on
//! optional fields keeps the wire format clean.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;

use crate::failure_context::{FailureCluster, FailureContext};

/// One event emitted on the NDJSON stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// The run has begun. Emitted once at start with the full
    /// proposal inventory so the GUI can render the pending list
    /// before validation begins.
    RunStarted {
        run_id: String,
        started_at: String,
        repository: String,
        /// Ecosystems active in this run (after `--ecosystem` filter).
        ecosystems: Vec<String>,
        /// All proposals surfaced by the proposer phase, in stable
        /// order. Each carries the metadata the GUI needs to render
        /// a "pending" row.
        proposals: Vec<EventProposal>,
        /// Cohort groupings (multi-member only). The GUI uses this
        /// to render the visual affordance grouping cohort members
        /// under one container.
        cohorts: Vec<EventCohort>,
    },
    /// A worker has picked up a proposal and started the apply +
    /// validate cycle. Emitted once per non-cohort proposal.
    ProposalValidating { id: String, subject: String },
    /// A worker has picked up a multi-member cohort and started
    /// the atomic apply + validate cycle. Emitted once per cohort
    /// group; individual member `ProposalValidating` events are
    /// NOT emitted for cohort members.
    CohortValidating {
        cohort: String,
        display: String,
        member_ids: Vec<String>,
    },
    /// A single proposal has finished validating. Conclusion is one
    /// of `success`, `failure`, `unvalidated`.
    ProposalCompleted {
        id: String,
        subject: String,
        conclusion: String,
        duration_ms: u64,
        /// Structured failure context. `Some(_)` on every `failure`
        /// conclusion (even unparseable stderr produces a
        /// `rule:"generic:unstructured"` context); `None` on
        /// `success` / `unvalidated`. Shipped in 1.6.0 — additive
        /// per the 1.0 stability promise.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        failure_context: Option<FailureContext>,
    },
    /// A multi-member cohort has finished validating atomically.
    /// The same conclusion applies to every member.
    CohortCompleted {
        cohort: String,
        conclusion: String,
        member_ids: Vec<String>,
        duration_ms: u64,
    },
    /// Final summary; the run is complete. Emitted once at the
    /// end. After this event, no further events are emitted on
    /// the stream.
    RunCompleted {
        summary: EventSummary,
        run_json_path: String,
        finished_at: String,
        /// Root-cause clusters: proposals that failed for the
        /// same reason (shared fingerprint over their parsed
        /// findings). Empty when no two proposals share a
        /// fingerprint (singletons are excluded — a cluster of
        /// one is not a cluster). Shipped in 1.6.0 — additive
        /// per the 1.0 stability promise.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        failure_clusters: Vec<FailureCluster>,
    },
}

/// Per-proposal metadata included in the `RunStarted` event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventProposal {
    pub id: String,
    pub subject: String,
    pub from: String,
    pub to: String,
    pub tier: String,
    pub ecosystem: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cohort: Option<String>,
}

/// Per-cohort grouping included in the `RunStarted` event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventCohort {
    /// Stable cohort id (e.g. `angular-framework`, `tokio`).
    pub id: String,
    /// Human-readable display name (e.g. `@angular/* framework`,
    /// `tokio + tokio-*`).
    pub display: String,
    /// Proposal ids that belong to this cohort, in stable order.
    pub member_ids: Vec<String>,
}

/// Final run summary in `RunCompleted`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSummary {
    pub proposals_total: usize,
    pub proposals_passed: usize,
    pub proposals_failed: usize,
    pub proposals_unvalidated: usize,
    pub proposals_shipped: usize,
}

/// Sink that accepts events from the pipeline and emits them
/// somewhere. The pipeline calls `emit` from multiple threads, so
/// implementations must be `Send + Sync`.
pub trait EventSink: Send + Sync {
    /// Emit one event. Errors are swallowed by convention — losing
    /// a progress event must never abort the run.
    fn emit(&self, event: Event);
}

/// No-op sink — events are dropped. Used when `--format` is `text`
/// or `json`. Pipeline code can always call `emit` without
/// branching on output format.
pub struct NoopEventSink;

impl EventSink for NoopEventSink {
    fn emit(&self, _event: Event) {}
}

/// Sink that writes each event as a JSON line on stdout.
/// `Mutex` serializes concurrent writers so two threads can't
/// interleave a single JSON line. (`stdout` is line-buffered, but
/// `println!` itself isn't atomic across multiple `write_all`
/// calls under heavy contention.)
pub struct NdjsonStdoutSink {
    lock: Mutex<()>,
}

impl NdjsonStdoutSink {
    pub fn new() -> Self {
        Self {
            lock: Mutex::new(()),
        }
    }
}

impl Default for NdjsonStdoutSink {
    fn default() -> Self {
        Self::new()
    }
}

impl EventSink for NdjsonStdoutSink {
    fn emit(&self, event: Event) {
        let Ok(line) = serde_json::to_string(&event) else {
            return;
        };
        // Hold the lock through the println so the line + newline
        // land together. Poisoned-lock case: the panicking thread
        // already corrupted the stream; recovering via PoisonError
        // would print a half-line; just drop the event silently.
        let Ok(_guard) = self.lock.lock() else {
            return;
        };
        println!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_round_trips_through_json() {
        let evt = Event::ProposalCompleted {
            id: "npm-foo".into(),
            subject: "foo".into(),
            conclusion: "success".into(),
            duration_ms: 1234,
            failure_context: None,
        };
        let s = serde_json::to_string(&evt).unwrap();
        assert!(s.contains(r#""type":"proposal_completed""#));
        let back: Event = serde_json::from_str(&s).unwrap();
        match back {
            Event::ProposalCompleted { id, .. } => assert_eq!(id, "npm-foo"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn proposal_completed_carries_failure_context_when_red() {
        let ctx = FailureContext::new(
            "cargo:rustc-error",
            "E0277: trait not impl",
            vec![crate::failure_context::FailureFinding {
                code: Some("E0277".into()),
                message: "trait not impl".into(),
                file: Some("src/lib.rs".into()),
                line: Some(42),
                column: Some(7),
            }],
        );
        let evt = Event::ProposalCompleted {
            id: "cargo-foo".into(),
            subject: "foo".into(),
            conclusion: "failure".into(),
            duration_ms: 1234,
            failure_context: Some(ctx.clone()),
        };
        let s = serde_json::to_string(&evt).unwrap();
        assert!(
            s.contains("failure_context"),
            "wire format must carry failure_context; got {s}"
        );
        assert!(s.contains("cargo:rustc-error"));
        let back: Event = serde_json::from_str(&s).unwrap();
        match back {
            Event::ProposalCompleted {
                failure_context, ..
            } => {
                assert_eq!(failure_context, Some(ctx));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn proposal_completed_skips_failure_context_when_none() {
        let evt = Event::ProposalCompleted {
            id: "npm-foo".into(),
            subject: "foo".into(),
            conclusion: "success".into(),
            duration_ms: 1234,
            failure_context: None,
        };
        let s = serde_json::to_string(&evt).unwrap();
        assert!(
            !s.contains("failure_context"),
            "None must be elided from the wire format; got {s}"
        );
    }

    #[test]
    fn run_completed_carries_failure_clusters_when_present() {
        let ctx = FailureContext::new(
            "cargo:rustc-error",
            "E0277",
            vec![crate::failure_context::FailureFinding {
                code: Some("E0277".into()),
                message: "trait not impl".into(),
                file: None,
                line: None,
                column: None,
            }],
        );
        let cluster = FailureCluster {
            fingerprint: ctx.fingerprint.clone(),
            proposal_ids: vec!["a-1".into(), "a-2".into()],
            representative: ctx,
        };
        let evt = Event::RunCompleted {
            summary: EventSummary {
                proposals_total: 2,
                proposals_passed: 0,
                proposals_failed: 2,
                proposals_unvalidated: 0,
                proposals_shipped: 0,
            },
            run_json_path: "/tmp/run.json".into(),
            finished_at: "2026-05-20T00:00:00Z".into(),
            failure_clusters: vec![cluster.clone()],
        };
        let s = serde_json::to_string(&evt).unwrap();
        assert!(s.contains("failure_clusters"));
        let back: Event = serde_json::from_str(&s).unwrap();
        match back {
            Event::RunCompleted {
                failure_clusters, ..
            } => {
                assert_eq!(failure_clusters, vec![cluster]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn run_completed_skips_failure_clusters_when_empty() {
        let evt = Event::RunCompleted {
            summary: EventSummary {
                proposals_total: 0,
                proposals_passed: 0,
                proposals_failed: 0,
                proposals_unvalidated: 0,
                proposals_shipped: 0,
            },
            run_json_path: "/tmp/run.json".into(),
            finished_at: "2026-05-20T00:00:00Z".into(),
            failure_clusters: Vec::new(),
        };
        let s = serde_json::to_string(&evt).unwrap();
        assert!(
            !s.contains("failure_clusters"),
            "empty cluster vec must be elided from the wire format; got {s}"
        );
    }

    #[test]
    fn event_with_cohort_field_is_present() {
        let evt = Event::CohortValidating {
            cohort: "angular-framework".into(),
            display: "@angular/* framework".into(),
            member_ids: vec!["npm-1".into(), "npm-2".into()],
        };
        let s = serde_json::to_string(&evt).unwrap();
        assert!(s.contains(r#""type":"cohort_validating""#));
        assert!(s.contains(r#""cohort":"angular-framework""#));
    }

    #[test]
    fn proposal_optional_cohort_is_skipped_when_none() {
        let p = EventProposal {
            id: "npm-foo".into(),
            subject: "foo".into(),
            from: "1.0.0".into(),
            to: "2.0.0".into(),
            tier: "breaking".into(),
            ecosystem: "npm".into(),
            cohort: None,
        };
        let s = serde_json::to_string(&p).unwrap();
        assert!(
            !s.contains("cohort"),
            "stand-alone proposal should not serialize an empty cohort field; got: {s}"
        );
    }

    #[test]
    fn noop_sink_drops_events() {
        let sink = NoopEventSink;
        sink.emit(Event::ProposalValidating {
            id: "x".into(),
            subject: "y".into(),
        });
        // No assertion needed — just verifying the trait impl
        // doesn't crash on a no-op.
    }
}
