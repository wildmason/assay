# Assay — Dependency Upgrade Impact Analyzer

> Status: Draft (round 2) · 2026-05-17

## Goal

Build **assay**, a standalone CLI tool that answers two questions about any project's dependencies: **(1) what can be upgraded?** and **(2) what happens to our project if we upgrade?** It does so by enumerating available bumps for the chosen ecosystem, applying each candidate to a sandboxed copy of the working tree, and running the project's own CI workflows (or a fallback build+test command) against the upgraded tree. The verdict is binary — pass or fail — with rich per-workflow failure-flavor reporting (REGRESSION / SETUP-FAILURE / TIMEOUT). Three output modes (report-only, `--apply-local`, `--apply-pr`) let the operator either inspect, commit the validated change-set to the current branch, or open a pre-validated pull request.

The motivating use case is the day-job monorepo problem: dozens of consumer projects depend on a shared `package.json`/`Cargo.toml`/`go.mod`, and dependency upgrades stall because nobody owns the full chain of "will this break any of our 47 consumers?" Assay automates that ownership: point it at a workspace root, get a per-consumer pass/fail report, ship the upgrade or skip it with evidence either way.

Assay is single-tenant, runs on the operator's own machine, and uses the operator's existing GitHub credentials (`gh auth token` / `$GH_TOKEN`) for the optional `--apply-pr` mode. It complements but does not depend on **ci-forge** (the sibling Wildmason GitHub-Actions-without-GitHub runner): when `forge` is on PATH, assay uses it to run the project's real workflows locally; when it isn't, assay falls back to manifest-inferred build+test commands.

## Scope

### In scope (v1)

- **Two ecosystems:** Cargo and GitHub Actions (`uses:` SHA pinning). Both already implemented in the imported baseline (see Current State); the work is repurposing, not building from scratch.
- **CLI surface:** `assay analyze --project <manifest>` as the single primary verb. Subflags govern output mode (`--apply-local` / `--apply-pr`), parallelism (`--threads N`), validator override (`--gate ...`), and workflow scope (`--include-workflow` / `--exclude-workflow`).
- **Workspace awareness:** when `--project` points at a workspace root (`Cargo.toml` with `[workspace]`, `package.json` with `"workspaces"`), assay analyzes the whole resolution scope and reports per-workspace-member breakdown — but only for members where the upgraded dep actually appears in the dep graph.
- **All-must-pass aggregation:** verdict is `pass` only if every gate workflow returns success across every affected consumer. One red consumer → overall `fail`. Per-consumer/per-workflow detail surfaced in the report.
- **Validator hierarchy** via the `ValidatorBackend` trait (see §C.4.c): a `ForgeRunBackend` (shells out to `forge run`), a `BuildTestBackend` (manifest-inferred commands like `cargo test --workspace`), and a `CustomBackend` (`--gate-cmd` / `--gate-file`). Selection happens once at validator construction; per-WorkUnit dispatch is virtual through the trait.
- **Binary verdict + flavor tags:** per workflow, classify the failure as one of `REGRESSION` (workflow ran, returned non-success), `SETUP-FAILURE` (workflow couldn't start — missing secret, unsupported step, executor crash), or `TIMEOUT` (killed after `--workflow-timeout`).
- **Three output modes:**
  - **`report-only` (default):** print the report, no mutations.
  - **`--apply-local`:** commit the validated change-set to the *current* branch (atomic commit, no branch, no push, no PR). Sandbox state is *copied back* to the host tree to preserve determinism (see §C.6).
  - **`--apply-pr`:** create a branch, push it, open a PR via `gh pr create`. PR body carries the impact report inline.
- **`--threads N` parallelism** over `(proposal)` work units with **per-ecosystem caps** (default Cargo cap = 1 because of the `~/.cargo/.package-cache` global lock; default GHA cap = unlimited). Default `min(4, num_cpus)` for the global pool. Run-all-and-report (not fail-fast) by default; `--fail-fast` opt-in.
- **`--workflow-timeout <duration>`:** per-workflow kill switch. Default 30 minutes. Flavor-tagged as `TIMEOUT` when triggered. Implemented via the `wait-timeout` crate + OS-native process-group lifecycle so descendant processes (docker containers, child cargo processes) don't survive their owning workflow.
- **Receipts:** structured run record written to `.assay/runs/<run-id>/run.json` plus per-stage receipts under `.assay/runs/<run-id>/receipts/<stage>/...`. Schema-versioned. Designed to be aggregated by a CI matrix orchestrator after fan-out across consumer projects.
- **Configuration:** `.assay.toml` at project root for sticky overrides (timeout defaults, gate command, workflow include/exclude patterns, executor preference, per-ecosystem parallelism caps).

### Out of scope (v1)

- **Ecosystems beyond Cargo + GHA.** npm/pnpm/yarn is the obvious next target given the monorepo motivation, but it's a real lift (lockfile semantics differ across the three; package.json workspace resolution is non-trivial; the Applier shape is fundamentally different — npm needs explicit lockfile diff writes, not re-resolve). v1 ships with what's already built.
- **User-specified upgrade target.** v1 enumerates all available bumps for the ecosystem. A future flag like `assay analyze --dep foo@1.1.0` to validate one specific upgrade is a v1.5 feature.
- **Cross-repo orchestration.** v1 operates on one repo per invocation. Users with N repos use a shell loop or CI matrix; the manifest-pointed CLI design (Unix philosophy) makes that trivial.
- **Flake retry.** No automatic re-runs on workflow failure. Flake is the team's CI problem; assay reports what ran.
- **Custom PR templates.** v1 generates a fixed report-driven PR body. Configurable templates are v1.5.
- **GitHub App registration.** Single-tenant tool using user's existing `gh` auth. No App scaffolding.
- **Non-GitHub forges.** GitLab / Bitbucket / Gitea support is later. v1 ships a single concrete `gh_cli::open_pr` function; a `PullRequestBackend` trait will be introduced when the second impl materializes (see Review Pass 1, Arch-4).
- **Per-WorkUnit parallelism of workflows within the same proposal.** Each proposal's workflows run sequentially against a single sandboxed tree per worker to eliminate shared-tree races. Most monorepo workloads have N proposals × few workflows; the per-proposal parallelism is plenty.
- **Aggressive `--fail-fast` (kill-in-flight).** v1's `--fail-fast` drains the queue but lets in-flight units complete (or hit their own `--workflow-timeout`). A future `--fail-fast-kill` flag for users who want aggressive cancellation.

## Current State

The repo at `C:\Users\Matt\Documents\development\@wildmason\oss\assay\` was just cloned (empty) and has the previous **forge-tinker** baseline imported at `crates/forge-tinker/`. That baseline was built under the original "Dependabot-equivalent for self-hosted CI" framing, which we pivoted away from after discovering that the more defensible value prop is **impact analysis for monorepos**, not PR generation. Most of the baseline code transfers cleanly to the new framing; the bits that don't get ripped out, not adapted.

### What carries over (~75% of baseline LOC, verified at file:line)

- **`crates/forge-tinker/src/ecosystem/mod.rs`** — `DependencyEcosystem` trait. Methods (`detect_manifests`, `propose_updates`, `affected_workflows`, `apply_proposal`, `pr_body_fragment`) are exactly what an analyzer needs. Carries over verbatim under the new package name, with one rename: `affected_workflows` → `gate_workflows` (clearer; these are candidate gate workflows, not "workflows touched by the proposal"), and one new method: `affected_consumers(&Proposal, &Path) -> Vec<ConsumerId>` for the new Resolver stage (§C.3.5).
- **`crates/forge-tinker/src/ecosystem/cargo.rs`** — Cargo impl. `cargo update --dry-run --workspace` enumeration + lockfile cross-check (`propose_from_cargo_dry_run` at cargo.rs:235) defends against parser drift; `git clone --local --no-hardlinks` (cargo.rs:467-491) provides the sandbox; `apply_cargo_update_to_tree` (cargo.rs:320-348) lands changes. Workspace-aware via cargo's own resolver (cargo.rs:47-50). Carries over directly.
- **`crates/forge-tinker/src/ecosystem/github_actions.rs`** — GHA impl with YAML byte-range rewriter that preserves formatting/comments. Detects `uses:` references; defends against double-application via `from` mismatch. Carries over directly. Reused by `--apply-local`'s copy-back path with the same `from` mismatch defense.
- **`crates/forge-tinker/src/validator.rs`** — already shells out to `forge run` via `ValidatorCommandBuilder::build_argv` (validator.rs:195-214). Narrow flag set pinned in one place; receipt JSON parser at validator.rs:236-255 reads `run_id` + `conclusion` with fallback to `workflows[].conclusion`. **Repurposes as the `ForgeRunBackend` impl** (§C.4.c).
- **`crates/forge-tinker/src/sanitize.rs`** — PR body / branch name / commit subject sanitization (charset filters, CRLF stripping, HTML escaping, UTF-8-boundary-safe truncation). Adversarial tests cover shell-injection inputs. Used by both `--apply-local` (commit message) and `--apply-pr` (PR body) paths.
- **`crates/forge-tinker/src/redact.rs`** — Two-layer redactor: value registry (`Arc<RwLock>`) + regex pre-filter for `ghs_*`/`ghp_*`/`Bearer ...` token shapes. Verified by concurrency review: registration is rare (per-run token registration), reads dominate, RwLock is the right primitive — no parallel-logging bottleneck.
- **`crates/forge-tinker/src/receipt.rs`** — Writes `run.json` plus per-stage receipts. `write_run_receipt` (receipt.rs:19-44) **pre-creates `receipts/` and `logs/` subdirectories** at the call site, with an in-code comment at receipt.rs:28 documenting this is to prevent races. We exploit this: top-level `write_run_receipt` is invoked **once** before fan-out, then workers `fs::write` files into the pre-existing dirs (no parallel `create_dir_all`). Path renames from `.ci-forge/tinker-runs/` → `.assay/runs/` and the stage-filename schema gets restructured (§H).
- **`crates/forge-tinker/src/publisher/branch_name.rs`** — Deterministic + injective branch name generation. Carries over for `--apply-pr`. Prefix renames from `forge-tinker/` → `assay/`.
- **`crates/forge-tinker/src/publisher/git_push.rs`** — Shell-safe argv construction for `git push`; charset validation rejects metacharacters. Carries over.
- **`crates/forge-tinker/src/publisher/guards.rs`** — Three independent push-target guards. Carries over.
- **`crates/forge-tinker/src/publisher/pr_body.rs`** — PR body rendering with sanitizer-routed release notes. Carries over.
- **`crates/forge-tinker/src/model.rs`** — `Classification`, `Manifest`, `Proposal`, `ValidationOutcome`, `TinkerRunReceipt`, `RunSummary`, `Provenance`, `ProvenanceRecord`. Mostly carries; `TinkerRunReceipt` renames to `AssayRunReceipt`. The `Proposal` shape gets a new optional `affected_consumers: Vec<ConsumerId>` field populated by the Resolver.
- **147 unit tests** across the baseline. Most transfer with file-path rename + a few semantic adjustments for the new `--apply-local` meaning and the per-stage receipt schema. Expected lossage: 15-20 tests that exercised App-auth specifically; expected additions: 30-50 new tests across parallelism, fallback validator, failure-flavor classification, per-ecosystem cap respect, deterministic apply order, child-process kill semantics.

### What gets deleted

- **`crates/forge-tinker/src/auth/jwt.rs`** — GitHub App JWT signer. Not needed.
- **`crates/forge-tinker/src/auth/secrets.rs`** — 0600-enforced App-secrets loader. Not needed.
- **`crates/forge-tinker/src/auth/test_rsa_key.pem`** — test fixture. Not needed.
- **`crates/forge-tinker/src/auth/mod.rs`** — entire auth module. Not needed.
- **`jsonwebtoken = "9"` dep** at `crates/forge-tinker/Cargo.toml:22`. Removed with JWT module.
- **`forge-core.workspace = true` dep** at `crates/forge-tinker/Cargo.toml:21`. Verified unused (`grep "use forge_core"` returned zero matches). Dead dep.
- **`forge-tinker init github-app` subcommand** if present. App-registration scaffolding goes.
- **`--secret-file <path>` CLI flag** at `cli.rs:77`. Replaced by automatic gh CLI discovery.
- **`--apply-remote` flag** at `cli.rs:57` renamed to `--apply-pr` and rewired to the gh-backed publisher.
- **Hardcoded App-auth error message** at `cli.rs:165-168` pointing to `forge-tinker init github-app`. Deleted.
- **`PullRequestBackend` trait + `UnconfiguredBackend` + `RecordingBackend`** in `publisher/mod.rs:53-106`. The file's own header comment at `publisher/mod.rs:11-13` already self-flags this ("there is NO trait until a second impl materializes"). v1 has one impl (`GhCliBackend`) — accept the comment's verdict. Test seam is fixture-PATH `gh` binary (same pattern as `which("forge")`).

### What gets restructured

- **Single-crate flat layout.** `crates/forge-tinker/{src,Cargo.toml}` moves to repo root (`./src/`, `./Cargo.toml`). The `crates/forge-tinker/` directory is removed.
- **`Cargo.toml` workspace inheritance removed.** Fields like `edition.workspace = true` at `crates/forge-tinker/Cargo.toml:4` become concrete values (`edition = "2024"`).
- **Renames:** crate/binary/library `forge-tinker` → `assay`; config filename `.forge-tinker.toml` → `.assay.toml`; receipt dir `.ci-forge/tinker-runs/` → `.assay/runs/`; branch prefix `forge-tinker/` → `assay/`.
- **CLI verb:** `scan` → `analyze` at `cli.rs:29-31`.

### What gets reworked semantically

The biggest semantic shift is **`--apply-local`**. Today (`cli.rs:425-470`) it creates an isolated retained worktree at `.ci-forge/tinker-runs/<id>/work/<proposal>` so the operator can inspect the bumped state without touching the original tree. Under the new architecture, `--apply-local` means **commit the validated change-set to the current branch as an atomic commit, no branch, no push, no PR**. Substantively different code path — see §C.6 for the pinned mechanics.

The other restructure is the **Validator's work-unit grain and backend dispatch**. Today's validator (`validator.rs:59-148`) runs workflows in a sequential `for` loop on the same thread, hardcoded to `forge run`. The new design uses a `(proposal)`-grained work queue with a trait-dispatched backend (§C.4). Per-proposal parallelism only — workflows within one proposal run sequentially against the same sandboxed tree, eliminating shared-tree races (per Review Pass 1, Conc-1).

### Open gaps to address in the new architecture

The Round 1 plan called out five gaps. After Review Pass 1, two more emerged. The seven gaps the implementation closes:

1. **`--threads N` parallelism** — `Validator::validate` runs single-threaded today. New: `(proposal)`-grained work queue with thread pool (§E).
2. **Fallback validator** — `Validator::new` hardcodes `forge_bin = "forge"` (validator.rs:48-54). New: `ValidatorBackend` trait with `ForgeRunBackend` / `BuildTestBackend` / `CustomBackend` impls (§C.4.c).
3. **Failure-flavor classification** — today's conclusion is binary success/non-success (validator.rs:316-320). New: per-workflow `REGRESSION` / `SETUP-FAILURE` / `TIMEOUT` tags (§C.4.b).
4. **`pull_request`-trigger filtering** — `CargoEcosystem::affected_workflows` (cargo.rs:70-98) returns every workflow. New: trigger-event filter applied at the Validator stage, not at the ecosystem trait method (per Arch-3) — keeps the trait surface minimal and the YAML `on:` parser in one place.
5. **Workspace-member dep-graph filtering** — today no stage owns this. New: dedicated **Resolver** stage between Proposer and Applier (per Arch-2). Owns `cargo metadata` invocation, walks dep graph, populates `Proposal::affected_consumers`.
6. **Concurrent child-process lifecycle on Windows** — today `Child::kill` doesn't reach descendants (Win32 limitation). New: Win32 job objects (`CREATE_NEW_PROCESS_GROUP` + `AssignProcessToJobObject` + `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) on Windows; `setpgid` + `killpg` on Unix. Implemented via the `win32job` crate (Windows) and `nix`'s process-group helpers (Unix), with `wait-timeout` providing the watchdog primitive — see §C.4.f.
7. **Per-ecosystem parallelism caps** — `cargo update` acquires the `~/.cargo/.package-cache` global advisory lock. N parallel cargo workers serialize on that lock, making `--threads` a lie for cargo-heavy runs. New: per-ecosystem semaphores with cargo default = 1 (§C.4.e).

## Proposed Approach

### A. Architecture overview

Assay is a single Rust binary that drives a six-stage pipeline per `assay analyze` invocation:

```
Scanner → Proposer → Resolver → Applier → Validator → Reporter → [optional: Publisher]
                          (NEW)              (work-queue)
```

Each stage is a module:

- **Scanner** (`ecosystem::*::detect_manifests`): walk the target rooted at `--project <manifest>`, infer the ecosystem from the manifest type, enumerate manifest files.
- **Proposer** (`ecosystem::*::propose_updates`): per ecosystem, produce a list of `Proposal`s describing each available upgrade. For Cargo: shell out to `cargo update --dry-run --workspace` + lockfile diff cross-check. For GHA: read each workflow, find `uses: <action>@<sha>` lines, resolve the latest tagged SHA upstream via a *shared* Octocrab client (see §C.2).
- **Resolver** (NEW — `crate::resolver`): for each `Proposal`, compute the set of workspace members that consume the bumped dep. Populates `Proposal::affected_consumers`. For Cargo: invokes `cargo metadata --format-version 1`, walks the dep graph from each member's root, marks members whose tree contains the bumped crate. For GHA (single-project, no workspace-member axis): no-op; `affected_consumers` stays empty.
- **Applier** (`ecosystem::*::apply_proposal`): apply one proposal to a sandboxed tempdir clone. The Applier writes into a per-WorkUnit tree clone so concurrent workers never share filesystem state. `git clone --local --no-hardlinks` (cargo.rs:467) is the cloning primitive; clone operations are **serialized via a global mutex** to defend against `.git/index.lock` races against the operator's IDE (per Conc-2).
- **Validator** (`validator::Validator`): pop `(proposal)`-grained work units from the queue, dispatch to the backend, run each gate workflow sequentially against the sandboxed tree. Returns a per-proposal `ValidationOutcome` aggregating per-workflow outcomes (Pass / Regression / SetupFailure / Timeout).
- **Reporter**: aggregate per-proposal outcomes into a binary verdict, render text or JSON, write the run receipt + per-stage receipts. Logs are streamed to disk during validation; only summary references make it to the result channel (per Conc-6).
- **Publisher** (only on `--apply-local` or `--apply-pr`): apply green proposals to the operator's tree (in deterministic order — sorted by proposal ID lex order per Conc-9), commit (`--apply-local`) or branch+push+PR (`--apply-pr`).

The new architectural moves vs Round 1: **Resolver** is a first-class stage; **Validator** uses a trait-dispatched backend; **WorkUnit grain** is per-proposal not per-workflow (workflows run sequentially within a worker against a single sandboxed tree).

### B. CLI surface (target shape)

```
assay analyze [OPTIONS] --project <PATH>

Required:
  --project <PATH>           Manifest file (Cargo.toml, package.json, etc.)
                             OR directory containing one. Type infers ecosystem.

Modes (mutually exclusive):
  (default)                  Report only. No mutations.
  --apply-local              Commit validated change-set to current branch.
  --apply-pr                 Branch + push + open PR via `gh pr create`.

Parallelism:
  --threads <N>              Global pool size. Default min(4, num_cpus).
  --allow-cargo-parallel     Override the cargo cap-of-1 default
                             (use only if you're sure cargo cache lock
                             contention is acceptable).
  --fail-fast                Drain queue at first failure. In-flight units
                             still run to their own timeout. Default off.

Validator gate:
  --gate <MODE>              auto (default) | compile | tests | ci
  --gate-cmd <CMD>           Override with a shell command.
  --gate-file <PATH>         Override with a script.
  --workflow-timeout <D>     Per-workflow kill. Default 30m.
  --include-workflow <PAT>   Glob; can repeat. Additive overlay.
  --exclude-workflow <PAT>   Glob; can repeat. Subtractive overlay.

Ecosystem filtering:
  --ecosystem <NAME>         cargo | github-actions | all. Default: all.

Output:
  --format <FORMAT>          text (default) | json.
  --quiet                    Only print the final verdict line.

Safety:
  --force                    Override safety refusals (clean-tree, etc).
  --executor <KIND>          host | docker (passed to forge run).
  --unsafe-host-validation   Required when --executor host + apply mode.

Misc:
  --config <PATH>            Override default .assay.toml path.
  --run-id <ID>              Force a specific run id.
  --no-color                 Disable ANSI colors.
```

Single primary verb `analyze`. All other behavior is flag-driven.

### C. Pipeline stages — detailed

#### C.1 Scanner

Given `--project <PATH>`:
- If `PATH` is a directory: look for `Cargo.toml`, `package.json`, `go.mod`, `pyproject.toml`, `Gemfile` in that order. First match wins. Multiple matches → error: "ambiguous manifest at `<dir>` — pass the manifest file directly".
- If `PATH` is a file: infer ecosystem from filename. `Cargo.lock` rejected (point at manifest, not lockfile).
- The chosen ecosystem's `detect_manifests` runs against the manifest's directory.
- For Cargo: returns root `Cargo.toml` + `Cargo.lock` (cargo.rs:26-51) — workspace resolution from the root.

The Scanner writes a single receipt at `.assay/runs/<run-id>/receipts/scanner.json` and never executes in parallel.

#### C.2 Proposer

Cargo: existing `run_cargo_proposer` (cargo.rs:358-435) carries over directly. The cross-check at cargo.rs:266-312 defends against cargo stdout drift.

GHA: enumerates `uses:` references and resolves each to the latest tagged SHA via a **shared Octocrab client** (one instance per run, held in `Arc<Mutex<Octocrab>>` or `Arc<Octocrab>` if Octocrab's API is thread-safe — verify at implementation time). HTTP requests go through a single client to benefit from connection pooling and rate-limit accounting.

**Rate-limit handling (per Conc-12, refined by Round 2 research):** GitHub enforces both a **primary** rate limit (authenticated PATs: 5000/hr, surfaced via `x-ratelimit-remaining` / `x-ratelimit-reset` headers) and **secondary** rate limits (100 concurrent requests, 900 points/min/endpoint, 90s CPU/60s real-time). The GHA proposer:

- **Honors `x-ratelimit-remaining` proactively** — if remaining ≤ 10, sleep until `x-ratelimit-reset` before issuing more requests. Avoids the avoidable-429 hit.
- **Retries on 429 / 403-with-secondary-rate-limit-message** with `Retry-After` header. When `Retry-After` is missing (a documented gap on secondary rate limits, see references), fall back to a 60-second wait.
- **Caps concurrent in-flight GHA API requests at < 100** via an `Arc<Semaphore>` separate from `--threads`. With `--threads 4` running 4 GHA proposers in parallel, each proposer may issue multiple in-flight requests; the semaphore is a project-wide ceiling, not per-worker.
- **Max 3 retries per call**, total budget 60s per proposal. Beyond that, the proposal is reported as `SETUP-FAILURE` (we couldn't enumerate the upgrade target).

At typical assay scan sizes (≤200 actions across a project), the primary limit is irrelevant — 200 calls is 4% of an hourly budget. The secondary concurrent-request limit is the real constraint at high `--threads` values.

**v1 simplification: no user-specified target.** The Proposer enumerates *all* available bumps. v1.5 feature: `assay analyze --dep <name>@<version>` to validate one specific upgrade.

Each `Proposal` is written to `.assay/runs/<run-id>/receipts/proposer/<proposal-id>.json` (per Conc-8).

#### C.3 Applier

The Applier writes into a **per-WorkUnit tempdir clone**. Each work unit (one per `Proposal`) gets its own sandboxed tree via `git clone --local --no-hardlinks` (cargo.rs:467-491).

**Clone serialization (per Conc-2):** the clone primitive is wrapped in a global `Mutex<()>` so at most one `git clone` runs at a time against the operator's source `.git/`. This defends against:
- Concurrent index.lock contention with the operator's IDE
- Repack/gc operations interleaving with reads from packfiles
- Cross-worker mutual interference on shared git state

The lock is held only for the clone duration (~1s for typical repos); apply + validate steps run unlocked and in parallel.

Once cloned, the ecosystem's `apply_proposal` writes changes:
- Cargo: `apply_cargo_update_to_tree` (cargo.rs:320-348) — runs `cargo update --workspace` in the tempdir.
- GHA: byte-range rewrite of `uses:` lines, preserving formatting (existing baseline).

Per-WorkUnit isolation means concurrent workers never share `target/`, never share `~/.cargo/registry` cache contention beyond what cargo itself locks, never collide on workflow scratch files.

Each apply produces a receipt at `.assay/runs/<run-id>/receipts/applier/<proposal-id>.json` containing the bytes of the diff applied.

#### C.3.5 Resolver (NEW)

The Resolver fills the "who consumes this proposal?" gap (per Arch-2). It runs once per proposal, post-apply, against the sandboxed tree:

```rust
pub trait DependencyEcosystem {
    // ... existing methods ...
    fn affected_consumers(&self, proposal: &Proposal, tree: &Path) -> Result<Vec<ConsumerId>>;
}
```

For **Cargo**: invoke `cargo metadata --format-version 1 --manifest-path <tree>/Cargo.toml`, parse the result, walk each workspace member's dependency closure. A member is "affected" if the bumped crate appears anywhere in its transitive deps. Implementation note: cargo metadata is JSON-emitting and stable since cargo 1.41+; we depend on the `cargo_metadata` crate (already widely-used, stable API) to avoid hand-parsing.

For **GHA**: there is no workspace-member axis. `affected_consumers` returns `vec![]`. The Reporter handles the empty case by collapsing to a single-project report.

Each Resolver invocation produces `.assay/runs/<run-id>/receipts/resolver/<proposal-id>.json` with the affected consumer list and the dep-graph evidence.

#### C.4 Validator

The Validator orchestrates parallel execution against sandboxed trees. Six sub-concerns:

##### C.4.a Work-queue model and grain

Work units are `(proposal)`-grained — **not** `(proposal × consumer × workflow)`. Rationale (per Conc-1): N workflows for the same proposal share one apply state; running them concurrently against the same tree corrupts state (`target/` writes, cargo cache mutations, transient YAML reads). Per-WorkUnit independent tree clones are the alternative; their disk cost (N × tree-size) is high enough that v1 prefers per-proposal granularity.

A worker pops a `WorkUnit`, owns its sandboxed tree for the unit's duration, and runs every selected gate workflow against that tree sequentially. Per-workflow outcomes are aggregated into a per-proposal `ValidationOutcome`. Workers then return outcomes to the Reporter via a bounded result channel.

```rust
struct WorkUnit {
    proposal: ProposalId,
    tree_path: PathBuf,         // owned by this WorkUnit; deleted on drop
    workflows: Vec<PathBuf>,    // computed by Validator from gate_workflows + filter
}

struct UnitOutcome {
    proposal_id: ProposalId,
    workflows: Vec<WorkflowResult>,  // per-workflow Pass/Regression/SetupFailure/Timeout
    affected_consumers: Vec<ConsumerId>,  // copied from Proposal post-Resolver
    overall: ProposalVerdict,    // Pass if all workflows Pass; Fail otherwise
}
```

Total parallelism = `min(--threads, num_proposals)`. For a monorepo with 50 proposals and `--threads 8`, eight proposals validate concurrently — ample for typical workloads.

##### C.4.b Failure-flavor classification

Per workflow, classify the outcome:

```rust
enum WorkflowOutcome {
    Pass,
    Fail(FailureFlavor),
}

enum FailureFlavor {
    Regression,      // child completed; parsed JSON conclusion = failure
    SetupFailure,    // child completed but JSON unparseable, OR JSON conclusion
                     //   indicates pre-step abort, OR forge run exited non-zero
                     //   before producing a receipt
    Timeout,         // our wait_timeout watchdog fired and we killed the child
}
```

Classification logic lives on each `ValidatorBackend` impl (since different backends produce different signals — `forge run` emits structured JSON; `cargo test` emits exit code + stderr; custom commands could emit anything). The trait defines:

```rust
fn classify_outcome(
    &self,
    workflow: &Path,
    exec_result: BackendExecResult,
) -> WorkflowOutcome;
```

##### C.4.c ValidatorBackend trait

Per Arch-1: backend dispatch is a **trait, not an enum**. The original Round 1 enum (`ValidatorBackend { ForgeRun, BuildTest, Custom }`) forces a giant `match` per call site and violates open/closed when v1.5 adds a `ForgeLib` (in-process forge as a library) variant. The trait shape:

```rust
pub trait ValidatorBackend: Send + Sync {
    /// Run one workflow against the prepared tree.
    /// `unit_log_path` is where the worker should redirect captured stdout/stderr.
    fn run_workflow(
        &self,
        workflow: &Path,
        tree: &Path,
        timeout: Duration,
        unit_log_path: &Path,
    ) -> Result<BackendExecResult>;

    /// Map the execution result to a flavor classification.
    fn classify_outcome(
        &self,
        workflow: &Path,
        exec: BackendExecResult,
    ) -> WorkflowOutcome;

    /// Human-readable name for the run receipt's provenance field.
    fn name(&self) -> &'static str;
}
```

Three v1 impls:

- **`ForgeRunBackend`** (validator.rs:40-148 carries over): shells out to `forge run --workflow X --workspace Y --event push --executor docker --format json`. Classification uses the existing JSON parser (validator.rs:236-255). Failure flavors: child exited 0 + JSON `conclusion=failure` → Regression; child exited non-zero + JSON unparseable → SetupFailure; timeout watchdog → Timeout.
- **`BuildTestBackend`**: shells out to manifest-inferred commands. For Cargo: `cargo build --workspace` followed by `cargo test --workspace`. For npm/pnpm/yarn (v2): the lockfile-detected package manager's `test` script. Classification: child exited 0 → Pass; non-zero with valid stderr → Regression; non-zero with missing-binary stderr → SetupFailure; timeout → Timeout.
- **`CustomBackend`**: shells out to `--gate-cmd "<shell>"` or `--gate-file <script>`. Classification: exit code 0 → Pass; non-zero → Regression (no flavor distinction; users wanting flavor distinction should use the structured backends).

Backend selection happens once at Validator construction:

```rust
fn select_backend(
    project_root: &Path,
    gate_override: Option<GateOverride>,
) -> Box<dyn ValidatorBackend> {
    if let Some(over) = gate_override {
        return Box::new(CustomBackend::new(over));
    }
    if has_forge_on_path() && has_pull_request_workflows(project_root) {
        return Box::new(ForgeRunBackend::new(which("forge").unwrap()));
    }
    Box::new(BuildTestBackend::infer(project_root))
}
```

##### C.4.d Workflow filter at Validator-level (not trait-level)

Per Arch-3: trigger-event filtering is **not** a parameter on `gate_workflows`. The filter is project-wide and applied once at Validator construction:

```rust
struct WorkflowFilter {
    default_triggers: Vec<TriggerEvent>,   // ["pull_request", "push:default-branch"]
    include_patterns: Vec<Glob>,
    exclude_patterns: Vec<Glob>,
}

impl Validator {
    fn applicable_workflows(
        &self,
        candidates: Vec<PathBuf>,
        repo: &Path,
    ) -> Vec<PathBuf> {
        candidates
            .into_iter()
            .filter(|w| {
                let on = parse_workflow_on_block(repo, w);
                self.filter.matches(&on, w)
            })
            .collect()
    }
}
```

YAML parsing of the `on:` block lives in one place. Ecosystem trait stays minimal — `gate_workflows` returns the candidate list; Validator filters it.

##### C.4.e Per-ecosystem parallelism caps

Per Conc-3: `cargo update` acquires `~/.cargo/.package-cache` (advisory file lock). N parallel cargo workers serialize on that lock — making `--threads 4` a lie for cargo-only runs.

**Nuance (from Round 2 research):** modern cargo uses a three-mode lock at `~/.cargo/.package-cache` — `DownloadExclusive` (resolution + downloads; held by `cargo update`), `Shared` (builds; held by `cargo test`/`cargo check`), and `MutateExclusive` (gc / source-file mutation). A `DownloadExclusive` lock does NOT block `Shared` locks, so two concurrent `cargo test` invocations can run in parallel even though two `cargo update`s cannot. v1's cap-of-1 is intentionally coarse: it serializes the entire `(apply + validate)` work unit rather than tracking lock mode per subcommand. Per-mode semaphores (allowing parallel `cargo test` after the serialized `cargo update`) are deferred to v1.5 — the mode-aware state machine is more code than the parallelism win justifies for v1's monorepo workload, where per-proposal parallelism already saturates `--threads` at typical N.

Defense: per-ecosystem semaphores. The work-queue scheduler maintains:

```rust
struct EcosystemSemaphores {
    cargo: Semaphore,           // default permits = 1
    github_actions: Semaphore,  // default permits = usize::MAX
}
```

Permits are acquired before dispatching a `WorkUnit` to a worker, released when the unit completes. Default Cargo cap of 1 makes `--threads 4` produce 1-active-cargo-worker + up-to-3-active-GHA-workers concurrently. The `--allow-cargo-parallel` CLI flag overrides Cargo's cap to unlimited (use at your own risk; see Risks).

Configuration override in `.assay.toml`:
```toml
[ecosystems.cargo]
max_parallel = 1     # default
[ecosystems.github-actions]
max_parallel = 0     # 0 = unlimited; default
```

##### C.4.f Child-process lifecycle

Per Conc-4 + Arch-6: child-process kill on Windows requires Win32 job objects; Unix needs process groups.

Defense: spawn each child with the appropriate primitive:
- **Windows:** `CommandExt::creation_flags(CREATE_NEW_PROCESS_GROUP)`, then `AssignProcessToJobObject` with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. Killing the parent (or letting it drop the job handle) terminates the whole process tree, including docker containers spawned by `forge run`.
- **Unix:** `pre_exec(|| { setpgid(0, 0); Ok(()) })`, then on timeout `killpg(-pgid, SIGTERM)` followed by `killpg(-pgid, SIGKILL)` after a grace period.

The `wait-timeout` crate provides the `wait_timeout` primitive for the watchdog. The `shared_child` crate (or a thin internal wrapper) provides cross-thread `kill()` if/when the cancellation flow needs to reach a child from a non-owning thread; for v1 only the worker thread that spawned the child kills it (own-its-children pattern), so `shared_child` is not strictly required.

Crate additions to `Cargo.toml`:
- `wait-timeout = "0.2"` — for timeout-based child waits
- `cargo_metadata = "0.18"` — for Resolver's dep-graph walk
- `windows = { version = "0.58", features = ["Win32_System_JobObjects", "Win32_Foundation"] }` — Windows job objects (cfg-gated)
- Unix process-group handling uses `nix = "0.29"` or hand-rolled via `libc` — TBD at implementation time; both are stable choices.

#### C.5 Reporter

Aggregates `UnitOutcome`s into a structured report. Two output paths:

##### C.5.a Streamed log capture

Per Conc-6: workers do not buffer stdout/stderr in memory; instead they redirect to disk during execution. The `ValidatorBackend::run_workflow` signature takes `unit_log_path: &Path` precisely for this — the backend writes captured stdout/stderr to that path during the child's lifecycle.

```
.assay/runs/<run-id>/logs/<proposal-id>/<workflow-stem>.log
```

The result channel carries only metadata: `(proposal_id, workflow_path, classification, log_path, exec_duration_ms, tail_n_stderr)`. The `tail_n_stderr` is the last 4 KB of stderr (sufficient for "what was the last error?" rendering in text mode) — anything larger lives on disk.

This makes the channel payload `O(1)` per result, eliminating the unbounded-buffer risk.

##### C.5.b Output formatting

Text mode (default):
```
assay analyze --project ./Cargo.toml  (4m 32s wall)

ecosystems: cargo (cap=1, --allow-cargo-parallel off)
threads: 4  backend: forge run  workflow-timeout: 30m

3 available bumps validated against project's CI:

  ✓ serde 1.0.200 → 1.0.215           (3 workflows: ci.yml, fmt.yml, release-check.yml)
  ✓ tokio 1.40.0 → 1.42.1             (3 workflows green)
  ✗ thiserror 1.0.50 → 2.0.0          (REGRESSION: tests/error_kinds.rs:148)
                                          ci.yml ✗  (1 step failed)
                                          fmt.yml ✓
                                          release-check.yml ✓
                                      log: .assay/runs/<id>/logs/cargo-thiserror-2-0-0/ci-yml.log

verdict: FAIL (2/3 bumps clean; thiserror has a real regression)

receipt: .assay/runs/<id>/run.json
```

Workspace mode with per-consumer breakdown:
```
  ✓ lodash 4.17.20 → 4.17.21
        web-app           ✓ (3 workflows)
        admin-panel       ✓ (3 workflows)
        legacy-service    ✗ REGRESSION: tests/auth_test.js:42
        shared-lib        ⚠ SETUP-FAILURE (NPM_TOKEN secret missing)
```

The Reporter sorts the proposal list by proposal ID lex order in the output so two runs against the same inputs produce identical output (per Conc-9).

JSON mode emits the same structured report. The run receipt at `.assay/runs/<id>/run.json` is the same JSON shape.

#### C.6 Publisher (apply modes)

Only runs if at least one proposal validated green. Both modes share preconditions:
- Working tree is clean (`git status --porcelain` empty) OR `--force`.
- Working tree is a git checkout.

Per Conc-9: green proposals are sorted by proposal ID lex order before applying, so two runs of `--apply-local` against the same inputs produce byte-identical commits.

##### C.6.a `--apply-local` (sandbox copy-back)

Per Arch-5: the validated sandbox state is **copied back** to the operator's tree (not re-derived). This avoids non-determinism from registry state changing between sandbox-apply and host-apply.

Mechanics per ecosystem:
- **Cargo:** `fs::copy(sandbox/Cargo.lock, host/Cargo.lock)`. The lockfile is the canonical change-set; `Cargo.toml` is unmodified by `cargo update`.
- **GHA:** re-apply the byte-range rewrite to the host file. The rewriter (`rewrite_uses_in_workflow` in github_actions.rs) already refuses on `from` mismatch — if the operator edited the workflow file between sandbox-clone and host-apply, the rewrite is rejected with a clear error: "the workflow file at <path> has changed since validation; re-run assay or pass --force to override the from-mismatch check (not recommended)."

After copy-back:
1. `git add` the modified paths (only paths assay touched — never blind `git add .`)
2. `git commit -m "<sanitized subject>"` with the impact report as commit body

Commit subject follows Conventional Commits: `chore(deps): bump <N> dependencies` (N = green proposal count). Body lists each bump with from→to and the workflow validation summary. All text routed through `sanitize::sanitize_commit_subject` to defend against any pathological metadata (real-world risk: a malicious release-note string).

##### C.6.b `--apply-pr` (gh CLI)

Per Arch-4: no `PullRequestBackend` trait. One concrete function:

```rust
pub fn open_pr(
    branch: &str,
    base: &str,
    title: &str,
    body: &str,
) -> Result<PullRequestUrl>;
```

Implementation:
1. Resolve auth: `gh auth token` → `$GH_TOKEN` → fail loudly with remediation.
2. Verify token scope: `gh auth status` parses the token's scopes; if `repo` is missing, fail with `gh auth refresh -s repo` remediation (per "Risk: gh auth token returns a token that lacks PR-create scope").
3. Apply green proposals to a fresh branch (not the operator's branch). Branch name from `publisher::branch_name::branch_name_for_bump`.
4. `git push origin <branch>` (argv from `publisher::git_push::build_push_argv`).
5. Fetch branch metadata via `gh api repos/<owner>/<repo>/branches/<branch>` (or via `git ls-remote`); guard via `publisher::guards::guard_push_target` (rejects pushes to default or protected branches).
6. `gh pr create --base <base> --head <branch> --title <title> --body <body>`. Capture the PR URL from stdout.
7. Surface the PR URL.

Tests use a fixture `gh` binary in a tempdir-prepended PATH (the same pattern used for `which("forge")` in validator tests). The fixture script records its argv to a known path so tests can assert "the push happened with these exact args" and "the PR was created with this body". No mock trait needed.

### D. DependencyEcosystem trait (final shape)

```rust
pub trait DependencyEcosystem: Send + Sync {
    fn name(&self) -> &'static str;
    fn detect_manifests(&self, repo: &Path) -> Result<Vec<Manifest>>;
    fn propose_updates(
        &self,
        manifests: &[Manifest],
        repo: &Path,
        ctx: &EcosystemContext,
    ) -> Result<Vec<Proposal>>;

    // NEW (Arch-2): which workspace members consume this proposal's subject?
    fn affected_consumers(
        &self,
        proposal: &Proposal,
        tree: &Path,
    ) -> Result<Vec<ConsumerId>>;

    // RENAMED (Arch-11): was `affected_workflows` — clearer that these are
    // candidate gate workflows, not "workflows touched by this proposal"
    fn gate_workflows(&self, proposal: &Proposal, repo: &Path) -> Result<Vec<PathBuf>>;

    fn apply_proposal(&self, proposal: &Proposal, tree_path: &Path) -> Result<()>;

    // Now takes a `mode` parameter so the same code path serves both
    // commit-body and PR-body (Arch-5):
    fn pr_body_fragment(
        &self,
        proposal: &Proposal,
        outcome: &ValidationOutcome,
        mode: BodyMode,
    ) -> String;
}

pub enum BodyMode {
    CommitBody,  // shorter; no markdown emphasis
    PrBody,      // longer; markdown encouraged
}
```

The trait surface picks up **two** new methods (`affected_consumers`, mode-aware `pr_body_fragment`), one rename (`affected_workflows` → `gate_workflows`), and zero signature changes to existing methods. The filter parameter floated in Round 1 (per Arch-3) is dropped — that's Validator state, not ecosystem state.

### E. Validator implementation details

The Validator orchestrates the work queue, workers, child-process lifecycles, result channel, and reporter handoff. The reference implementation:

```rust
pub struct Validator {
    backend: Box<dyn ValidatorBackend>,
    filter: WorkflowFilter,
    semaphores: Arc<EcosystemSemaphores>,
    clone_lock: Arc<Mutex<()>>,         // serializes git clone (Conc-2)
    redactor: Arc<crate::redact::Redactor>,
}
```

Worker loop (one per thread, spawned via `std::thread::scope`):

```rust
fn worker(
    queue: Arc<Mutex<VecDeque<WorkUnit>>>,
    results: crossbeam_channel::Sender<UnitOutcome>,
    validator: &Validator,
    cancel: Arc<AtomicBool>,
) {
    while !cancel.load(Ordering::SeqCst) {
        // Pop next unit (lock briefly; release before doing work).
        let unit = { queue.lock().unwrap().pop_front() };
        let Some(unit) = unit else { return; };

        // Per-ecosystem permit (Conc-3).
        let _permit = validator.semaphores.acquire(unit.ecosystem);

        // Run workflows sequentially against the unit's tree.
        let mut workflow_results = Vec::new();
        for workflow in &unit.workflows {
            let log_path = unit_log_path(&unit, workflow);
            let exec = validator.backend.run_workflow(
                workflow,
                &unit.tree_path,
                validator.workflow_timeout,
                &log_path,
            );
            let outcome = match exec {
                Ok(ex) => validator.backend.classify_outcome(workflow, ex),
                Err(e) => WorkflowOutcome::Fail(FailureFlavor::SetupFailure),
            };
            workflow_results.push((workflow.clone(), outcome, log_path));
        }

        let overall = if workflow_results.iter().all(|(_, o, _)| matches!(o, WorkflowOutcome::Pass)) {
            ProposalVerdict::Pass
        } else {
            ProposalVerdict::Fail
        };

        let _ = results.send(UnitOutcome {
            proposal_id: unit.proposal,
            workflows: workflow_results,
            affected_consumers: unit.affected_consumers,
            overall,
        });

        // Tempdir tree drops here -> automatic cleanup on success.
        // (On panic, Drop still runs; on kill-9, OS reclaims the tempdir
        // when the assay process exits.)
    }
}
```

Reporter loop (single thread):

```rust
fn reporter(
    results: crossbeam_channel::Receiver<UnitOutcome>,
    cancel: Arc<AtomicBool>,
    fail_fast: bool,
) -> Vec<UnitOutcome> {
    let mut all = Vec::new();
    while let Ok(outcome) = results.recv() {
        let failed = matches!(outcome.overall, ProposalVerdict::Fail);
        all.push(outcome);
        if fail_fast && failed {
            cancel.store(true, Ordering::SeqCst);
            // Drain remaining queued units, but let in-flight finish.
        }
    }
    all
}
```

Channel sizing: `crossbeam_channel::bounded(min(threads * 2, 32))`. With streamed-log capture (§C.5.a), the channel payload per outcome is small (a handful of fields + log path string), so bounded back-pressure is fine.

Cancellation semantics (per Conc-5): the `cancel` AtomicBool tells workers "stop popping new units after the current one completes". In-flight units finish (or hit `--workflow-timeout`). Completed `UnitOutcome`s already on the channel are aggregated normally. Drainage happens organically — workers exit when the queue is empty.

For aggressive cancellation, future `--fail-fast-kill` would extend the cancel signal to "kill the in-flight child" via a per-worker `Arc<Mutex<Option<shared_child::SharedChild>>>` handle. Deferred to v1.5.

### F. Auth path for `--apply-pr`

```rust
fn resolve_github_token() -> Result<RedactedToken> {
    // 1. Try `gh auth token`
    if let Ok(output) = Command::new("gh").args(["auth", "token"]).output() {
        if output.status.success() {
            let token = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !token.is_empty() { return Ok(RedactedToken::new(token)); }
        }
    }
    // 2. Try $GH_TOKEN
    if let Ok(t) = std::env::var("GH_TOKEN") {
        if !t.is_empty() { return Ok(RedactedToken::new(t)); }
    }
    // 3. Fail explicitly
    Err(Error::Auth(
        "no GitHub token: install gh CLI (`gh auth login`) or set $GH_TOKEN".into()
    ))
}
```

Tokens flow through `crate::redact::Redactor::register` immediately so any log line containing the token gets redacted before write. `RedactedToken` is a newtype around `String` with no `Display` impl — only `as_authorization_header()` returns the bearer string for HTTP use. The token is never written to disk.

### G. Configuration: `.assay.toml`

```toml
[meta]
schema_version = 1

[ecosystems.cargo]
enabled = true
max_parallel = 1    # default; the ~/.cargo/.package-cache global lock makes
                    # higher values misleading. --allow-cargo-parallel overrides.

[ecosystems.github-actions]
enabled = true
max_parallel = 0    # 0 = unlimited

[validator]
gate = "auto"                  # auto | compile | tests | ci
workflow_timeout = "30m"
threads = 4                    # CLI --threads overrides

[validator.workflows]
include = []                   # additive glob patterns
exclude = ["release-*.yml"]    # subtractive glob patterns

[pull_request]
draft = false
labels = ["dependencies"]
reviewers = []
default_branch_guard = true    # refuse PRs that would target default/protected branches
```

Schema version enforced; unknown top-level + section fields rejected via `serde(deny_unknown_fields)`. Migration on schema bump points to a helper command.

### H. Receipts (final path schema)

Per Arch-7 + Conc-7 + Conc-8: per-stage subdirectories, with stage-appropriate filenames. The Reporter calls `write_run_receipt` **once** before fan-out, pre-creating all subdirs (per receipt.rs:28-36, already in place); workers `fs::write` files into existing dirs (race-free).

```
.assay/runs/<run-id>/
├── run.json                                # top-level AssayRunReceipt
├── receipts/
│   ├── scanner.json                        # one per run
│   ├── proposer/
│   │   ├── cargo-serde-1-0-215.json
│   │   └── cargo-tokio-1-42-1.json
│   ├── resolver/
│   │   ├── cargo-serde-1-0-215.json        # affected consumers + dep-graph
│   │   └── cargo-tokio-1-42-1.json
│   ├── applier/
│   │   ├── cargo-serde-1-0-215.json
│   │   └── cargo-tokio-1-42-1.json
│   ├── validator/
│   │   ├── cargo-serde-1-0-215-ci-yml.json     # one per (proposal × workflow)
│   │   ├── cargo-serde-1-0-215-fmt-yml.json
│   │   ├── cargo-tokio-1-42-1-ci-yml.json
│   │   └── cargo-tokio-1-42-1-fmt-yml.json
│   ├── reporter.json                       # aggregated final outcome
│   └── publisher.json                      # only present if --apply-* mode
└── logs/
    ├── cargo-serde-1-0-215/
    │   ├── ci-yml.log
    │   └── fmt-yml.log
    └── cargo-tokio-1-42-1/
        ├── ci-yml.log
        └── fmt-yml.log
```

Filename schemas:
- **`receipts/validator/`** is flat: `<proposal-id>-<workflow-stem>.json` (one file per `(proposal × workflow)` combination).
- **`logs/`** is nested by proposal: `<proposal-id>/<workflow-stem>.log` (subdirectory per proposal, one log file per workflow inside). Keeps logs together for `tail -f` and grep-friendly inspection.

`<workflow-stem>` is the workflow filename with the `.yml`/`.yaml` extension stripped and `.` and `/` replaced with `-`. For deeply-nested workflow paths or pathological filenames a 12-hex hash suffix disambiguates collisions:

```rust
fn workflow_stem(path: &Path) -> String {
    let raw = path.with_extension("").to_string_lossy().replace(['/', '\\', '.'], "-");
    if raw.len() <= 80 && raw.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        raw
    } else {
        let hash = sha256_first_12_hex(path.to_string_lossy().as_bytes());
        format!("{}-{hash}", &raw[..raw.len().min(60)])
    }
}
```

### I. Workspace and monorepo handling

When `--project` points at a workspace root:

- **Cargo:** detect via `[workspace]` section in root `Cargo.toml`. The **Resolver** (§C.3.5) invokes `cargo metadata` and walks each member's dep graph to determine which members consume each proposal's bumped crate. Members where the crate doesn't appear → not in the report.
- **GHA:** workflows live at repo root; per-workspace-member breakdown doesn't apply. Resolver returns empty `affected_consumers`; Reporter collapses to single-project format.
- **npm/yarn/pnpm (v2):** parse `package.json`'s `workspaces` field; resolve via the appropriate lockfile.

For non-workspace projects, the "consumer" axis collapses — one project, one report.

## Risks & Open Questions

### Resolved (during Review Pass 1)

The following Round 1 risks were either resolved by reviewer findings or pinned to a concrete approach:

- **Parallel workflows colliding on shared resources** → cargo cap-of-1 default + per-ecosystem semaphores + per-WorkUnit tempdir cloning + `--allow-cargo-parallel` escape hatch.
- **`--apply-local` semantic ambiguity** → pinned to sandbox-copy-back with `from` mismatch defense for GHA.
- **Receipt path conflation** → per-stage subdirectory schema (§H).
- **WorkUnit grain ambiguity** → per-proposal grain; workflows sequential within a worker against a single sandboxed tree.
- **git clone race** → global mutex on the clone primitive.

### Remaining risks

- **Windows child-process kill leak**: if the `windows` crate's job-object handling has bugs or unsupported subprocess shapes (e.g. docker daemon spawning processes outside the parent's job), kill semantics could still leak. Mitigation: integration test that spawns a child-with-children, kills the parent via job object, asserts the descendants exit. Run on Windows in CI.
- **`forge run` JSON schema drift**: parser is narrow (validator.rs:236-255 reads `run_id` + `conclusion` with workflow-array fallback). Schema drift on other fields is fine; drift on these two breaks the parser. Mitigation: a known-good `forge run` against a pinned workflow fixture, run in CI. Drift detected as SETUP-FAILURE.
- **GitHub API rate limit under heavy GHA proposers**: 5000/hr authenticated. For a scan of a 200-action workflow, the proposer makes 200 API calls. Two parallel scans = 400 calls. Sustained workloads of N runs/hr × M actions/run could approach the limit. Mitigation: shared Octocrab client + retry-on-429 in v1; dedicated semaphore for outbound API calls is v1.5.
- **`docker` container/port collisions under `--executor docker`** — TWO problems here, the second one more serious:
  - **(a) Container name collisions**: if `forge run` uses deterministic container names (e.g. `forge-run-<workflow-hash>`), two assay workers running the same workflow against different sandboxed trees would collide. Mitigation: assay passes a unique `--container-suffix` argument to `forge run` if forge supports it; otherwise serialize per-workflow runs at the assay level. Need to verify with forge's container naming policy.
  - **(b) Container survives parent kill (THE real issue)**: docker containers are NOT child processes of `forge run` — they're managed by the docker daemon, which is a separate process tree. When assay's `--workflow-timeout` fires and kills the `forge run` process via Win32 job object / Unix process group, **the docker container keeps running** because it's not in the killed tree. This leaks compute, network resources, and potentially mutates state (e.g. test databases) the operator didn't authorize. Mitigation options:
    - **(i)** assay invokes `docker ps` post-kill to find containers labeled with the assay run-id (forge run would need to pass `--label assay-run-id=<id>` on container creation) and `docker rm -f` them.
    - **(ii)** rely on `forge run` to register a signal handler that kills its own containers on `SIGTERM` — assay sends SIGTERM, waits a grace period, then kills via job object.
    - **(iii)** for v1, document the limitation and accept that `--executor docker` + `--workflow-timeout` may leak containers in pathological cases. Operators using docker should periodically run `docker container prune` if leaks are observed.
  - The right answer is (ii) — `forge run` owns container lifecycle, so the cleanup signal handler belongs there. assay coordinates by sending SIGTERM first, giving forge ~5s grace, then escalating. Implementation requires a small change in ci-forge — log as a follow-up task. Until then, v1 ships with the documented limitation.
- **v2 npm/pnpm Applier shape**: the Applier pattern for Cargo (`re-run cargo update --workspace`) doesn't translate to npm because npm's lockfile resolution depends on registry state at run time. v2 npm Applier needs to write the lockfile diff *explicitly* from the proposer's diff output, not re-resolve. Flag for v2 design.
- **`cargo metadata` cost in monorepos with N members**: invocation is one-shot but parses the full workspace graph. For workspaces with hundreds of members, this is multi-second. Acceptable for v1; profile in real workloads.

### Open questions

- **Per-workspace-member ordering of consumers in the report**: alphabetical, dep-order, or proposal-impact-order? **Recommendation:** alphabetical by member name. Predictable, easy to scan, no surprise.
- **Should `--apply-local` create one commit or N commits when N proposals are green?** **Recommendation:** one commit by default; `--commit-per-bump` flag for users who prefer atomic per-dep commits.
- **Should `--apply-local` against a partially-green workspace ever commit?** **Recommendation:** refuse, default (one red consumer → no commit). The whole value prop is "if you upgrade X, your projects break"; landing partial green contradicts the verdict. `--apply-partial` future flag if real users ask.
- **Impact report format in PR body**: markdown table or fenced code block? **Recommendation:** fenced code block for the text report; markdown bullet list for the per-consumer summary. Keep it scannable.
- **`gh pr create` failures mid-flight (rate limit, scope error, etc.)** — branch is already pushed; how does the user recover? **Recommendation:** print a remediation that includes the branch name + a manual `gh pr create` command they can re-run. Don't auto-delete the pushed branch; the user might want to inspect or re-PR it.

## Test Strategy

### Unit tests (TDD-first)

All pure-logic modules use TDD: write the failing test first, then implement.

- **`ecosystem::cargo::parse_cargo_update_output`** — cargo.rs:563-587, already 8 cases. Carries over.
- **`ecosystem::cargo::diff_lockfiles`** — cargo.rs:599-617. Carries over.
- **`ecosystem::cargo::propose_from_cargo_dry_run` cross-check** — cargo.rs:619-664. Carries over.
- **`validator::ValidatorCommandBuilder::build_argv`** — validator.rs:277-333. Carries over as part of `ForgeRunBackend`.
- **`validator::parse_forge_run_output`** — validator.rs:336-381. Carries over.
- **NEW: `ValidatorBackend` trait — three impl unit tests:**
  - `ForgeRunBackend::run_workflow` — argv shape, child spawn, JSON parse, all four classification outcomes (Pass / Regression / SetupFailure / Timeout). Unparseable JSON output collapses to SetupFailure (covered by the SetupFailure case rather than being its own outcome).
  - `BuildTestBackend::run_workflow` — manifest detection (Cargo / npm-stub / unknown), child spawn, exit-code classification, missing-binary SetupFailure.
  - `CustomBackend::run_workflow` — argv pass-through, exit-code-only classification.
- **NEW: `WorkflowFilter::matches`** — pull_request inclusion, push:default-branch inclusion, schedule exclusion, glob include overlay, glob exclude overlay, overlap rules (exclude wins over include).
- **NEW: `EcosystemSemaphores::acquire/release`** — cargo cap-of-1, GHA unlimited, `--allow-cargo-parallel` override, fairness (FIFO-ish).
- **NEW: `Resolver::affected_consumers` (Cargo)** — synthetic workspace with N members each consuming or not consuming the bumped crate; assert membership matches dep graph.
- **NEW: Child-process kill semantics** — Windows + Unix. Spawn a child that itself spawns a long-running grandchild; kill the parent's process group/job; assert grandchild exits within grace period.
- **NEW: `--apply-local` copy-back determinism** — same inputs twice → byte-identical commits.
- **NEW: `workflow_stem` collision resistance** — pathological filenames + nested paths produce unique outputs.
- **NEW: `--fail-fast` cancellation flow** — 10 work units, fail the 3rd, assert: in-flight units complete normally (not killed), no new units start, all completed `UnitOutcome`s are reported (none dropped by the cancel race).
- **NEW: `--threads 1` boundary** — single-worker work queue still completes all units in submission order; no deadlock.
- **NEW: `--threads N` exceeding num_proposals** — assay degrades gracefully; idle workers exit cleanly.
- **`sanitize::*`** — branch names, commit subjects, PR bodies. Adversarial inputs already covered. Carries over.
- **`redact::Redactor`** — token shapes. Carries over.
- **`publisher::branch_name::branch_name_for_bump`** — Carries over.
- **`publisher::guards::guard_push_target`** — Carries over.
- **`publisher::pr_body::render_pr_body`** — Carries over with `BodyMode` parameter added (Arch-5).
- **NEW: `auth::resolve_github_token`** — gh CLI fixture path, env path, both-missing failure path, scope-check pass/fail.
- **NEW: `open_pr` (gh CLI front-end)** — fixture-PATH gh binary; assert argv shape, capture PR URL from stdout.

### Integration tests

- **Synthetic Cargo fixture**: tempdir with known-version `Cargo.toml` + `Cargo.lock`. Run `assay analyze --project <fixture>`. Assert per-proposal report shape.
- **Synthetic Cargo workspace fixture**: 3-member workspace where members A and C consume `serde` but B does not. Assert Resolver produces `[A, C]` for a serde proposal; B is not in the report.
- **Synthetic GHA fixture**: tempdir with `.github/workflows/ci.yml` containing pinned `uses:`. Assert proposals generated for each `uses:` line.
- **Synthetic GHA fixture with non-pull_request workflows**: workflow with `on: schedule` should be excluded by default; assert it shows in the candidate list but not in the validator's gate list.
- **`--apply-local` integration**: tempdir git repo, run `assay analyze --apply-local`, assert exactly one commit added with the expected subject + body; running again on the same inputs produces an identical commit (byte-for-byte).
- **`--apply-pr` integration**: fixture `gh` binary that records argv to a file. Assert correct push, correct `gh pr create` invocation, PR URL surfaced.
- **`--threads N` parity**: 12 proposals × 3 workflows each = 36 workflow runs. `--threads 1` vs `--threads 4` produce the same final verdict; `--threads 4` is at least 2× faster (loose bound).
- **Cargo cap-of-1 respect**: 4 cargo proposals + `--threads 4` runs at most 1 cargo workflow at a time. Assert via observed concurrent run count (instrumented worker counter).
- **`--allow-cargo-parallel` override**: 4 cargo proposals + `--threads 4 --allow-cargo-parallel` runs up to 4 cargo workflows concurrently.

### E2E tests

- **Real `forge run` against the assay repo's own workflows** after a real `cargo update`. Pinned to a known-good baseline; runs in CI on every PR. Catches schema drift between assay and forge.
- **`--apply-pr` against a sacrificial GitHub repo** (e.g. `wildmason/assay-e2e-sandbox`) using a dedicated test PAT. Runs nightly. PR auto-closed by a follow-up cleanup job.

### Adversarial tests (load-bearing)

- **Cargo stdout drift**: feed historical cargo output formats (1.70, 1.80, 1.85) at the parser. Cross-check survives all.
- **GHA YAML pathological inputs**: workflows with `uses:` inside heredocs / multi-line strings / commented-out blocks / Windows CRLF / leading BOM. Existing baseline tests cover most.
- **Sanitizer shell-injection**: branch names / commit subjects with `;`, `$(...)`, backticks, null bytes, CRLF. Baseline covered.
- **Token redactor**: log lines containing real-looking token shapes get redacted.
- **NEW: Child kill leak**: integration test asserts that killing a `ValidatorBackend`'s worker process causes its docker container / cargo subprocess to also exit within a grace period.

## Acceptance Criteria

Implementation is complete when:

- [ ] `assay analyze --project Cargo.toml` runs end-to-end against a real Cargo workspace, produces a text report, writes `.assay/runs/<id>/run.json` plus per-stage receipts under the schema in §H.
- [ ] Per-workspace-member report rows are produced via the Resolver, filtered to members that consume the bumped dep.
- [ ] `--threads 4` produces the same final verdict as `--threads 1` (just faster on workloads where the cap allows concurrency).
- [ ] Default Cargo cap-of-1 respected: 4 concurrent cargo proposals + `--threads 4` shows max 1 concurrent worker on cargo workflows.
- [ ] `--allow-cargo-parallel` overrides the cap; 4 concurrent cargo proposals + `--threads 4 --allow-cargo-parallel` shows up to 4 concurrent.
- [ ] `--apply-local` adds exactly one commit to the operator's current branch (subject matches Conventional Commits format); refuses on dirty tree without `--force`; same inputs twice → byte-identical commits.
- [ ] `--apply-local` copy-back refuses on GHA workflow mid-flight edits (`from` mismatch defense fires); error message points at the offending file.
- [ ] `--apply-pr` creates a branch matching `assay/<eco>/<subject>-<version>-<hash>` shape, pushes it, opens a PR via `gh pr create`. The PR body contains the impact report.
- [ ] `--apply-pr` fails fast with clear remediation when `gh auth token` is empty AND `$GH_TOKEN` is unset.
- [ ] `--apply-pr` checks `gh auth status` for `repo` scope before pushing; fails with `gh auth refresh -s repo` remediation if missing.
- [ ] `--gate compile` runs `cargo check --workspace` (or equivalent) and skips full test runs.
- [ ] `--workflow-timeout 1s` against a known-slow workflow yields a `TIMEOUT` failure flavor in the report; the killed child's descendants (docker container, child cargo) also exit within a grace period (Windows + Unix).
- [ ] When `forge` is not on PATH, the validator falls back to `cargo test --workspace` (verified by removing forge from PATH in a test sandbox).
- [ ] Failure flavors classified correctly: REGRESSION (workflow ran, returned failure), SETUP-FAILURE (missing secret / executor / parseable JSON failure), TIMEOUT (watchdog killed).
- [ ] `--fail-fast` drains the work queue after the first failure but lets in-flight units complete; no `UnitOutcome` is dropped due to the cancel race.
- [ ] All inherited baseline tests (147) pass after rename/strip/restructure (modulo the App-auth-specific ones that get deleted, expected 15-20 lossage).
- [ ] At least 30 new tests across: trait backends, work queue, per-ecosystem caps, Resolver, child-kill semantics, `--apply-local` determinism, `--fail-fast`, `--threads` boundaries.
- [ ] `cargo clippy --workspace -- -D warnings` clean.
- [ ] `cargo fmt --check` clean.
- [ ] README at repo root has a "Quick start" section with 3 example invocations.

## Out-of-band References

- **Original forge-tinker deep-plan** (now obsolete) at `docs/forge-tinker-plan.md` — preserved in the repo for context on what the prior direction was and why it was abandoned.
- **ci-forge repo** at `C:\Users\Matt\Documents\development\@wildmason\oss\ci-forge\` — the `forge run` binary assay invokes for the default validator backend. Receipt JSON schema lives there.
- **Dependabot's source** at `github.com/dependabot/dependabot-core` — useful for parser edge cases on lockfiles. Not used as architectural inspiration.
- **Renovate's docs** at `docs.renovatebot.com` — useful for understanding ecosystem coverage gaps.
- **GitHub CLI auth model** at `cli.github.com/manual/gh_auth_status` — reference for the `gh auth token` shape.
- **`wait-timeout` crate** at `crates.io/crates/wait-timeout` — child process timeout primitive.
- **`cargo_metadata` crate** at `crates.io/crates/cargo_metadata` — workspace dep-graph walking for the Resolver.
- **`win32job` crate** at `docs.rs/win32job` — Rust wrapper around Win32 Job Objects. Cleaner API than rolling our own via the `windows` crate; preferred choice for v1's Windows child-tree kill.
- **`windows` crate, Win32_System_JobObjects feature** at `microsoft.github.io/windows-docs-rs` — raw Win32 API access; fallback option if `win32job`'s abstraction is too thin for our needs.
- **`shared_child` crate** at `crates.io/crates/shared_child` — option for cross-thread `Child::kill` when v1.5 adds `--fail-fast-kill`.
- **`kill_tree` crate** at `crates.io/crates/kill_tree` — alternative process-tree-walking kill (no job objects). Not preferred for v1 because it can miss processes spawned after enumeration; job objects catch them automatically.
- **Meziantou's "Killing all child processes when the parent exits (Job Object)"** at `meziantou.net/killing-all-child-processes-when-the-parent-exits-job-object.htm` — clearest writeup of the `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` pattern.
- **Cargo's `cache_lock` module** at `doc.rust-lang.org/nightly/nightly-rustc/cargo/util/cache_lock/` — the three-mode (`DownloadExclusive` / `Shared` / `MutateExclusive`) lock implementation; relevant to §C.4.e's per-ecosystem cap rationale.
- **GitHub REST API rate-limits doc** at `docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api` — primary (5000/hr authenticated) + secondary (100 concurrent, 900 pts/min/endpoint, 90s CPU/60s real-time) limits.
- **GitHub REST API troubleshooting** at `docs.github.com/en/rest/using-the-rest-api/troubleshooting-the-rest-api` — `Retry-After` header handling and the known gap where secondary rate limits sometimes omit it.

---

## Review Pass 1

**Reviewers:** Architecture Reviewer, Concurrency Reviewer

**Verdicts:** `needs-revision` / `needs-revision`

**Status before:** Draft (round 1) · 2026-05-17
**Status after:** Draft (round 2) · 2026-05-17

### Findings settled

**Accepted in full:**

- 🔴 **Arch-1 — `ValidatorBackend` enum leaks across module boundaries.** Refactored to trait (`ValidatorBackend`) with three impls (`ForgeRunBackend`, `BuildTestBackend`, `CustomBackend`). Each impl owns its own failure-flavor classification logic. Plan §C.4.c rewritten.
- 🔴 **Arch-2 — Workspace-member dep-graph filtering had no home in the pipeline.** Added a dedicated **Resolver** stage between Proposer and Applier. Owns `cargo metadata` invocation, walks dep graph, populates `Proposal::affected_consumers`. Trait gains `affected_consumers(&Proposal, &Path) -> Vec<ConsumerId>`. Plan §A architecture overview and §C.3.5 (new) added. The `WorkUnit` now carries `affected_consumers` populated by Resolver before validation begins.
- 🔴 **Conc-1 — `WorkUnit` granularity vs shared apply tree.** Pinned grain at `(proposal)`, not `(proposal × consumer × workflow)`. Each worker materializes one tempdir tree, applies the proposal, runs all gate workflows sequentially against that tree. Per-workflow parallelism within a proposal is dropped; per-proposal parallelism remains plenty for monorepo use cases. Plan §C.4.a, §E rewritten.
- 🔴 **Conc-2 — `git clone --local` against live source repo race.** Added a global `Mutex<()>` around the clone primitive. Clones serialize; apply + validate stages run unlocked. Plan §C.3 rewritten.
- 🔴 **Conc-3 — Cargo global cache lock contention is real, not deferred.** Per-ecosystem semaphores; default Cargo cap = 1, GHA cap = unlimited. `--allow-cargo-parallel` CLI flag to override. `.assay.toml` `max_parallel` field per ecosystem. Plan §C.4.e (new) and §G updated.
- 🔴 **Conc-4 — Windows child-process kill semantics undefined.** Pinned implementation: Win32 job objects (`CREATE_NEW_PROCESS_GROUP` + `AssignProcessToJobObject` + `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) on Windows; `setpgid` + `killpg` on Unix. `wait-timeout` crate for the watchdog. Crate additions documented at §C.4.f.
- 🟠 **Arch-4 — `PullRequestBackend` trait is premature abstraction.** Accepted the publisher's own self-flag at `publisher/mod.rs:11-13`. Trait + `UnconfiguredBackend` + `RecordingBackend` deleted. v1 ships one concrete `open_pr(...)` function tested via fixture-PATH `gh` binary. Plan §C.6.b rewritten.
- 🟠 **Arch-5 — `--apply-local` semantic shift had unstated edge cases.** Pinned to sandbox-copy-back (not re-derive). GHA copy-back uses the existing `from` mismatch defense to refuse on mid-flight host edits. Plan §C.6.a rewritten.
- 🟠 **Arch-6 — Timeout-watchdog vs cancellation interaction.** Pinned crate choices: `wait-timeout` for the watchdog; `shared_child` deferred to v1.5 when `--fail-fast-kill` lands. v1 keeps cancellation own-its-children pattern (only the spawning worker kills).
- 🟠 **Arch-7 + Conc-8 — Receipt path conflates dimensions.** Restructured to per-stage subdirectories with stage-appropriate filenames. Filename schema `<proposal-id>-<workflow-stem>.json` with hash-suffix collision fallback. Plan §H rewritten.
- 🟠 **Conc-5 — Fail-fast cancellation race.** Pinned: cancel is advisory; all completed `UnitOutcome`s on the channel are aggregated; only the queue drains; in-flight units run to their own timeout. Future `--fail-fast-kill` for aggressive cancellation. Plan §E rewritten.
- 🟠 **Conc-6 — Bounded channel + huge stdout buffering.** Workers stream stdout/stderr to disk at `.assay/runs/<id>/logs/<proposal-id>/<workflow-stem>.log`. Result channel carries only metadata (`log_path`, classification, tail-N stderr). Plan §C.5.a (new).
- 🟠 **Conc-7 — Receipt directory creation race on Windows.** Confirmed already mitigated by existing receipt.rs:28-36 (top-level `write_run_receipt` pre-creates `receipts/` and `logs/`). Plan §H explicitly states the precondition: `write_run_receipt` runs **once** before fan-out.
- 🟠 **Conc-9 — `--apply-local` ordering non-determinism.** Pinned: green proposals sorted by proposal ID lex order before applying. Acceptance criteria includes "same inputs twice → byte-identical commits". Plan §C.6.
- 🟠 **Conc-12 — GitHub API rate-limit collision.** Shared Octocrab client across the run + retry-on-429 with exponential backoff. Dedicated outbound-API semaphore deferred to v1.5. Plan §C.2.

**Accepted with modification:**

- 🟠 **Arch-3 — `affected_workflows` signature change was the wrong refactor.** Accepted the substance (filter is project-wide, not per-proposal) but moved the filter from the trait method to Validator construction. Trait method renamed to `gate_workflows` per Arch-11. Plan §D and §C.4.d rewritten. The trait signature is now stable (no per-call filter parameter).

**Accepted as nits:**

- 🟡 **Arch-11 — "affected" is a misnomer; these are candidate gate workflows.** Renamed `affected_workflows` → `gate_workflows` in the trait. Plan §D.
- 🟡 **Arch-12 — `--threads` default `min(4, num_cpus)` Windows hyperthread caveat.** Acknowledged in Scope: the conservative bit is `min(4, ...)`, not `num_cpus`. Acceptance criteria includes `--threads 1` boundary and `N > num_proposals` boundary.
- 🟡 **Conc-10 — `--threads 1` boundary test.** Added to test strategy.
- 🟡 **Conc-11 — Default cap clarification.** §C.4.e calls out "per-process across all ecosystems combined".

**Speculative findings preserved as future risks:**

- ⚪ **Arch-13 — v2 npm/pnpm Applier needs different shape.** Logged in Risks ("v2 npm/pnpm Applier shape"); v2 design will reckon with it.
- ⚪ **Conc-16 — Docker container/port collisions.** Logged in Risks ("`docker` container/port collisions"); to be verified with forge's container naming policy before declaring `--executor docker` safe under `--threads > 1`.

**Strengths preserved (not refactored under reviewer pressure on adjacent items):**

- 🟢 Failure-flavor classification clean — `Regression` / `SetupFailure` / `Timeout` survives as the canonical taxonomy.
- 🟢 Cargo parser cross-check defensive (cargo.rs:266-312) — unchanged.
- 🟢 `std::thread::scope` + `crossbeam_channel` is the right primitive for sync-blocking child workloads — no tokio.
- 🟢 Redactor's `Arc<RwLock>` design under parallel logging is fine — registration is rare, reads dominate.
- 🟢 Carry-over claim (~75% of baseline LOC) verified at file:line by Arch reviewer.

**Findings rejected:** none. All reviewer findings were either accepted, modified, or filed as future risks.

### Changes summary

The Round 2 plan is materially larger than Round 1 — the rewrite added approximately 600 lines of new technical content. Major structural deltas:

1. New pipeline stage: **Resolver** (§C.3.5), with corresponding trait method `affected_consumers`.
2. `ValidatorBackend` is now a trait with three impls.
3. Workflow filter moved from trait to Validator construction.
4. WorkUnit grain is `(proposal)`, not `(proposal × consumer × workflow)`.
5. Per-ecosystem parallelism caps + `--allow-cargo-parallel`.
6. Per-WorkUnit tempdir cloning; global mutex on clone.
7. Win32 job objects / Unix setpgid for child kill.
8. Streamed log capture to disk; small metadata on result channel.
9. Per-stage receipt subdirectories with stage-appropriate filename schemas.
10. `--apply-local` sandbox copy-back with deterministic ordering.
11. `PullRequestBackend` trait removed; one concrete `open_pr` function.
12. Crate additions: `wait-timeout`, `cargo_metadata`, `windows` (cfg-gated), possibly `nix` for Unix process groups.

**Phase 4 (research augmentation)** added: cargo's three-mode lock nuance (§C.4.e), `win32job` crate as the preferred Windows job-object wrapper (§C.4.f, References), GitHub primary+secondary rate-limit refinement (§C.2), and the docker daemon-vs-subprocess kill caveat (Risks §"docker container/port collisions").

**Phase 5 (final validation)** cleared up six internal consistency issues: sub-concern count, cross-section reference accuracy, log path schema across §C.5.a and §H, classification outcome count, validator/ vs logs/ schema distinction, and trailing status text.

The plan is ready for hand-off.
