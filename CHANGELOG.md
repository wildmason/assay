# Changelog

All notable changes to `assay` are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project tracks [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] — 2026-05-20

Targeted single-dep validation — the canonical "I just heard about a CVE in foo, validate moving to foo@1.5.3" workflow finally has a first-class flag.

### Added

- **`assay analyze --dep <name>@<version>`** — Skip the standard outdated-discovery proposer (`cargo update --dry-run`, `npm outdated`, etc.) and build a synthetic single proposal: `from` is resolved from the project's lockfile or declared constraint, `to` is the operator-supplied version. The proposal flows through the same classifier / validator / apply pipeline as a discovered proposal, so `--dep foo@1.2.3 --validate` is the canonical way to answer "would moving to foo 1.2.3 break my project?" without scanning the rest of the dep graph.
- **Scoped npm packages handled** via rightmost-`@` separator parsing: `--dep @angular/core@22.0.0` works; the leading `@` stays attached to the scope name.
- **Clean exit when nothing to do.** When the requested dep isn't declared in any enabled ecosystem at the repo, or is already pinned at the requested version, the run emits a one-line stderr notice (`[dep] foo@1.2.3: not declared in any enabled ecosystem at this repo, or already pinned at the requested version. Nothing to validate.`) and a per-ecosystem "already resolves to X in Cargo.lock" notice when the lockfile already matches.
- **Lockfile reads across all four npm flavors.** `package-lock.json` reuses the existing v2/v3 reader; `pnpm-lock.yaml` is parsed via a focused YAML walk of `importers.<importer>.dependencies.<name>.version` (peer-suffix `(react@18)` stripped); yarn berry `yarn.lock` reuses the existing `__metadata:`-anchored descriptor parser; yarn1's custom-format `yarn.lock` falls through to a constraint-strip fallback against `package.json` (acceptable for v1 — produces a working proposal even if `from` loses any narrowing the lockfile would have provided).
- **Trait surface.** New `DependencyEcosystem::synthesize_dep_proposal(name, target_version, manifests, repo, ctx) -> Result<Option<Proposal>>` method with a sensible `Ok(None)` default so ecosystems that don't support `--dep` (currently `github-actions`, whose `<subject>@<ref>` shape isn't a version) inherit a clean skip rather than a crash.

### Internal

- **`parse_dep_spec` (`src/cli/args.rs`)** parses `<name>@<version>` with 9 covering tests (plain, scoped, prerelease, build-metadata, and 5 rejection cases: missing `@`, empty version, empty name from `@1.0.0`, empty spec, bare scope without version).
- **10 new ecosystem tests** for the synthesize path: 4 cargo (success, dep absent, already-at-target, major-bump-as-breaking), 6 npm (npm/pnpm/yarn-berry lockfile reads, dep absent, already-at-target, yarn1 constraint-strip fallback).
- Tier classification reuses `classify_unchanged_bump` / `classify_npm_bump`. LockfileOnly tier is suppressed in v1 — even bumps that satisfy the existing constraint route through the manifest-widening applier (idempotent widen to the same value), which is conservative-correct but produces a harmless manifest edit the discovery proposer would have avoided. Refining this is a follow-up.

### End-to-end verification (dogfooded)

- `assay analyze --dep sha2@0.11.0 --repo .` against assay's own Cargo repo emits one Breaking proposal (`sha2 0.10.9 -> 0.11.0`) with the `source:--dep` note.
- `assay analyze --dep typescript@6.0.0 --repo <aegis>` against the aegis npm project emits one Breaking proposal (`typescript 5.9.3 -> 6.0.0`) with three correctly-resolved consumers (`@angular/compiler-cli`, `ng-packagr`, `rollup-plugin-dts`) — the peer-dep walker found them via `affected_consumers` enrichment.
- `assay analyze --dep nonsense` errors cleanly: `assay: --dep value 'nonsense' is missing '@version'; expected '<name>@<version>'`.
- `assay analyze --dep sha2@0.10.9` (already-at-target) and `--dep nonexistent@1.0.0` (not declared) both exit cleanly with the per-ecosystem and cli-level notices.

712 tests pass (up from 702 in 1.4.2); clippy clean under `-D warnings`.

## [1.4.2] — 2026-05-20

Continuation of the 1.4.1 internal refactor: finish breaking up the remaining godfiles. No behavior changes; no public-API changes; identical CLI surface, receipt schema, and event stream. 693 tests still pass; clippy still clean under `-D warnings`; end-to-end dogfood against assay's own repo still emits the expected 4 cargo proposals.

### Internal

- **`validator.rs` (2898 lines) → `validator/` module tree** with three backend submodules + a trim mod.rs:
  - `validator/backend_build_test.rs` — manifest-inferred cargo build+test backend (`BuildTestBackend`)
  - `validator/backend_forge.rs` — `ForgeRunBackend` + `ValidatorCommandBuilder` + `ForgeRunSummary` + `parse_forge_run_output`
  - `validator/backend_custom.rs` — `CustomBackend` for `--gate-cmd` / `--gate-file`
  - `validator/mod.rs` — trait, types, the `Validator` orchestrator, and the shared `stderr_tail` helper
- **`ecosystem/github_actions.rs` (2350 lines) → `ecosystem/github_actions/` module tree**:
  - `github_actions/tag_utils.rs` — pure tag-parsing helpers (`parse_action_tag`, `tag_specificity`, `count_version_segments`, `truncate_tag`, `is_shortcut_ref`, `is_likely_commit_sha`, `is_version_char`)
  - `github_actions/manifest_discovery.rs` — workflow/composite-action detection + `uses:` line parser (`walk_composite_actions`, `workflow_to_manifest`, `collect_uses_references`, `parse_uses_value`, `extract_tag_comment`)
  - `github_actions/propose.rs` — proposer (`aggregate_actions_from_manifests`, `pick_target_tag`, `build_action_proposals`, `build_sha_pin_proposal`, `classify_action_bump`, `explain_action_bump`, `filter_ignored_actions`)
  - `github_actions/apply.rs` — `rewrite_uses_in_workflow` + line-terminator preservation
  - `github_actions/mod.rs` — `GitHubActionsEcosystem` impl + shared types (`UsesReference`, `UsesKind`, `PinKind`, `ActionAggregate`) + tests
- **`ecosystem/cargo.rs` (2288 lines) → `ecosystem/cargo/` module tree**:
  - `cargo/parse.rs` — `CargoUpdateLine` / `CargoUnchangedLine` types and `parse_cargo_update_output` / `parse_cargo_unchanged_output` / `diff_lockfiles` / `cross_check`
  - `cargo/classify.rs` — caret-compat group rules (`classify_unchanged_bump`, `explain_unchanged_bump`, `explain_lockfile_only_bump`)
  - `cargo/propose.rs` — `run_cargo_proposer`, `propose_from_cargo_dry_run`, `propose_from_cargo_stdout`, `propose_unchanged_from_cargo_stdout`, `filter_ignored_crates`, `tag_proposals_with_cargo_cohorts`, transitive-dep filter, `sanitize_id_segment`
  - `cargo/apply.rs` — `apply_cargo_proposal` + merged variants + `apply_cargo_update_to_tree` + copy-back primitives
  - `cargo/consumers.rs` — `resolve_cargo_consumers` + `find_workspace_consumers_in_metadata` + `can_reach_any` (the cargo_metadata BFS)
  - `cargo/mod.rs` — `CargoEcosystem` impl + tests
- **`ecosystem/npm.rs` (3845 lines) → `ecosystem/npm/` module tree** — finished the split started in 1.4.1:
  - `npm/flavor.rs` — `NpmFlavor` + `detect_flavor` + `yarn_lock_is_berry` + platform-aware binary names + spawn-IO error mapper
  - `npm/outdated.rs` — `NpmOutdatedRow` + `parse_npm_outdated_output` + `parse_yarn1_outdated_output` + `read_lockfile_versions` + `backfill_current_from_lockfile`
  - `npm/classify.rs` — `classify_npm_bump` + `explain_npm_bump` + `explain_npm_lockfile_only_bump`
  - `npm/direct_deps.rs` — `collect_direct_dep_names` + `collect_direct_deps_with_constraints`
  - `npm/berry.rs` — `parse_berry_lockfile` + `parse_berry_descriptor_name` + `query_berry_latest_version` + `propose_berry_updates`
  - `npm/workspaces.rs` — `WorkspaceMember` + `detect_workspace_members` + `resolve_npm_consumers`
  - `npm/apply.rs` — `apply_npm_proposal` + install variants + package.json edit helpers + `copy_back_npm_sandbox`
  - `npm/propose.rs` — `build_npm_proposals` + `run_npm_proposer` + `filter_to_direct_deps` + cohort/override/ignore annotation pipeline
  - `npm/peer_walk.rs` — existing module retained as-is
  - `npm/mod.rs` — `NpmEcosystem` impl + tests

### Why

Every previously-published symbol path is preserved through re-exports at the matching `*/mod.rs`; downstream callers (`assay-gui`, `cli`, `apply_merger`) didn't need to change. The change is purely a layout one: each submodule is now under ~750 lines of production code with focused tests, so a future change to (say) the npm `--apply-pr` flow lives in `npm/apply.rs` without sifting through 3845 lines of unrelated outdated-parsing + workspace-walk + cohort-annotation code. The same standard the cli refactor set in 1.4.1.

## [1.4.1] — 2026-05-20

Internal refactor: break up the godfiles. No behavior changes; no public-API changes; identical CLI surface, receipt schema, and event stream. 693 tests still pass; clippy still clean under `-D warnings`.

### Internal

- **`cli.rs` (7484 lines) → `cli/` module tree** with 14 focused submodules organized by concern:
  - `cli/args.rs` — clap-derived flag types (`Cli`, `AnalyzeArgs`, `EcosystemSelector`, `ExecutorChoice`, `OutputFormat`, `ApplyMode`)
  - `cli/time_utils.rs` — ISO 8601 + run-id helpers, chrono-free
  - `cli/paths.rs` — path-shape helpers (extended-length prefix strip, forward-slash normalize, relative-prefix, same-path, enclosing git root)
  - `cli/polyglot.rs` — auto-detection of polyglot/monorepo scan roots
  - `cli/git_ops.rs` — git plumbing for the apply pipelines + worktree prep
  - `cli/run_state.rs` — cross-module data types (`WorkUnit`, `WorkerOutcome`, `ProposalRun`, `PreValidationFailureRow`, `CommitSummary`, `MergedDropInfo`, `ApplyPrSummary`)
  - `cli/reporting.rs` — text-mode rendering (`tier_counts`, `print_discovered_section` + cohort/single helpers, `format_*`, `aggregate_*`, `format_red_proposal_section`, `ship_counts`)
  - `cli/apply_local.rs` — `perform_apply_local_commit` + `build_commit_body` + `build_ship_plan_from_runs` (shared with apply_pr)
  - `cli/apply_pr.rs` — `perform_apply_pr` + all its preflight / label / reviewer / branch-name / `PartialApplyState` RAII helpers
  - `cli/project_scope.rs` — `ProjectScope` + `resolve` decision rule, `capture_run_context`, `infer_project_scope_from_manifest`
  - `cli/config_resolve.rs` — validator construction, `parse_cache_ttl` (still publicly re-exported), workflow filter, explanation injection, ignore-list merging, ecosystem enablement, zero-manifest hints
  - `cli/text_report.rs` — per-ecosystem `[<eco>] manifests detected: N` breadcrumb + `Cargo.lock`-missing warning
  - `cli/work_unit.rs` — `build_work_units` cohort-aware bucketing, `process_proposal_unit` worker body, `emit_run_started_event` NDJSON event, `cohort_display_name`
  - `cli/mod.rs` — orchestrator only: `run` / `dispatch` / `parse_cli` + `analyze_command` driver + the test module
- **`ecosystem/npm.rs` (4120 lines) → `ecosystem/npm/` module tree** — started:
  - `ecosystem/npm/peer_walk.rs` — peer-dependency walker across four install layouts (flat `node_modules`, pnpm virtual store, yarn berry unplugged, yarn berry `.pnp.data.json`)

### Why

A 7484-line file is hard to load into LLM context and friction-y for humans navigating it. The new layout means a change to (say) the `--apply-pr` preflight checks lives in one ~700-line file with focused tests, not buried among 3000 lines of unrelated orchestration. Public stability promise is preserved via re-exports at `cli/mod.rs` (`Cli`, `Command`, `AnalyzeArgs`, `parse_cli`, `run`, `parse_cache_ttl`).

## [1.4.0] — 2026-05-20

NDJSON streaming events for real-time GUI consumption. The new `--format ndjson` output mode emits one JSON object per line as the run progresses, designed for a Tauri-based progress GUI (`assay-gui`, separate repo) and other live-progress sidecars that update UI state as proposals flow through the worker pool.

### Added

- **`--format ndjson` output mode.** Emits a structured event stream on stdout: `run_started` (with full proposal inventory + cohort groupings), `proposal_validating` / `proposal_completed` for non-cohort proposals, `cohort_validating` / `cohort_completed` for multi-member cohort lockstep units (so the GUI groups members visually instead of showing N separate spinners), `run_completed` with the summary + run.json path. Each event has a `type` discriminator + variant-specific fields. Suppresses all text output so the stream is parseable without prefixes.
- **`assay::events` module** is part of the public API surface under the 1.0 stability promise (new variants and fields are additive minor changes; existing variants don't change shape within a major version). Re-exports the `Event`, `EventSink`, `EventProposal`, `EventCohort`, `EventSummary` types plus the `NoopEventSink` and `NdjsonStdoutSink` impls.
- `WorkerContext.event_sink` threads the sink through to every worker. The pipeline calls `sink.emit(...)` unconditionally; the default no-op sink drops events when the user didn't request `--format ndjson`, so existing Text/Json callers see no behavior change.

### Internal

- 4 new tests for the event types (round-trip serde, cohort field presence, skip-when-none on optional cohort field, no-op sink basic). Test count: 693 (up from 689).
- `process_proposal_unit` now records `worker_started: Instant` so `proposal_completed` / `cohort_completed` events can carry `duration_ms`.
- New shared `cohort_display_name` helper looks up cohort display strings across both ecosystem registries.

### Live dogfood (slate ui)

- `assay analyze --format ndjson --ecosystem npm` against slate's ui emits two lines: a `run_started` event with all 37 proposals + 3 cohort groupings (angular-framework × 7, angular-tooling × 2, tiptap × 20), then `run_completed` with the summary. Under `--validate`, the per-proposal and per-cohort validating/completed events fire in real time as the worker pool churns.

## [1.3.0] — 2026-05-20

Cargo workspace cohort awareness — the Cargo analog of the npm cohort work shipped in 1.1.0. Crate families that MUST move together (`tokio` + `tokio-util`, `serde` + `serde_derive`, `tracing` + `tracing-core` + `tracing-subscriber`, `tauri` + `tauri-build` + `tauri-plugin-*`, `prost` family, `tonic` family, `axum` family, `hyper` family, `tower` family, `clap` family, `reqwest` + `reqwest-middleware`, `bevy_*`) now apply + validate + bisect atomically — partial cohort applies (e.g. `tokio@1.45` without `tokio-util` paired to that major+minor) are eliminated.

### Added

- **`ecosystem::cargo_cohorts` module** with 12 hardcoded cargo cohort definitions covering tokio, serde, tracing, clap, axum, tower, prost, hyper, tonic, reqwest, tauri, and bevy families.
- **`tag_proposals_with_cargo_cohorts`** in `ecosystem::cargo` hooks the registry into the cargo proposer pipeline. Pure annotation pass; ecosystem-agnostic widening then runs.
- **`ecosystem::cohort_pipeline`** is a new shared (`pub(crate)`) module that hosts `widen_cohort_tiers` + `tier_severity`. Both ecosystems now use the same widening logic, keeping cohort behavior consistent across cargo + npm.

### Internal

- 12 new tests in `cargo_cohorts` (exact + prefix matches, lookalike guards, duplicate-id + non-empty registry invariants). Test count: 689 (up from 677).
- `widen_cohort_tiers` moved out of `ecosystem::npm` into the shared `cohort_pipeline` module; npm.rs re-exports the symbol so existing callers don't break.

### Live dogfood (mortar src-tauri)

- **tauri cohort**: 3 packages collapsed (`tauri`, `tauri-build`, `tauri-plugin-dialog`) under one Compatible-tier header.
- **prost cohort**: 3 packages collapsed (`prost`, `prost-reflect`, `prost-types`) under one Breaking-tier header.
- **reqwest cohort with tier widening**: the second `reqwest` entry (at a different version) shows `[cohort-lockstep: widened from compatible to breaking to match reqwest (lockstep with 2 members)]` — the lockstep widening rule firing on real data.

## [1.2.0] — 2026-05-20

Yarn berry (yarn 2+) PnP support for peer-dependency cross-reference. Closes the v1.1 dogfood gap: monorepos using yarn berry's Plug'n'Play resolution were invisible to the consumer-search step because PnP doesn't materialize `node_modules/`.

### Added

- **Yarn berry `.yarn/unplugged/` walker.** Walks `.yarn/unplugged/<pkg>-npm-<ver>-<hash>/node_modules/<pkg>/package.json` (the subset yarn has unzipped for install-script or native-binding reasons). Layout mirrors pnpm's virtual store, so the same `walk_flat_node_modules` reusable walker handles it.
- **Yarn berry `.pnp.data.json` parser.** Reads yarn's structured PnP runtime data and checks each registry entry's `packagePeers` array — yarn's authoritative list of peer-dep subjects for that resolution. Catches every registered package, not just the unplugged subset (the zipped-only deps in `.yarn/cache/` are visible through this path even in zero-installs setups). Best-effort: missing, unreadable, or malformed PnP data contributes no entries, never crashes the proposer.
- Skip-self-consumption defensive check (a registry entry's own name is never reported as a peer-dep consumer of itself).

### Internal

- 5 new tests covering yarn berry unplugged walk (1), PnP data JSON parse (1), self-consumption guard (1), malformed-input robustness (1), and union-with-dedupe across unplugged + PnP data paths (1). Test count: 677 (up from 672).
- `find_peer_dep_consumers` now handles four layouts: npm/yarn1 flat, pnpm virtual store, yarn berry unplugged, yarn berry PnP data.

## [1.1.0] — 2026-05-20

Three additive features that close the cohort + monorepo gaps surfaced by the 1.0 dogfood tour. All changes are minor-version-safe under the 1.0 stability promise.

### Added

- **pnpm virtual-store walking for peer-dep cross-reference.** The npm ecosystem's `affected_consumers` now walks `node_modules/.pnpm/<pkg>@<ver>/node_modules/<pkg>/package.json` in addition to the flat hoisted layout. pnpm-style monorepos (the dominant flavor in modern Wildmason projects) put the real install under `.pnpm/`, while the top-level `node_modules/` is just symlinks to declared deps. Before this, transitive peer-dep declarers were invisible to the consumer search; now they're surfaced exactly like first-party consumers. Dedupes by package name across multiple peer-resolution suffixes (e.g. `@wildmason+aegis@1.5.4_@angular+core@21.0.0` and `@wildmason+aegis@1.5.4_@angular+core@22.0.0` register as one consumer).
- **Multi-cohort lockstep tier widening.** When two or more proposals share a cohort id (`@angular/*` framework, `@tiptap/*`, `@next/*`, etc.), the most invasive member's tier (Breaking > Compatible > LockfileOnly) now propagates to every cohort member. A `@angular/core` Breaking bump bundled with a `@angular/common` Compatible bump can NOT be applied as "Compatible for common, Breaking for core" — pnpm/npm refuses to resolve the lockfile that way. Widened proposals get a structured note (`cohort-lockstep: widened from compatible to breaking to match angular-framework (lockstep with 2 members)`) so the operator can see at a glance why the cohort is being flagged as Breaking. Single-member cohorts are NOT widened — there's no lockstep to enforce.
- **Atomic apply-as-one-unit for cohort lockstep.** Multi-member cohorts are now applied + validated together as a single atomic unit instead of as N independent proposals. The worker applies ALL members to one sandbox via `apply_merged`, validates the combined state once, and the aggregator expands the shared outcome into one `ProposalRun` per member. The merger's bisect step is cohort-aware: when the merged set goes red, the bisect drops cohort members as a group, never alone. This eliminates the partial-cohort failure mode where `@angular/core@22` would be shipped without `@angular/common@22` (which pnpm/npm would then refuse to resolve on the host).

### Internal

- 17 new tests covering pnpm virtual-store walking (4), cohort tier widening (5), cohort-aware bisect drop groups (3), and cohort-aware work-unit construction (5). Test count: 672 (up from 655).
- `WorkUnit` carries `lockstep_members: Vec<Proposal>` (internal type, no stability impact); `WorkerOutcome::CohortCompleted` is a new variant the aggregator expands into per-member `ProposalRun`s.

### Live dogfood

- **slate ui** (npm + @angular/* + @tiptap/*): 37 proposals collapsed to 3 cohort headers (`@angular/* framework` × 7, `@angular/* tooling` × 2, `@tiptap/*` × 20) + 5 stand-alones. Display density wins vs. the pre-1.1 wall-of-proposals view.

## [1.0.0] — 2026-05-20

**Stable release.** Six releases in two days (0.2.0 → 0.7.0) closed every value-prop gap and bug surfaced by the multi-target dogfood tour. 1.0.0 is the same crate as 0.7.0 plus a public stability commitment.

### Stability promise

Starting at 1.0, three surfaces follow [SemVer 2.0](https://semver.org/spec/v2.0.0.html):

- **CLI:** every flag documented in `assay analyze --help` is stable. New flags may be added in minor releases. Subcommands and their flags will not be removed or semantically repurposed within a major version. Exit codes are stable (`0` success, non-zero error).
- **Receipt schema:** the JSON shape under `.assay/runs/<run-id>/run.json` (rooted at `AssayRunReceipt`) carries `schema_version` and is forward-compatible within a major version. New fields are additive with `#[serde(default)]`; existing fields don't change shape or semantic.
- **Public Rust API:** the types re-exported from `lib.rs` — `Proposal`, `Manifest`, `ManifestKind`, `Classification`, `ProposalKind`, `ValidationOutcome`, `AssayRunReceipt`, `Error`, `Result`, `AnalyzeArgs`, `DependencyEcosystem`, `EcosystemContext`, `EcosystemName` — follow SemVer. Adding variants to enums in this set is a minor change; removing or renaming is a major change.

Internal modules (`apply_merger`, `worker_pool`, `validator`, `verdict_cache`, `workflow_filter`, `process_runner`, `redact`, `external_deps`, `member_gate`, `publisher`, `sanitize`, `config`) are now `#[doc(hidden)]` — they're still `pub` for the binary's use but are NOT covered by the stability promise. Treat them as implementation detail.

### Documentation

- README gains crates.io + docs.rs badges and reflects the framework-cohort + peer-dep + SHA-pin feature surface.
- `lib.rs` carries the stability statement.

### Final dogfood verification (2026-05-20)

End-to-end smoke against three targets confirms the 0.5/0.6/0.7 features integrate cleanly:

- **safe-bundle** (cargo single crate): SHA-pin proposals fire for every tag-pinned action (4 actions), tag-bump proposals still emit, cargo `affected_consumers` populates.
- **mortar** (Tauri polyglot): 22 breaking cargo proposals + npm typescript bump with peer-dep cross-reference (`typescript 5.9.3 -> 6.0.3 (2 consumers: @angular/build, @angular/compiler-cli)`).
- **ci-forge** (Cargo workspace + nested `apps/web/` npm): `vite 7 -> 8 (2 consumers: @vitejs/plugin-react, @vitest/mocker)` — peer-dep cross-reference + nested-monorepo discovery both working.

### Internal

- `lib.rs` re-exports unchanged; the surface is the same as 0.7.0.
- Test count: 655 (unchanged from 0.7.0).
- `#[doc(hidden)]` added to 12 internal modules; docs.rs landing page now shows only the stable surface.

## [0.7.0] — 2026-05-20

"npm peer-dep awareness" release. Closes the third largest dogfood gap: `affected_consumers` was empty for every npm proposal. For a library that declares `peerDependencies: { "@angular/core": ">=21" }`, an `@angular/core` bump may shift the minimum peer range — exactly the cross-cut a library author needs. Pre-0.7.0 that signal was invisible.

### Added

- **npm peer-dep cross-reference.** `resolve_npm_consumers` now walks `node_modules/*/package.json` (flat layout) and `node_modules/@*/*/package.json` (scoped layout) looking for `peerDependencies` declarations of the proposal's subject. Each matching package name is added to `affected_consumers`. Workspace-member detection still runs first; peer-dep declarers are appended without duplicates.
- **TypeScript-affects-Angular signal.** Slate dogfood post-fix: `typescript 5.9.3 -> 6.0.3 (2 consumers: @angular/build, @angular/compiler-cli)` — the operator now sees at a glance that bumping TypeScript may break Angular tooling that declares TS as a peer. `@angular/cdk 21.2.9 -> 21.2.11 (1 consumer: @wildmason/aegis)` — the project's own dependency on aegis is recognized as a peer-dep relationship.
- **Tiptap-extension peer awareness.** `@tiptap/pm` shows 9 consumers (`@tiptap/core`, `@tiptap/extension-*`) — Tiptap extensions all declare `@tiptap/pm` as a peer, so bumping pm has clear blast-radius visibility.

### Behavior

- **pnpm virtual store NOT walked.** `node_modules/.pnpm/<name>@<version>/...` is out of scope for v0.7.0 — pnpm projects still get the workspace-member half. Plain `node_modules/<pkg>/` and `node_modules/@scope/<pkg>/` ARE walked, so hoisted dependencies in npm and yarn classic projects work.
- **Best-effort, IO-tolerant.** A missing `node_modules`, unreadable package.json, or malformed JSON produces zero peer-dep consumers; the proposer never crashes when node_modules is half-installed.

### Internal

- New `find_peer_dep_consumers(tree, subject) -> Vec<String>` helper in `npm.rs`.
- New `check_peer_dep(pkg_dir, subject, pkg_name, &mut out)` filter helper.
- Test count: 651 → 655 (+4: flat package, scoped package, dot-dir + non-peer skip, missing-node_modules-handled).

## [0.6.0] — 2026-05-20

"SHA-pinning" release. Closes the biggest GitHub-Actions security value-prop gap from the 2026-05-20 dogfood: every floating tag pin (`actions/checkout@v6`) is now ALSO proposed as a SHA pin (`actions/checkout@<sha> # v6.0.2`), the GitHub-recommended supply-chain-hardened form. The cache resolved the SHAs all along — pre-0.6.0 they were sitting unused.

### Added

- **SHA-pin proposals for tag-pinned GitHub Actions.** For every `actions/foo@vN` ref, the proposer now also emits a `Compatible`-tier proposal converting the floating tag to a SHA pin at the resolved tag (`actions/foo@<sha> # vN.M.P`). Each carries an explanation rule `gha:tag-to-sha-pinning`, a `security:` note linking to https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions, and the `from_tag` / `to_sha` / `to_tag` inputs for audit. The tag-bump proposal still emits independently — the operator chooses between version-tracking and security-hardening.
- **`--no-sha-pin-proposals` CLI flag.** Opt-out for teams that prefer tag pins for readability. Default behavior is "emit SHA-pin proposals" (the security-best-practice default).
- **`rewrite_uses_in_workflow` auto-comments SHA pins.** When the proposer applies a SHA-pin to a workflow that had no inline comment, the rewriter adds `# <tag>` automatically so the SHA stays human-readable. Existing-comment behavior unchanged (tag-to-tag rewrites keep their `# vN.M.P` comment, replaced with the new tag).
- **`is_likely_commit_sha` heuristic.** Recognizes 7–40 hex characters as a probable commit SHA; used to gate the auto-comment branch in the workflow rewriter.

### Changed

- **`EcosystemContext` gains `sha_pin_proposals: bool`** (default `true`). The CLI threads `!args.no_sha_pin_proposals` through `propose_updates`. `Default::default()` impl is now hand-written (was `#[derive(Default)]`) so `allow_network` defaults to `true` too instead of being silently `false`.
- **`populate_proposal_explanations` preserves proposer-supplied explanations.** Previously, every proposal's explanation was overwritten by the generic per-tier classifier in `cli.rs`. Now, when the proposer attaches an explanation at construction time (the SHA-pin path), the populator skips it. The generic classifier would have mis-labeled `tag → SHA` bumps as `gha:unparseable-tag`.

### Internal

- `build_action_proposals(manifests, client)` → `build_action_proposals(manifests, client, sha_pin_proposals)`. Two test call sites updated.
- New `build_sha_pin_proposal(agg, release, target_tag, client)` helper in `github_actions.rs`.
- New test coverage: SHA-pin proposal emitted when flag on, suppressed when flag off, auto-comment rewriter for SHA pins, tag-to-tag comment preservation, `is_likely_commit_sha` happy + edge cases.
- Test count: 646 → 651 (+5).

### Live verification

gha-eventsmith dogfood with `--ecosystem github-actions --explain`:
- Pre-0.6.0: 1 proposal (`actions/checkout v5 -> v6`, tag bump only; `dtolnay/rust-toolchain@stable` and `wildmason/gha-eventsmith@v1` silently skipped despite cached SHAs).
- Post-0.6.0: 3 proposals — the original tag bump PLUS two SHA-pin proposals (`actions/checkout v5 -> de0fac2e4...` and self-referential `wildmason/gha-eventsmith v1 -> bb4c5df3...`). Each annotated with `[gha:tag-to-sha-pinning]` and the security rationale.

## [0.5.0] — 2026-05-20

"Framework cohort" release. Closes the largest UX gap from the 0.4.0 dogfood: Angular / Tiptap / Vue / Next / Nuxt / SvelteKit / Astro / React / Vitest / Storybook / NestJS / Remix / @tauri-apps/* packages all publish in lockstep, but pre-0.5.0 they emitted as N independent proposals. Slate dogfood: 9 separate `@angular/*` proposals + 20 separate `@tiptap/*` proposals (33 lockfile-only lines total) when conceptually each cohort is one upgrade decision.

### Added

- **`cohort: Option<String>` field on `Proposal`.** Packages that belong to a known framework cohort get tagged at proposer time. New `crate::ecosystem::npm_cohorts` module holds the hardcoded definitions; matcher uses exact + prefix rules. 15 cohorts shipping: `angular-framework`, `angular-tooling`, `angular-components`, `tiptap`, `nextjs`, `nuxt`, `sveltekit`, `astro`, `react`, `vue`, `vitest`, `storybook`, `nestjs`, `remix`, `tauri-js`.
- **Cohort-aware reporter.** Per-tier section collapses cohort members into a single header line (`@angular/* framework cohort (7 packages, 21.2.4 -> 21.2.13):`) with an indented member list. Single-member cohorts render as stand-alone proposals (no cohort overhead when there's nothing to group). Version ranges are surfaced when members target different versions (e.g. `@angular/cdk` lags `@angular/core` by 2 patches → `21.2.1..21.2.4 -> 21.2.13`).
- **Lockfile-only tier surfaces in the per-tier section when it contains cohorts.** Pre-0.5.0 lockfile-only was always collapsed into the top-of-run count to keep cargo runs lean; now it renders when there's cohort grouping to show (typical Angular/Vue/React project shape). Single-package cargo runs unchanged.
- **npm `overrides` / pnpm `pnpm.overrides` / yarn `resolutions` honored** as annotations. Slate dogfood: package.json overrides block was silently ignored; the operator had no signal that adopting a proposal would conflict with an existing pin. Each proposal whose subject is governed by an override now carries `override-pinned to <version>; adopting this bump would conflict` in its `notes` array. Path-form keys (`"foo > bar"`) are handled — the right-most segment is the package being pinned. Conditional pnpm overrides (`{ "..": "1.0.0" }`) handled too.

### Internal

- New `npm_cohorts::CohortDef { id, display, exact, prefixes }` struct.
- New `npm::tag_proposals_with_cohorts` post-processing step (npm proposer pipeline).
- New `npm::annotate_proposals_with_overrides` post-processing step (npm proposer pipeline).
- New `print_group_with_cohorts` + `print_cohort_block` + `print_single_proposal_line` reporter helpers (replaces the inline closure that lived in `print_discovered_section`).
- Test count: 629 → 646 (+17: 10 cohort matcher tests, 5 override-parsing tests, 2 reporter cohort-grouping integration tests).

## [0.4.0] — 2026-05-20

"Polish & correctness" release. A seven-target dogfood tour across the Wildmason fleet (`ci-forge`, `gha-eventsmith`, `aegis`, `slate`, `mortar`, `helm`, `wildmason.dev`, plus the `nlg` smoke) surfaced two real correctness bugs, three significant UX gaps, and a long tail of receipt-schema papercuts. All addressed.

### Fixed (correctness)

- **`--ignore npm:<subject>` is a silent no-op.** `NpmEcosystem::propose_updates` took the `EcosystemContext` as `_ctx` (deliberately ignored) and never applied the per-ecosystem ignore filter that cargo + github-actions both honored. New `filter_ignored_packages` mirroring the existing `filter_ignored_crates` / `filter_ignored_actions` helpers, plumbed into the proposer. Confirmed live on aegis: `--ignore npm:typescript` now drops the `typescript 5.9.3 -> 6.0.3` proposal (count 10 → 9, breaking-tier 1 → 0).
- **Duplicate proposal IDs on multi-version transitive deps.** Two `reqwest` proposals (`0.12.28 -> 0.13.3` AND `0.13.2 -> 0.13.3`) both got ID `cargo-reqwest-0-13-3` because the format only included `subject` + `to`. Under `--apply-pr` the branch-per-proposal flow would clobber one branch with another. Cargo + npm proposal IDs now wedge the `from` version between subject and target (`cargo-reqwest-0-12-28-to-0-13-3`, `npm-left-pad-1-0-0-to-1-3-0`). Pre-1.0 ID format change; verdict cache is content-addressed, not ID-keyed, so existing caches are unaffected.
- **`--project <dir>` returned 0 manifests for every polyglot layout.** The `--project <dir>` branch of `ProjectScope::resolve` returned EARLY without invoking `detect_polyglot_subdirs`. Auto-detect only fired on the legacy `--repo` path. Slate (`--project slate` missed `ui/`), ci-forge (`--project ci-forge` missed `apps/web/`), and mortar (`--project mortar` missed BOTH `src-tauri/` AND `ui/`) all silently dropped the majority of their actionable proposals. Mortar's case dropped 49/52 (94%). Extracted the polyglot block into a shared `augment_with_polyglot_subdirs` helper called from both `ProjectScope::resolve` branches. Live verification: mortar 3 → 52 proposals, ci-forge 6 → 13, slate 0 → 37.
- **Polyglot detection skipped the entire repo when root had ANY manifest.** ci-forge's shape — Cargo workspace at root + Vite/React frontend at `apps/web/` — fell through the gate. New per-ecosystem gating: root `Cargo.toml` suppresses the cargo subdir probe (workspace covers members) but does NOT block the npm subdir probe. Inverse holds for root `package.json`. The npm probe also walks one level into `apps/<name>/` and `packages/<name>/` so monorepo-style nested frontends are reachable.
- **`--format json` produced invalid JSON.** Output was a stream of concatenated top-level JSON objects (one per ecosystem-scan_root pair from inline `report_json` calls) AND omitted proposals entirely — the payload contained only manifest-detection records. `JSON.parse(stdout)` failed with "Extra data"; `jq` saw only manifest scans. Confirmed across 4 of 7 dogfood agents. Fix: suppress inline per-ecosystem JSON during the scan phase, emit ONE valid JSON document at end-of-run mirroring the receipt 1:1, plus a sibling `receipt_path` field for callers who want to drop into the on-disk artifact.

### Fixed (UX)

- **Summary line honors `--ecosystem` filter.** Pre-fix: "across 3 ecosystem(s)" regardless of how the filter narrowed the active set. Post-fix: "across N of M ecosystem(s)" when filtered. Three dogfood agents flagged this.
- **`--member-gate` paired with DryRun emits a hint.** The flag only affects the validator stage; DryRun (the default) doesn't run the validator, so `--member-gate` had no observable effect. New `[member-gate] note: ...` one-liner explains the no-op and points at `--validate` / `--apply-local` / `--apply-pr`.
- **`--offline` rustdoc matches behavior.** Pre-fix doc said network-bound ecosystems "emit no proposals" under `--offline`; actual behavior falls back to the action-store cache and emits cache-served proposals annotated with `source:offline-cache`. Help text + behavior now agree.
- **Zero-manifest hint when `--ecosystem <name>` returns nothing.** Per-ecosystem remediation line surfaces the most common cause: GHA repos without `.github/workflows/`, cargo crates without a manifest at the scan root, npm projects in a subdirectory.
- **npm orphan-lockfile suppression.** `package-lock.json` (or `pnpm-lock.yaml`, `yarn.lock`) without a sibling `package.json` is no longer reported as a detected manifest. Mortar dogfood: empty root-level `package-lock.json` short-circuited polyglot traversal AND looked like a successful "1 manifest, 0 proposals" scan.
- **`--quiet` flag** suppresses the per-ecosystem manifest-detection breadcrumbs and the per-proposal `proposal <id>: ...` lines during the scan. Bottom-of-run summary + tier breakdown + per-tier detail section still print. No effect on `--format json` (already batches).

### Fixed (receipt schema)

- **`run_context` block** (new, top-level, optional): captures `cli_args`, `tool_version`, `host` (os/arch) for reproducibility audits. Saves walking every provenance record for "what version on what machine."
- **Lazy `logs/` + `receipts/` subdirs.** Pre-creating both in `write_run_receipt` made every DryRun receipt directory contain two empty subdirs that read as "the run aborted partway." Stage writers (`write_stage_receipt`, log handlers) materialize them lazily now.
- **`repository.path` canonicalization + forward-slash normalization.** Drops the `\.` artifact when `--project .` was used (visible in the nlg smoke), strips the Windows `\\?\` extended-length prefix that `canonicalize()` emits, and replaces backslashes with forward slashes so cross-platform receipt consumers don't have to special-case Windows. The "receipt written to ..." log line and the `[project] auto-detected polyglot scan root:` breadcrumb get the same treatment.
- **Tighter npm bump explanations with implied manifest-edit hint.** `npm:caret-major-crossed` no longer restates the rule + boundary in slightly different words; it surfaces the boundary once AND names the implied caret-constraint widening (`widens `^5.9.3` -> `^6.0.3``). Same pattern applied to the other 3 npm tier-explanation rules.

### Deferred to v0.4.1 / v0.5.0

These dogfood findings are real but represent feature work rather than fixes:

- **SHA-pinning proposals for floating GHA tags** despite resolved SHAs in the cache (gha-eventsmith biggest value-prop gap)
- **Framework cohort awareness** — @angular/*, @tiptap/*, @sveltejs/* emit as N independent proposals violating lockstep
- **npm peer-dep cross-reference** — `affected_consumers` empty for all npm proposals; no peer-dep awareness for library projects
- **npm `overrides` block** ignored (slate)
- **Tag cache stores `exists:true` but not the resolved SHA** — bundle with SHA-pinning
- **Provenance records for skipped GHA refs** (`@stable`, `@nightly`, self-ref) — bundle with SHA-pinning

### Internal

- Test count: 618 → 629 (+11 net).
- The `RunContext` struct + `forward_slash_path` / `strip_extended_length_prefix` helpers are new shared utilities.

## [0.3.0] — 2026-05-20

Four `--apply-pr` polish items surfaced by the 0.2.0 dogfood against `wildmason/safe-bundle`, all addressed:

### Added

- **Cleanup-on-failure RAII guard for `--apply-pr`.** When push or PR-open fails partway, the worktree at `.assay/runs/<run-id>/pr-tree` and the local branch created by `git worktree add -b` are now removed automatically on early-return (Rust Drop semantics). Stops the "branch already exists" footgun every retry stumbled over before. Successful runs preserve both (audit trail under `.assay/runs/`). `NothingToPublish` cleans up quietly because it isn't an error.
- **Auto-create missing PR labels** via `gh label create <name> --color ededed --description "Bumped via assay" --force`. The publisher now provisions any label declared in `config.pull_request.labels` (default `["assay", "dependencies"]`) that doesn't already exist on the target repo. On create failure, the offending label is dropped with a warning — the PR still opens. Replaces the 0.2.0 filter-only helper which would silently drop missing labels.
- **Reviewer assignment now flows from `config.pull_request.reviewers`** end-to-end, with a collaborator-existence filter (`gh api repos/<o>/<r>/collaborators --paginate`) so requesting a non-collaborator user doesn't abort the whole `gh pr create` call. Team-level reviewers (`org/team` form) bypass the filter because GitHub exposes them through a separate endpoint with different assignability rules.
- **`config.pull_request.draft` plumbed through to `gh pr create`.** Drafts open as drafts.
- **Pre-flight detection of the broken global `insteadOf` rewrite** (`url.https://x-access-token:@github.com/.insteadof = https://github.com/`). When this rule is set, `git push` for every github.com URL hits an empty-token credential and fails. The new `--apply-pr` preflight catches it before validation work begins and emits a remediation pointing at `git config --global --unset url."https://x-access-token:@github.com/".insteadOf`. `--force` bypasses.

### Internal

- Two new PullRequestBackend trait methods: `list_collaborators` (for the reviewer-existence filter) and `create_label` (for the label auto-provisioner). GhCliBackend shells out to `gh api repos/<o>/<r>/collaborators --paginate` and `gh label create --force` respectively.
- Renamed `filter_labels_to_existing` → `ensure_labels_exist` to reflect the new auto-create behavior.
- Test count: 603 → 618 (+15: 4 insteadOf check, 5 filter_reviewers, 5 ensure_labels replacing 4 filter_labels = +1 net, 5 cleanup/PartialApplyState).

## [0.2.0] — 2026-05-19

### Added

- **`--validate` apply mode.** Proposer + validator in an isolated sandbox per proposal, reports per-proposal pass/fail, but does NOT commit or open a PR. The "test before adopt" mode that closes the gap the default `analyze` couldn't cover. Joins `DryRun` (default), `--apply-local`, `--apply-pr`.
- **Verdict cache.** Content-addressed per-(workspace, workflow, backend, event) reuse of validator outcomes. Cache lives at `<repo>/.assay/verdict-cache/<sha256>.json`. Only deterministic verdicts (`Pass` / `Regression`) are persisted — `SetupFailure` and `Timeout` are environment-dependent and always re-run. Knobs: `--no-cache` bypasses; `--cache-ttl <duration>` (default `7d`; accepts `s/m/h/d/w` suffixes or bare integer = seconds) tunes staleness. Report renders `assay: verdict cache: K cached / L fresh (X% reused; ...)`.
- **`--explain` mode.** Every proposal carries a structured `BumpExplanation { summary, rule, inputs, decision }` in the receipt and the reporter renders the explanation inline beneath each proposal. Stable rule keys (`cargo:caret-major-1-plus`, `gha:ref-shape-loosening`, `npm:caret-0-x-minor-crossed`, etc.) make classifier output greppable.
- **Yarn berry full support.** New `NpmFlavor::YarnBerry` variant distinguished from yarn1 by the `__metadata:` header in `yarn.lock`. Proposer walks direct deps from `package.json` and queries `corepack yarn npm info <pkg> --json` per dep (berry core has no `outdated` command). Applier uses `corepack yarn up <pkg>@<ver>` / `corepack yarn install`. Corepack-first routing ensures the project's `packageManager`-pinned berry version actually runs even when the global `yarn` shim is yarn1.
- **`--member-gate` mode.** Workspace-member-precise validator filtering. Gate workflows that name ONLY non-affected workspace members are dropped before the validator runs. Wildcard workflows (`--workspace`, `--workspaces`, `-r`, `workspaces foreach`) and selector-free workflows are kept conservatively. Recognises Cargo (`-p`/`--package`/`--package=`), npm (`--workspace=`/`--workspace `), pnpm (`--filter`/`--filter=`), and yarn (`workspace <name>`) selectors. Report renders `assay: member-precise gating: N workflow(s) skipped`.
- **Polyglot auto-detection.** Plain `assay analyze` on a Tauri-shape repo (Cargo at `src-tauri/`, npm at `ui/`, workflows at root) now auto-adds `src-tauri/Cargo.toml` and `ui/`/`frontend/`/`app/`/`web/`/`client/`'s `package.json` to scan roots when the repo root has no top-level manifest and `[project] roots` is empty.
- **GitHub Actions ref-shape classifier.** Pin-loosening from immutable `1.85.0` to floating `v1` is now classified `Breaking` (not `Compatible`), surfacing the supply-chain regression the operator should review.
- **README + CHANGELOG.** First public-facing docs.
- **`--apply-pr` pre-flight `gh auth` check.** Verifies `gh` is installed and the active token carries `repo` scope BEFORE the validator runs, so unauthenticated operators fail fast instead of after minutes of validation. `--force` bypasses for the operator with reasons (manual PR-open path, `gh` in a non-standard location, etc.).
- **`PullRequestBackend::list_labels`** — backend trait gained a label-listing method; `GhCliBackend` implements it via `gh api repos/<o>/<r>/labels --paginate --jq '.[].name'`. Used by the publisher to filter out non-existent labels before `gh pr create`.

### Changed

- **Crate renamed to `dep-assay` on crates.io.** The bare `assay` name was claimed in 2022 by an unrelated testing-macro crate (`mgattozzi/assay`, 72k downloads, stable). The binary, library, and brand all stay `assay` — `cargo install dep-assay` produces `~/.cargo/bin/assay` and you invoke it as `assay analyze ...`. Only the package identifier on crates.io changes. README install section updated.
- **MSRV bumped from Rust 1.85 to Rust 1.88.** The source already used let-chains (stabilized in 1.88) at seven sites across `cargo.rs`, `npm.rs`, and `external_deps.rs`; the previous `rust-version = "1.85"` declaration was aspirational and the code wouldn't compile on a true 1.85 toolchain. `Cargo.toml` and `.github/workflows/ci.yml`'s MSRV job both updated to 1.88.
- **`AssayRunReceipt.schema_version`** is now driven by the central constant `model::CURRENT_RECEIPT_SCHEMA_VERSION` (value `1`) and gains `#[serde(default)]` for back-compat with hypothetical pre-versioning receipts.
- **`.assay.toml`'s `[assay]` section is now optional.** When omitted, `schema_version` defaults to the parser's current schema version. Closes a footgun where the documented example config crashed the parser.
- **`pnpm outdated -r`** (recursive) is now the default — earlier `assay 0.1.0` ran the non-recursive form, which missed workspace members entirely. `OutdatedEntry.wanted` / `latest` made `Option<String>` so `file:`/`link:`/`workspace:` deps skip cleanly without crashing the parse.
- **Cargo polyglot scans** no longer double-up the manifest path when `--project` targets a sub-directory.
- **`.assay/` artifact tree** is excluded from `assay --apply-local`'s dirty-tree refusal — assay's own receipts no longer trip its own apply guard.
- **`--project <sub-dir>`** anchors `.assay/runs/...` at the enclosing git root instead of dropping it inside the sub-project directory.

### Fixed

- **`--apply-pr` hardcoded label crashed PR-open against repos without an `assay` label.** The publisher now reads labels from `config.pull_request.labels` (default `["assay", "dependencies"]`) and filters them through `backend.list_labels()` so missing labels are dropped with a stderr warning instead of failing `gh pr create`. On `list_labels` error the publisher drops all labels to preserve forward progress — the PR is the load-bearing artifact, labels are categorisation polish.
- **`--apply-pr` "branch already exists" error gave no recovery hint.** When a prior run created a local branch and failed before PR open, retrying produced `git worktree add ... already exists` with no guidance. The new error message includes the exact cleanup commands (`git branch -D <branch>` and the corresponding remote-delete one-liner).
- **Yarn1 silently disabled.** `npm_binary_name(Yarn)` returned an empty string, short-circuiting `run_npm_proposer`. Now returns `yarn.cmd` / `yarn`.
- **Missing pnpm/yarn binary** produced the unhelpful `io error reading .: program not found`. New `map_npm_spawn_io` converts `NotFound` IO errors into `pnpm.cmd not found on PATH; install pnpm to analyze pnpm-flavored projects (detected from lockfile at <path>)`.
- **Gitignored lockfile in apply-local.** `git add Cargo.lock` against a tokio-style repo that gitignores its lockfile no longer aborts the commit; the partitioned-add wrapper stages only tracked paths and surfaces the excluded paths as a warning.
- **Optional + feature-gated consumers.** `affected_consumers` now uses `cargo metadata --all-features` so feature-gated deps are surfaced in the consumer list.
- **Cargo `[workspace.dependencies]` priority.** Editor walks workspace dep tables first, then member crates — fixes the rust-lang/cargo monorepo case where the root manifest is both workspace root AND binary crate.
- **Cargo constraint operator prefix.** `= 0.1.0-beta.1` → `0.1.0-beta.3` no longer drops the `= ` operator (would have silently widened exact-pins to default-caret).
- **Library crates without `Cargo.lock`** now emit a clear warning at scan time pointing at `cargo generate-lockfile`.

### Internal

- Three new modules: `verdict_cache.rs`, `member_gate.rs`, expanded `validator.rs` cache integration.
- New `BumpExplanation` model + per-ecosystem explainers (`cargo::explain_unchanged_bump`, `github_actions::explain_action_bump`, `npm::explain_npm_bump`).
- **Removed `publisher::UnconfiguredBackend` stub** + its module-level docstring that referenced the abandoned GitHub-App / installation-token design. `GhCliBackend` is the only live backend; the publisher's design rationale now matches the code.
- `--apply-pr` end-to-end dogfood against `wildmason/safe-bundle`. See `docs/dogfood-tour-apply-pr-2026-05-19.md`.
- **LICENSE files** — `LICENSE-MIT` + `LICENSE-APACHE` added so the dual-license declared in `Cargo.toml` ships with actual texts (crates.io best practice; the wildmason canonical pattern).
- **CI workflow** — `.github/workflows/ci.yml` rewritten to match the wildmason canonical pattern: MSRV check (Rust 1.85 via `cargo check --locked --all-targets`), `cargo package --locked` + `cargo publish --dry-run --locked` preflight, `cargo doc --no-deps` with `RUSTDOCFLAGS=-D warnings`, plus the existing fmt/clippy/test matrix across ubuntu/macos/windows.
- **Release workflow** — `.github/workflows/release.yml` rewritten as a five-job multi-target chain. `verify` (matrix: ubuntu/macos/windows; tag-version sanity + fmt + clippy + test + `cargo package` + `cargo publish --dry-run`) → `create-release` (draft GitHub Release with `gh release create --draft --verify-tag --generate-notes`) → `crate` (cargo package + sha256 + upload + `actions/attest@v4`) + `binaries` (matrix: x86_64-linux-gnu, x86_64-darwin, aarch64-darwin, x86_64-windows-msvc; build per target → package archive with README/CHANGELOG/LICENSE-MIT/LICENSE-APACHE → sha256 → smoke `--version` + `analyze --help` against the unpacked binary → attest → upload) → `publish-release` (flip draft → published). The crates.io publish itself happens locally — operator runs `cargo publish --locked` from their machine after the GitHub Release publishes, matching the established pattern across every other wildmason crate (action-proof, release-proof, safe-bundle, tauri-hardening-md, ...). CI's `cargo publish --dry-run --locked` gate in `verify` catches publish-blockers before the local publish. Workflows validated structurally via `forge run` locally (ci-forge confirms YAML parse, job graph, matrix expansion, event-trigger filter) so first push to a `v*` tag doesn't burn GH runner minutes debugging YAML.
- Test count: 468 → 603 (+135).

## [0.1.0] — 2026-05-17

Initial public release. Cargo + GitHub Actions + npm/pnpm/yarn1 proposers; `--apply-local` + `--apply-pr` apply modes. See `docs/assay-plan.md` for the design rationale and `docs/dogfood-tour-2026-05-19.md` for the 0.1.0-era audit findings that motivated the 0.2.0 cycle.
