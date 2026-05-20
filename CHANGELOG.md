# Changelog

All notable changes to `assay` are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project tracks [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
