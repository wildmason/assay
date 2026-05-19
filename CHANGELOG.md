# Changelog

All notable changes to `assay` are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project tracks [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- Test count: 468 → 603 (+135).

## [0.1.0] — 2026-05-17

Initial public release. Cargo + GitHub Actions + npm/pnpm/yarn1 proposers; `--apply-local` + `--apply-pr` apply modes. See `docs/assay-plan.md` for the design rationale and `docs/dogfood-tour-2026-05-19.md` for the 0.1.0-era audit findings that motivated the 0.2.0 cycle.
