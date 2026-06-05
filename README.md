# assay

**Test dependency upgrades against your projects' real CI before you adopt them.**

[![crates.io](https://img.shields.io/crates/v/dep-assay.svg)](https://crates.io/crates/dep-assay)
[![docs.rs](https://docs.rs/dep-assay/badge.svg)](https://docs.rs/dep-assay)

`assay` is a standalone CLI that scans a repository for outdated dependencies, computes the upgrade impact (per-workspace-member on cargo, peer-dep-aware on npm across all four install layouts: npm/yarn1 flat, pnpm virtual store, yarn berry unplugged, yarn berry PnP), and — optionally — runs the project's own gate workflows against the bumped tree to prove the upgrade survives CI before you commit it. Cargo + GitHub Actions + npm/pnpm/yarn1/yarn berry shipping. **Framework-cohort aware:** `@angular/*`, `@tiptap/*`, `next + @next/*`, etc. apply + validate atomically as one lockstep unit — partial-cohort applies (e.g. `@angular/core@22` without `@angular/common@22`) are impossible. SHA-pin hardening proposals for floating GitHub Actions tags by default.

The wedge versus Dependabot/Renovate: **monorepo blast-radius**. When `tar = { version = "0.4.45" }` lives at the workspace root and seven members consume it transitively, the question those tools don't answer is *"if I take tar 0.4.46, which of those seven still pass their CI?"* — `assay` does, by running the project's real CI workflows against the bumped tree.

## Install

```sh
cargo install dep-assay
```

The crate is published as `dep-assay` on crates.io because the bare `assay` name was taken in 2022 by an unrelated testing macro. The installed binary, library, and brand are still `assay` — `cargo install dep-assay` produces `~/.cargo/bin/assay` and you invoke it as `assay analyze ...`.

Rust 1.88 or later. No other system dependencies required for the proposer phase; the validator phase needs either `forge` ([ci-forge](https://github.com/wildmason/ci-forge)) on PATH or a manifest-inferred build/test toolchain (Cargo, npm, etc.).

## Quick start

Run a read-only scan against the current directory:

```sh
assay analyze
```

Output:

```
[cargo] manifests detected: 2
  - Cargo.toml
  - Cargo.lock
    proposal cargo-serde-1-0-228: serde 1.0.100 -> 1.0.228
assay: scanned 2 manifest(s) across 3 ecosystem(s); 1 proposal(s) (mode=DryRun)
assay: tier breakdown: 0 lockfile-only / 1 compatible / 0 breaking
assay: per-tier upgrades:
  compatible:
    serde  1.0.100 -> 1.0.228  (1 consumer: my-crate)
```

Validate every proposal against the project's CI workflows without committing or pushing:

```sh
assay analyze --validate
```

After a dry run surfaces major-version or other breaking-risk bumps, validate just those high-risk proposals:

```sh
assay analyze --validate --only-breaking
```

`Breaking` is a risk classification, not proof that the repository fails. `--only-breaking` applies only those proposals in isolated sandboxes and runs the repo gates so the report can distinguish "breaking risk, no regression observed" from "breaking risk, failed this repo's CI".

Then commit the validated-green set to the current branch:

```sh
assay analyze --apply-local
```

Or branch + push + open a pull request:

```sh
assay analyze --apply-pr
```

### Targeted single-dep validation (`--dep`)

When you already know which upgrade you want to investigate — a freshly disclosed CVE, a release note that flagged behavior changes, a partner team's request to take a specific patch — skip the full discovery scan and validate exactly that one bump:

```sh
assay analyze --dep serde@1.0.228 --validate
assay analyze --dep @angular/core@22.0.0 --validate
```

`<NAME>@<VERSION>` accepts the usual ecosystem shapes — plain (`serde@1.0.228`), scoped npm (`@angular/core@22.0.0`), prerelease (`tokio@1.45.0-rc.1`), build metadata (`toml@1.1.2+spec-1.1.0`). The current pin is resolved from your lockfile (`Cargo.lock`, `package-lock.json`, `pnpm-lock.yaml`, yarn berry `yarn.lock`); yarn1 falls back to the declared constraint in `package.json`. When the dep isn't declared in any enabled ecosystem at the repo, or is already pinned at the requested version, the run exits cleanly with a one-line notice — no false-positive zero-proposal report.

`--dep` composes with `--validate`, `--apply-local`, and `--apply-pr` the same way as a discovered proposal, so `--dep serde@1.0.228 --apply-pr` is the canonical "validate this CVE fix end-to-end and open the PR if it survives CI" workflow.

## The four apply modes

| Mode | Flag | What it does | Mutates the host? |
|---|---|---|---|
| **DryRun** | *(default)* | Proposer phase only — fast scan, no sandbox, no validator. Reports proposals as `unvalidated`. | No |
| **Validate** | `--validate` | Proposer + validator. Each proposal lives in an isolated sandbox; reports per-proposal pass/fail. | No (sandboxes retained for audit) |
| **ApplyLocal** | `--apply-local` | Validate, then commit the all-green merged set to the current branch. No push. | Yes (one commit) |
| **ApplyPr** | `--apply-pr` | Validate, branch, push, open PR via your `gh` CLI's token. Refuses to push to default/protected branches without `--force`. | Yes (commit + push + PR) |

The four modes are mutually exclusive. `--validate`, `--apply-local`, and `--apply-pr` all run the same validator pipeline; only the post-validate behavior differs.

## Supported ecosystems

| Ecosystem | Detection | Proposer | Applier |
|---|---|---|---|
| **Cargo** | `Cargo.toml` + `Cargo.lock` (workspace or single crate) | `cargo update --dry-run --workspace --verbose` + format-preserving `toml_edit` constraint widening | `cargo update` (LockfileOnly) or constraint edit + `cargo update` (Compatible/Breaking) |
| **GitHub Actions** | `.github/workflows/*.yml` | `gh api /repos/<owner>/<repo>/releases/latest` per action `uses:` ref (cached at `.assay/actions/`) | YAML in-place edit |
| **npm** | `package.json` + `package-lock.json` | `npm outdated --json` | `npm install <pkg>@<ver>` |
| **pnpm** | `package.json` + `pnpm-lock.yaml` | `pnpm outdated -r --format=json` (recursive across workspace members) | `pnpm add <pkg>@<ver>` |
| **yarn1** | `yarn.lock` without `__metadata:` header | `yarn outdated --json` | `yarn upgrade <pkg>@<ver> --exact` |
| **yarn berry** | `yarn.lock` with `__metadata:` header | Direct-dep walk + `corepack yarn npm info <pkg> --json` per dep (berry core has no `outdated`) | `corepack yarn up <pkg>@<ver>` |

Polyglot layouts (Tauri-shape `src-tauri/` + `ui/`) auto-detect on plain `analyze`. For non-standard layouts, declare scan roots in `.assay.toml`:

```toml
[project]
roots = ["src-tauri", "ui"]
```

## Key features

### Bump tier classification

Every proposal is tagged with a `BumpTier`:

- `LockfileOnly` — new version satisfies the existing constraint; only the lockfile changes.
- `Compatible` — within caret-compat group (same major for `1.0+`, same minor for `0.x`) but outside the current constraint; needs manifest edit.
- `Breaking` — crosses semver boundaries; needs manifest edit AND is breaking-by-spec.

Use `--validate --only-breaking` to turn that risk classification into repo-specific evidence. A passing validation means "no regression observed under this repo's configured gates"; it does not prove the dependency is universally safe.

### Verdict cache

Validator outcomes are content-addressed on `(post-apply workspace tree hash, workflow hash, backend, event)` and cached under `<repo>/.assay/verdict-cache/`. Identical post-apply state on a re-run short-circuits the gate workflow entirely; source, test, manifest, lockfile, and workflow edits invalidate the key. Only deterministic verdicts (`Pass` / `Regression`) are cached — `SetupFailure` / `Timeout` are environment-dependent and always re-run.

```sh
# First run: 0 cached / 3 fresh
# Second run with identical proposal set: 3 cached / 0 fresh (100% reused)
assay analyze --validate

# Bypass the cache for a known-clean baseline:
assay analyze --validate --no-cache

# Tune staleness (default 7d; accepts s/m/h/d/w or bare integer = seconds):
assay analyze --validate --cache-ttl 30m
```

### `--explain` mode

Breaking proposals render their structured rationale by default. Use
`--explain` when you want every proposal to include the classifier rule
that produced its tier:

```sh
assay analyze --explain
```

```
    serde  1.0.100 -> 1.0.228  (1 consumer: my-crate)
      [cargo:caret-major-1-plus] cargo: 1.0+ band — caret groups by major; both versions share major=1, so only the manifest pin keeps cargo from bumping (Compatible)
```

Stable rule keys (`cargo:caret-major-1-plus`, `gha:ref-shape-loosening`, `npm:caret-0-x-minor-crossed`, etc.) make the classifier output greppable and audit-friendly. Receipts persist the full `BumpExplanation { rule, summary, inputs, decision }` whenever a rationale is attached.

### `--member-gate` mode

Workspace-member-precise validator filtering. Gate workflows naming ONLY non-affected members are dropped before the validator runs:

```sh
assay analyze --validate --member-gate
```

Recognises Cargo (`-p`/`--package`/`--package=`), npm (`--workspace=`/`--workspace `), pnpm (`--filter`/`--filter=`), and yarn (`workspace <name>`) selectors. Wildcard workflows (`--workspace`/`--workspaces`/`-r`/`workspaces foreach`) and workflows with no member selectors are kept conservatively.

Example: a 3-crate workspace where only `crate-a` consumes the bumped dep, with three gate workflows (`crate-a-ci.yml` uses `-p crate-a`, `crate-b-ci.yml` uses `-p crate-b`, `workspace-ci.yml` uses `--workspace`):

```
# Without --member-gate: 3 workflows run.
assay: verdict cache: 0 cached / 3 fresh

# With --member-gate: crate-b-ci skipped (named only crate-b, which doesn't consume the dep).
assay: verdict cache: 0 cached / 2 fresh
assay: member-precise gating: 1 workflow(s) skipped (named only non-affected workspace members)
```

### Validator backends

Auto-selected based on what's available:

1. **`ForgeRunBackend`** (default when `forge` is on PATH and `.github/workflows/` exists). Runs the project's real GHA workflows via [ci-forge](https://github.com/wildmason/ci-forge).
2. **`BuildTestBackend`** (fallback). Runs `cargo build && cargo test` (cargo) or `npm test` (npm) — manifest-inferred, no forge needed.
3. **`CustomBackend`** (explicit override). `--gate-cmd "<shell line>"` or `--gate-file <script-path>`. The script's shebang controls interpretation. Bypasses `--executor`.

Validator-specific knobs:

```sh
# Override the auto-selected backend with a shell line:
assay analyze --validate --gate-cmd "cargo nextest run --workspace"

# Or with a script:
assay analyze --validate --gate-file scripts/ci.sh

# Force the validator to run on the host instead of inside Docker
# (defeats build-script isolation; only use on audited dep graphs):
assay analyze --validate --executor host

# Filter the workflow set:
assay analyze --validate --include-workflow "deploy.yml" --exclude-workflow "release.yml"
assay analyze --validate --no-workflow-filter   # bypass the default pull_request-trigger filter
```

## Configuration: `.assay.toml`

Every section is optional. The `[assay]` header itself can be omitted when `schema_version` is the current default.

```toml
# Optional — omit to default to current schema_version.
[assay]
schema_version = 1

[ecosystems.cargo]
max_parallel = 1                  # 0 = unbounded sentinel
ignore = ["reqwest"]              # silence specific subjects

[ecosystems.npm]
max_parallel = 1

[ecosystems.github-actions]
max_parallel = 0                  # actions: no shared lock

[project]
roots = ["src-tauri", "ui"]       # polyglot scan additions
```

Per-run CLI ignores merge with config-file ignores:

```sh
assay analyze --ignore cargo:reqwest --ignore github-actions:actions/checkout
```

## Authentication (apply-pr only)

`assay --apply-pr` uses your `gh` CLI's `gh auth token` as the primary credential source. Falls back to `$GH_TOKEN`. No GitHub App registration; no JWT scaffolding.

Before validating any proposals, `--apply-pr` pre-flights `gh auth status` and refuses if `gh` isn't installed, isn't logged in, or its token lacks `repo` scope. `--force` bypasses if you have reasons (manual PR-open path, `gh` in a non-standard location, etc.). After validation, the publisher hits `gh api /repos/<owner>/<repo>` for default-branch / protected-branch metadata and refuses to push to those without `--force`.

**PR labels:** `config.pull_request.labels` in `.assay.toml` controls which labels the publisher attaches (default `["assay", "dependencies"]`). Labels that don't exist on the target repo are dropped with a stderr warning rather than failing the whole `gh pr create` call — so you can use the defaults safely on any repo.

## CLI surface

```
assay analyze --repo <PATH> [--ecosystem <SEL>]
              [--validate | --apply-local | --apply-pr]
              [--threads <N>] [--gate-cmd <CMD> | --gate-file <PATH>]
              [--ignore <ECO>:<SUBJECT>] [--project <PATH>]
              [--offline] [--refresh-cache] [--fail-fast]
              [--no-cache] [--cache-ttl <DURATION>]
              [--explain] [--member-gate]
              [--include-workflow <GLOB>] [--exclude-workflow <GLOB>]
              [--no-workflow-filter] [--executor host|docker]
              [--force] [--format text|json]
```

Run `assay analyze --help` for the full flag list.

## Receipts

Every run writes `<repo>/.assay/runs/<run-id>/run.json` with the full provenance trail: per-proposal classification, validator outcomes (including cached vs fresh and member-gate-skipped counts), publisher results, and per-stage stderr tails for failures. The schema is versioned via `schema_version`; back-compatible additive changes don't require a bump.

## Architecture

See [`docs/assay-plan.md`](docs/assay-plan.md) for the full design document.

## Companion tools

- [**ci-forge**](https://github.com/wildmason/ci-forge) — offline GitHub Actions runner. `assay`'s `ForgeRunBackend` shells out to `forge run` to validate proposals against the project's real workflows.

## License

Dual-licensed under MIT or Apache-2.0, at your option.
