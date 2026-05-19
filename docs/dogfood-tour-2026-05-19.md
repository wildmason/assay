# Assay Dogfood Tour — 2026-05-19

> Status: completed · binary `target/release/assay.exe` (HEAD = 32de551) · host = Windows 11, Node 22.x, Cargo nightly stable toolchain, Docker 29.2.0, pnpm 11.1.3, yarn 1.22.22

## Scope

End-to-end exercise of the assay v0.1.0 surface against real-world repositories. No source-code edits to assay or to any target — every test was either a plain `analyze` against the live working tree or `--apply-local` against a fresh `git clone --depth 1` into `%TEMP%`.

## Coverage at a glance

| Wave | Targets | Mode | Ecosystems exercised | Proposals surfaced |
|------|---------|------|----------------------|--------------------|
| 0 | assay (self-host)         | analyze + --apply-local (host gate `cargo check`) | Cargo                  | 4 → 3 green / 1 red |
| 1 | 20 Wildmason OSS repos    | analyze (offline)                                  | Cargo + GHA            | 35 cargo + 0 gha (offline) |
| 1b | 5 of those repos           | analyze (online)                                   | GHA only                | 6 GHA proposals |
| 2 | tokio, ripgrep             | analyze; ripgrep --apply-local (no-op gate)       | Cargo + GHA            | 0 (tokio: no Cargo.lock) + 13 (ripgrep) |
| 3 | 5 Wildmason Angular/npm    | analyze                                            | npm                    | 86 proposals across 5 repos |
| 3b | vite, prettier             | analyze                                            | npm (pnpm + yarn-berry)| 0 + 0 (both gaps — see findings) |
| 3c | tiny pnpm / yarn1 / npm-ws fixtures | analyze (with deps installed)           | npm flavors            | 3 / 0 / 3 (yarn1 gap confirmed) |
| 3d | pnpm workspace fixture     | analyze                                            | npm (pnpm-workspace.yaml) | 1 of 3 expected (workspace-member gap) |
| 5  | Bridge polyglot (Tauri)    | analyze; analyze --project src-tauri; analyze with multi-root `.assay.toml` | Cargo + npm + GHA | 5 GHA + 14 npm via --project ui; **cargo fails** in every Cargo-touching path |

## Major findings

### Critical — A. Validator stage is gated behind `--apply-*`

**Symptom:** `assay analyze` (no apply flag) reports `proposals_unvalidated: N` for every proposal. The validator stage never runs, so the report-only mode delivers a proposal list without any pass/fail verdict.

**Root cause:** `src/cli.rs:400` — the worker pool is only spun up when `mode == ApplyLocal || ApplyPr`. Otherwise the fallback at line 522 marks every proposal as `proposals_unvalidated = all_proposals.len()`.

**Why it matters:** README and `wiki/engineering/assay.md` pitch assay as *"Test dependency upgrades against your projects' real CI before you adopt them."* The default user invocation (`assay analyze`) does *not* test. Validation requires a mutating mode — there is no dry-run-with-validation flag.

**Suggested fix direction:** Add a third validator-enabled-no-mutation mode (e.g. `--validate` / `--check`) that runs the apply+validate pipeline into the isolated sandbox and reports per-proposal pass/fail without copying back. Or have plain `analyze` default to validation-with-no-copy-back. Either way, deliver the value-prop on the default invocation.

---

### Critical — J. Yarn1 proposer is silently disabled

**Symptom:** Running `assay analyze --ecosystem npm` against any project with `yarn.lock` returns `0 proposal(s)`, regardless of whether `yarn outdated --json` reports outdated entries. No warning, no error, no hint that yarn1 isn't being invoked.

**Root cause:** `src/ecosystem/npm.rs:1179`:

```rust
fn npm_binary_name(flavor: NpmFlavor) -> &'static str {
    match (flavor, cfg!(windows)) {
        (NpmFlavor::Npm, true) => "npm.cmd",
        (NpmFlavor::Npm, false) => "npm",
        (NpmFlavor::Pnpm, true) => "pnpm.cmd",
        (NpmFlavor::Pnpm, false) => "pnpm",
        (NpmFlavor::Yarn, _) => "",   // ← yarn1 disabled
    }
}
```

`run_npm_proposer:514-517` then early-returns `Ok(Vec::new())` whenever `bin.is_empty()`. The parser (`parse_yarn1_outdated_output`), the upgrade-args branch (`["upgrade", &pinned, "--exact"]`), and the install branch (`["install"]`) are all present and have unit-test coverage, but the binary-name short-circuit means **none of them ever run from `run_npm_proposer`**.

**Why it matters:**
1. The recent commit `feat(npm): yarn1 proposer + applier (NDJSON parser + upgrade wiring)` advertises yarn1 support that the binary-name function reverts.
2. `wiki/engineering/assay.md` lists yarn1 as a supported flavor.
3. The lockfile-flavor comment at `npm.rs:60-62` says yarn is *"recognized but not actionable in v1"* — that comment was true once, isn't quite true now (the wiring exists), but the binary-name gate makes it functionally true again. Three places-of-truth that don't agree.

**Suggested fix direction:** Replace line 1179 with `(NpmFlavor::Yarn, true) => "yarn.cmd"` / `(NpmFlavor::Yarn, false) => "yarn"` and delete the stale comment at 60-62. The rest of the chain already supports yarn1.

**Verified reproducer:** `/tmp/assay-dogfood/fixture-yarn1` — package.json with three known-outdated deps (lodash 4.17.20, chalk 4.1.1, axios 0.27.0), `yarn install` populated yarn.lock, `yarn outdated --json` returns three entries, assay reports `0 proposal(s)`.

---

### Critical — K. Pnpm proposer misses workspace members

**Symptom:** Against a pnpm-workspace.yaml monorepo, assay only proposes upgrades for deps declared in the *root* `package.json`. Workspace member dependencies are ignored entirely.

**Root cause:** `src/ecosystem/npm.rs:520` invokes `pnpm outdated --format=json` from the repo root. Without the `-r` (recursive) flag, pnpm only enumerates root-package outdated entries and skips workspace members. The npm flavor doesn't have this bug because `npm outdated` from a workspace root naturally enumerates workspace member deps via npm 7+ flattening.

**Why it matters:** Vite (the canonical pnpm monorepo dogfood target) reports 0 proposals from assay despite hundreds of `pnpm outdated -r` candidates. Any non-trivial pnpm project — most modern Vue / SvelteKit / Astro setups — sees the same blind spot.

**Suggested fix direction:** Change the pnpm args from `["outdated", "--format=json"]` to `["outdated", "-r", "--format=json"]` and tweak `parse_npm_outdated_output` to surface the `dependentPackages` array into `affected_consumers` so the per-consumer attribution lights up.

**Verified reproducer:** `/tmp/assay-dogfood/fixture-pnpm-ws` — root has lodash, packages/a has chalk, packages/b has axios. Assay returns 1 proposal (lodash). `pnpm outdated -r` returns all 3 with `dependentPackages` populated.

---

### Significant — C. GHA proposer can recommend loosening immutable pins

**Symptom:** On `safe-bundle`, assay proposes `dtolnay/rust-toolchain 1.85.0 → v1`, classified as `compatible`. The current pin (`@1.85.0`) is to an immutable release tag; the proposed pin (`@v1`) is to a moving major-version branch. The "upgrade" loosens supply-chain guarantees.

**Why it matters:** Most security-aware shops prefer to pin tighter, not looser. A user accepting this proposal would discover later that their CI is now silently following whatever dtolnay/rust-toolchain decides to ship as `v1`.

**Suggested fix direction:** When the current ref looks immutable (`x.y.z` semver tag or full SHA) and the candidate ref is a moving tag (`v1`, `master`, `main`, branch name), either skip the proposal or downgrade its classification to a noted `RefShapeChange` tier that is opt-in.

---

### Significant — D. `--apply-local` refuses on `.assay/`-dirty trees

**Symptom:** Running `analyze` followed immediately by `analyze --apply-local` on the same repo fails with `assay: refusing to --apply-local against a dirty working tree (uncommitted changes at ?? .assay/)`. The "dirty" change is assay's own runs directory.

**Why it matters:** The natural workflow ("look first, then commit") is broken by assay's own artifacts. Users have to either `--force` (which logs as a provenance escape hatch) or `.gitignore` `.assay/` manually before each run.

**Suggested fix direction:** Exclude `.assay/` from the dirty-tree check, or auto-add `.assay/` to the repo's `.gitignore` on first run (with a logged provenance record), or treat the dirty-tree predicate as "ignore-tracked-only" rather than "ignore-nothing."

---

### Significant — E. Missing pnpm/yarn binary yields a confusing error

**Symptom:** With `pnpm` not on PATH, `assay analyze` against a pnpm project errors with:

```
assay: io error reading .: program not found
```

**Why it matters:** The message conflates "reading a manifest" with "spawning a package manager binary." A user without pnpm installed sees a path-shaped error and has no idea which binary is missing.

**Suggested fix direction:** Wrap the `std::process::Command::new(bin)` spawn in `run_npm_proposer:524` so a `NotFound` IO error is reported as `pnpm not on PATH; install pnpm to analyze pnpm-flavored projects` (with the flavor name in the message).

---

### Critical — M. Polyglot Cargo scan path is doubled up

**Symptom:** Bridge has the canonical Tauri layout (`src-tauri/Cargo.toml`, `ui/package.json`, `.github/workflows/`). Running `assay analyze --project src-tauri/Cargo.toml`, or `--project src-tauri`, or even a properly-formed multi-root `.assay.toml`, all produce:

```
[cargo] src-tauri: 2 manifest(s)
  - Cargo.toml
  - Cargo.lock
assay: cargo update failed: cargo update --dry-run exited non-zero: stderr=
error: manifest path `.\src-tauri\Cargo.toml` does not exist
```

The manifest **was just detected** in the line above. Direct invocation of `cargo update --manifest-path "./src-tauri/Cargo.toml" --dry-run --offline` from the same CWD succeeds.

**Root cause:** `cargo.rs:721` — `let manifest_path = repo.join("Cargo.toml");` produces a path relative to `repo`. The cargo subprocess is then spawned with `current_dir = repo` (line ~926) and `--manifest-path <that path>`. When `repo` is itself a sub-directory (e.g. `bridge/src-tauri`), the manifest-path becomes `src-tauri/Cargo.toml` from a CWD that's already `bridge/src-tauri/`, doubling up to `bridge/src-tauri/src-tauri/Cargo.toml`. That's the path cargo says doesn't exist.

**Why it matters:** This blocks Cargo proposals for every polyglot Tauri / monorepo layout assay was built to support. The `04ae769` ship doc claims "Bridge dogfood post-ship: 6 manifests / 18 proposals in one pass" — that was presumably exercised via npm at the time, because the Cargo arm doesn't work today.

**Suggested fix direction:** Make `manifest_path` absolute via `repo.canonicalize()?` before passing to cargo, OR keep cargo's CWD anchored at the repo root and compute the manifest-path relative to that. The latter is more idiomatic for cargo — `cargo update --manifest-path bridge/src-tauri/Cargo.toml` works from `bridge/`.

**Verified reproducer:** `/tmp/assay-dogfood/bridge-mr/bridge-clone` — temp clone of Bridge with `.assay.toml` containing `[assay] schema_version = 1\n[project] roots = ["src-tauri", "ui"]`.

---

### Significant — L. Polyglot detection without `.assay.toml` silently produces partial results

**Symptom:** Running plain `assay analyze` against Bridge finds only the 2 `.github/workflows/*.yml` and produces 5 GHA proposals. Zero Cargo, zero npm — because `src-tauri/Cargo.toml` and `ui/package.json` are in subdirectories the single-root scanner doesn't see.

**Why it matters:** A user pointing assay at a Tauri repo and getting a 5-proposal report has no idea their Cargo + npm trees were completely ignored. Bridge's wiki says "Bridge dogfood post-ship: 6 manifests / 18 proposals in one pass" — that requires the operator to know about `[project] roots = [...]` and configure it.

**Suggested fix direction:** When the repo root has no `Cargo.toml` / `package.json` but has subdirectories that do (Tauri shape: `src-tauri/` + `ui/` / `frontend/` / `app/`), either auto-add those as scan roots OR emit a warning `polyglot layout detected (src-tauri/, ui/); add [project] roots = [...] to .assay.toml to scan them`.

---

### Significant — N. `--project ui` writes the receipt under the sub-project

**Symptom:** `assay analyze --project ui` against Bridge wrote `ui\.assay\runs\assay-XXXXXX\run.json` instead of `.assay\runs\...` at the repo root.

**Why it matters:** Per the wiki, "artifact_root is where `.assay/` lives and where git operations anchor (typically the repo root)." When the receipt lands inside the sub-project, `.gitignore` rules + audit-discoverability break, and a follow-up multi-root run produces a second `.assay/` at the repo root, fragmenting state.

**Suggested fix direction:** `--project <PATH>` should set `scan_root = PATH` but keep `artifact_root` anchored at the repo root (discovered via `git rev-parse --show-toplevel` or by walking up to the first `.git/`).

---

### Critical — O. Documented `.assay.toml` example is rejected by the parser

**Symptom:** The wiki page `engineering/assay.md` shows a `.assay.toml` example without a top-level `[assay]` section. Using exactly that example produces:

```
assay: invalid config at .\.assay.toml: TOML parse error at line 1, column 1
  |
1 | [project]
  | ^
missing field `assay`
```

**Root cause:** `config.rs:17-32` requires `[assay]` with `schema_version: u32` as the first section. The wiki + plan + README examples all omit it.

**Why it matters:** Anyone copying the docs verbatim hits a confusing TOML parse error on first use. There's no migration helper, no default-on-missing — just a hard refusal.

**Suggested fix direction:** Either make `[assay] schema_version` `Option<u32>` with a documented default, OR auto-inject the section if missing AND there's no `[assay]` key, OR ship a `assay init` command that writes a correctly-shaped starter file. Update the wiki / plan / README in the same pass.

**Documented-but-broken example** (from `wiki/engineering/assay.md:131-145`):
```toml
[ecosystems.cargo]
max_parallel = 1
ignore = ["reqwest"]

[ecosystems.npm]
max_parallel = 1

[ecosystems.github-actions]
max_parallel = 0

[project]
roots = ["src-tauri", "ui"]
```

**Correct shape:**
```toml
[assay]
schema_version = 1

[ecosystems.cargo]
max_parallel = 1
ignore = ["reqwest"]

[ecosystems.npm]
max_parallel = 1

[ecosystems.github-actions]
max_parallel = 0

[project]
roots = ["src-tauri", "ui"]
```

---

### Significant — G. Yarn berry detected but silently treated as no-op

**Symptom:** prettier (yarn berry) returns `rc=0` with `0 proposal(s)`. The `__metadata: version: 9` lockfile header is the standard yarn berry marker. assay doesn't print any warning that the detected `yarn.lock` is berry-shaped and won't be processed.

**Why it matters:** yarn berry is the modern yarn — users on yarn 3/4 see "0 proposals" and assume their deps are current.

**Suggested fix direction:** Detect the berry magic in `yarn.lock` (`__metadata`) during the flavor sniff and emit a clear "yarn berry detected — not supported by assay v0.1; see #issue" warning. Comment at `npm.rs:60-62` should also be reworded — yarn1 wiring exists, only berry is the unsupported variant.

---

## Strong successes worth keeping

These are the parts where assay shines and the dogfood validated the design:

- **Real upstream API regression caught** (Wave 0 self-host): `cargo_metadata 0.18.1 → 0.20.0` failed validation with a perfect error capture — `pkg.name` changed from `String` to a wrapper type, leading to `consumers.push(pkg.name.clone())` failing to compile. assay correctly:
  - validated each proposal in isolation
  - captured the full rustc error tail in the receipt with elision marker
  - reported 3 green / 1 red
  - refused to commit because not all-green
  - retained all 4 sandbox worktrees for audit
- **Ripgrep 12-proposal apply→commit chain** (Wave 2): all 12 cargo bumps merged into a single Conventional Commit `chore(deps): bump 12 dependencies` listing each (from→to) line, touching 10 manifest paths across the workspace.
- **BumpTier classification** is accurate across 100+ proposals: lockfile-only vs compatible vs breaking lines up with semver intent in every spot-check.
- **MSRV detection** works: `zip 7.2.0 → 8.6.0 [requires Rust 1.88]` annotation in safe-bundle.
- **Workspace consumer attribution with elision** (`13 consumers: prosaic, prosaic-core, …+9`) — clean UX even for very wide workspaces.
- **Cargo workspace handling**: `[workspace.dependencies]`, `path = "../foo"` deps materialized into sandbox, renamed deps via `package = ...`, optional/feature-gated deps — none of these crashed across the 20-repo Wildmason scan.
- **GHA proposer conservatism**: tokio (7 workflows with mixed pins — `@stable`, `@master`, `@cargo-hack`, `@v6`) produced 0 proposals because every version-shaped pin is already current and no proposal was generated for floating-tag pins. No false positives.
- **GitHub action-store cache** behaved correctly during repeated GHA-online runs.
- **Receipt schema (`run.json`)** carries every provenance record needed for a postmortem — proposer details (BumpTier, manifest paths, affected_consumers), validator stderr tails, classification flags. Strong audit shape.
- **`--apply-local` safety refusals**: dirty tree, $CI set, protected branch — all guarded by default; `--force` is logged as a provenance record.

## Findings summary

| ID | Severity | Area | One-line |
|----|----------|------|----------|
| A  | Critical | CLI dispatch | Default `analyze` mode never runs the validator — value-prop only delivered via `--apply-*` |
| J  | Critical | npm (yarn1) | `npm_binary_name(Yarn) = ""` short-circuits the entire yarn1 path |
| K  | Critical | npm (pnpm)  | `pnpm outdated` invoked without `-r`; workspace members skipped |
| M  | Critical | cargo polyglot | `cargo.rs:721` doubles up the manifest-path when scan_root is a subdirectory; Bridge multi-root cargo proposer fails outright |
| O  | Critical | config | Wiki / plan / README `.assay.toml` examples omit the required `[assay] schema_version` section; copy-paste fails on first use |
| C  | Significant | GHA proposer | Can recommend loosening immutable version pin to floating major tag |
| D  | Significant | CLI safety | `.assay/` artifact dir trips `--apply-local`'s own dirty-tree refusal |
| E  | Significant | npm error UX | Missing pnpm binary surfaces as `io error reading .: program not found` |
| G  | Significant | npm (berry) | Yarn berry silently produces 0 proposals with no detection warning |
| L  | Significant | polyglot detect | Plain `analyze` on a Tauri repo without `.assay.toml` silently scans 1 of 3 ecosystems |
| N  | Significant | --project | `--project <sub-dir>` writes receipts under the sub-dir instead of the artifact_root |

## Non-findings (verified)

- **Tokio's 0 GHA proposals** was correct — all pinned actions are at latest.
- **Wildmason OSS GHA pins** are well-maintained (ci-forge's `actions/checkout v4 → v6` was the only ladder visible across 26 workflow files).
- **`scoop-bucket` and `homebrew-tap`** correctly scan to 0 manifests (no Rust / JS surface).
- **`gha-container-proof`, `gha-runner-image-proof`, `gha-service-proof`, `gha-workflow-proof`** all genuinely 0-proposal (deps current; not a coverage gap).

## Next steps

Fix difficulty rough ranking (smallest first):
- **J** (1 line): `npm.rs:1179` — return `"yarn.cmd"` / `"yarn"`.
- **K** (2 lines): `npm.rs:520` — add `"-r"` to pnpm args; thread `dependentPackages` into `affected_consumers`.
- **M** (3-5 lines): `cargo.rs:721` — canonicalize the manifest_path, or anchor cargo's CWD at the repo root with a relative manifest-path.
- **O** (config + docs): make `[assay]` section optional with a default, AND update wiki/plan/README examples.
- **D, E, G, N** (5-20 lines apiece): targeted refinements.
- **L** (10-30 lines): polyglot auto-detection.
- **C** (10-30 lines): ref-shape classifier for GHA proposals.
- **A** (~20-50 lines): CLI dispatch refactor for `--validate` mode without copy-back.

None were applied during this tour — all carry-forward work per the no-source-edits constraint.

## Verdict

The **happy-path** for the most common Wildmason shapes (single-crate Rust + single-package Angular UI + flat GHA workflows) is solid and well-tested. assay caught a real upstream API regression (cargo_metadata 0.20.0), produced a clean merged commit across a 12-proposal Cargo workspace upgrade (ripgrep), and correctly classified BumpTier across 100+ proposals.

The **polyglot path** that the `04ae769 Polyglot multi-root` ship advertised — Cargo at `src-tauri/`, npm at `ui/`, GHA at root — has a hard cargo-side break (Finding M) and undocumented config requirements (Finding O). The two together mean a fresh user pointing assay at a Tauri repo today either gets a partial scan (no `.assay.toml`) or a hard error (with `.assay.toml`).

The **npm ecosystem** ships full support for npm (+ workspaces), root-level pnpm. Yarn1 is wired through the parser/applier/install branches but is **gated off** at a single-line `npm_binary_name` return value (J). Yarn-berry is **unsupported** but the silent zero-proposal return mode is worse than an explicit "not supported" message (G).

Once J + K + M + O are fixed, the tool delivers on its core pitch across every Wildmason shape we own.
