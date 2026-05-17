# forge-tinker — Local-First Dependency Bot

> Status: Bootstrap implementation landed + remaining design - 2026-05-17

## Goal

Build `forge-tinker`, a sibling binary to `forge` that automates dependency
maintenance for repositories the operator already runs through ci-forge. It is
a friendly riff on GitHub's Dependabot: scan a repo's dependency manifests for
out-of-date versions, generate a bump, validate it by running the affected
workflow through ci-forge's execution engine, and (when configured) open a pull
request on the operator's chosen forge. The wedge is the same one ci-forge
already holds: offline-first, receipt-backed, reproducible, runner-portable.

The user has no Dependabot equivalent for repositories whose CI runs on
ci-forge (Mortar, ci-forge itself, the rest of the Wildmason OSS family).
Today they pin everything manually and discover stale crates/actions only when
something breaks. `forge-tinker` closes that loop without forcing those repos
back onto github.com's hosted execution, and does so under ci-forge's existing
receipt-driven, principle-aligned design.

There's a real differentiator versus Dependabot itself: Dependabot's
documentation explicitly does NOT run the host project's CI against a proposed
bump — it verifies the manifest resolves and stops there (verified against
the `dependabot-core` source, see Out-of-band References). forge-tinker
*validates by execution* via ci-forge's existing runner, catching the whole
class of bumps that resolve cleanly but break the build. That's a wedge
ci-forge alone makes possible.

## Scope

### In scope (v1)

- **Two ecosystems, behind a real trait:** Cargo (Rust crate dependencies via
  `Cargo.toml` + `Cargo.lock`) and GitHub Actions (pinned `uses:` references in
  `.github/workflows/*.yml` and `.github/actions/**/action.yml`). The trait
  has two real impls in v1 — that satisfies the "two-impl rule" before any
  abstraction is introduced.
- **One trigger:** manual `forge-tinker scan <repo>` invocation. No daemon, no
  cron. The operator runs it when they want a sweep.
- **Validation by execution:** every proposed bump runs through ci-forge's
  workflow runner before a PR is opened. **Cargo bumps validate inside Docker
  by default** (because the validation step runs `cargo check`/`build`, which
  executes `build.rs` of newly bumped transitive crates — that's untrusted code
  per CWE-829). GitHub Actions bumps validate inside Docker too by default,
  for symmetry and because the bumped action may itself execute new code.
  Host-mode validation requires explicit `--unsafe-host-validation`.
- **Validation eventually reuses ci-forge as a library, not a subprocess.**
  The bootstrap implementation uses one narrow, unit-tested `forge run
  --format json` command builder in `crates/forge-tinker/src/validator.rs`.
  The permanent v1 target is still to extract
  `forge_core::validation::run_workflow_for_validation(...)` from the current
  orchestrator so forge-tinker does not depend on the CLI boundary. See §A.3.
- **PR generation against GitHub via REST (planned):** branch, commit, push,
  open PR with structured body. The bootstrap code includes branch/PR-body/
  guard modules and mock-backend tests, but live `--apply-remote` is explicitly
  gated off until the GitHub App token exchange + REST publisher is wired.
- **Auth via GitHub App installation token (partially implemented).** The
  bootstrap includes GitHub App JWT minting, installation-token response
  validation, strict secrets-file loading, and redaction. Live token exchange,
  one-shot git credentials, and PR creation are still pending.
- **Receipt parity with ci-forge.** Every tinker run produces a
  `RunStoreReceipt`-shaped record at `.ci-forge/tinker-runs/<run-id>/` whose
  `provenance.records[]` carries tinker-specific entries (ecosystem scans,
  proposals, validations, PR outcomes). Same envelope as `.ci-forge/runs/`, so
  the same index loader can read both stores. Every classification uses
  ci-forge's vocabulary — `exact`, `compatible`, `simulated`, `stubbed`,
  `unsupported`.
- **Pipeline architecture, not a god-orchestrator.** v1 splits the scan loop
  into six receipt-emitting stages: `Scanner → Proposer → Validator → Applier
  → Publisher → Receiptor`. Each stage is independently unit-testable; the
  end-to-end is a thin glue function.
- **Config file:** `.forge-tinker.toml` at repo root, dependabot.yml-inspired
  but not a 1:1 port. Schema documented and versioned.
- **No-op safety:** scan supports `--dry-run` (default), `--apply-local`
  (write bump to a retained isolated git worktree under
  `.ci-forge/tinker-runs/<run-id>/work/`, no PR), and the planned
  `--apply-remote` mode. Production behavior requires explicit
  `--apply-remote`, which remains disabled in the bootstrap implementation.
  Apply modes reject `--executor host` unless `--unsafe-host-validation` is
  explicitly supplied, because dependency validation may execute newly bumped
  build scripts.

### Out of scope (deferred to later phases)

- Scheduler / daemon mode (`forge-tinker daemon`).
- Additional ecosystems: npm, pnpm, pip/poetry/uv, go modules, Docker base
  images, bundler, composer. Each lands as a new `DependencyEcosystem` impl
  in a later phase. Docker isolation per ecosystem (the per-ecosystem image
  pattern Dependabot Core uses) gets revisited when npm/pip land.
- Forge backends other than GitHub. The `PullRequestBackend` trait is
  introduced in the v2 slice where the second backend (Forgejo / Codeberg /
  Gitea) actually arrives.
- Auto-merge after CI green.
- Security advisory feeds (GHSA / OSV / RUSTSEC). v1 bumps to latest
  semver-compatible only. Security-priority PRs land in a later phase.
- Rebase-on-conflict and supersede-stale-PR loops.
- Web UI surface (`forge serve` integration).

## Current State

ci-forge is a Rust workspace with `crates/forge-core`, `crates/forge-cli`,
`crates/forge-runner`, and the bootstrap `crates/forge-tinker` crate. The
bootstrap binary already supports `forge-tinker scan` dry runs, Cargo and
GitHub Actions manifest detection/proposal plumbing, retained isolated
`--apply-local` worktrees, receipt writing under
`.ci-forge/tinker-runs/<run-id>/`, GitHub App JWT/secrets/redaction helpers,
branch/PR-body safety modules, and a narrow subprocess validator around
`forge run --format json`.

Load-bearing existing surfaces forge-tinker will reuse:

- **`forge run` execution engine** — produces durable run receipts at
  `.ci-forge/runs/<run-id>/` (`docs/architecture.md:260-267`). The current
  entry point is `forge run` (CLI, `crates/forge-cli/src/cli.rs:351-470` plus
  `PlanArgs` flattened at 353-354). The bootstrap validator shells through a
  narrow tested CLI builder; v1 still extracts a library API from
  `crates/forge-cli/src/run_orchestrator.rs` so forge-tinker can call it
  directly rather than re-shelling.
- **`forge mirror-actions`** — already resolves `uses:` references to SHAs in
  `.ci-forge/actions/` (`README.md:154-156`, `crates/forge-cli/src/cli.rs:18-19`).
  forge-tinker reuses the resolution path to find current pinned SHAs.
- **`RunStoreReceipt` / provenance index** — `provenance.records[]` indexes
  evidence by tool, version, surface, subject, status, summary counts, artifact
  path (`docs/architecture.md:266-267`). forge-tinker writes the same envelope
  with tinker records inside.
- **Existing redaction pattern** — `secret_mask_values` and `redact_run_output`
  (`crates/forge-cli/src/github.rs:559-571, 1671-1818`). v1 honestly maps onto
  this: it's a **value-registry redactor with literal string replacement**, not
  pattern-aware. forge-tinker registers its sensitive values (installation
  token, App private key bytes, App ID, installation ID) with that same
  registry before any logging or receipt write happens, AND layers a regex
  pre-filter on top that matches GitHub token shapes (`ghs_[A-Za-z0-9]{36,}`,
  `ghu_[A-Za-z0-9]{36,}`, `Bearer\s+[A-Za-z0-9._-]+`) since the value-registry
  alone misses tokens we minted but didn't remember to register.
- **Token-handling patterns** — `RunGitHubServices` at
  `crates/forge-cli/src/github.rs:289-573` shows the in-process token model
  ci-forge uses. forge-tinker mirrors the pattern: tokens are passed as
  function arguments and held in struct fields, never as environment variables.

What remains after the bootstrap:

- The `forge_core::validation` library boundary (extracted from the existing
  orchestrator - see §A.3 for surgery scope).
- Network-backed Cargo/GitHub Actions update resolution. Cargo parsing and
  lockfile diffing exist, and GitHub Actions pinned-ref parsing/rewrite exists;
  release/tag freshness and ancestor verification still need live/offline
  resolver policy.
- Live GitHub App installation-token exchange, in-memory token lifecycle, key
  rotation support, one-shot git credentials, branch push, and PR creation via
  REST.
- End-to-end apply-remote grouping policy and stale-PR supersession.
- Shared index loading for `.ci-forge/tinker-runs/` alongside `.ci-forge/runs/`.

## Proposed Approach

### A. Architectural shape

#### A.1. Sibling binary, not a `forge` subcommand

forge-tinker ships as its own binary in the ci-forge workspace, not as
`forge tinker`. The case for this decision is real but not unanimous — here
are both sides honestly weighed:

**For separate binary:**
- Principle 5 (`docs/guiding-principles.md:69-83`) explicitly excludes
  "generic CI platform," "hosted CI marketplace," and "generic workflow
  engine." Dependabot-style automation is adjacent, not Actions execution.
- Principle 13 decision checklist questions 1, 2, and 8 all fail for
  forge-tinker — it doesn't improve Actions parity, doesn't help workflows
  run unchanged, doesn't make runner labs easier.
- Release cadence and security surface diverge. A forge-tinker CVE shouldn't
  force a `forge` release (or vice-versa).
- Distribution is two binaries, two release pipelines.

**Against separate binary (the counter-arguments):**
- `forge mirror-actions` (`crates/forge-cli/src/cli.rs:18-19`) is itself
  adjacent-to-execution and already lives inside `forge`. The mirror is a
  precedent for "GitHub-side things that aren't Actions execution can sit
  inside forge."
- User mental model: "I have ci-forge, I get a Dependabot too" is simpler
  than two installs.
- Distribution simplicity: one binary, one update path.

**Decision:** ship as a separate binary anyway. The deciding factor is the
*security surface*. `forge mirror-actions` is a read-only fetcher that
populates a local store; it doesn't authenticate to GitHub with write scopes
and doesn't open PRs. forge-tinker holds App private keys and mints write
tokens. Coupling that into the same binary as the local execution engine
expands the blast radius of any forge-cli vulnerability. The principles
arguments are strong, but the security-surface argument is the load-bearing
one.

Both binaries share the same workspace, so dependency upgrades and Cargo.lock
remain unified.

#### A.2. Pipeline, not a god-orchestrator

The scan flow is six receipt-emitting stages, each with a clear input/output
contract:

```text
Scanner    : repo → Vec<Manifest>            (per-ecosystem detection)
Proposer   : Manifest → Vec<Proposal>        (per-ecosystem update resolution)
Validator  : Proposal → ValidationOutcome    (bootstrap shells through narrow `forge run`; target is forge_core::validation)
Applier    : Proposal → AppliedTree          (writes the bump into a retained isolated worktree)
Publisher  : AppliedTree → PrOutcome         (only when --apply-remote)
Receiptor  : (everything) → TinkerRunReceipt (writes the receipt-envelope record)
```

Each stage is its own module with its own unit tests; the orchestrator
function is a thin glue layer that wires stages together and emits a top-level
receipt with one nested provenance record per stage outcome.

#### A.3. `forge_core::validation` library API

forge-tinker depends on a stable, narrow function — not a CLI string. The
extraction:

- New module `crates/forge-core/src/validation.rs`.
- New function:
  ```rust
  pub fn run_workflow_for_validation(
      req: ValidationRequest,
  ) -> Result<ValidationOutcome, ValidationError>;
  ```
- `ValidationRequest` is a struct with the minimal field set: workflow path,
  workspace path, event name, executor (host/docker), an optional runner
  manifest, an optional action store, and a cancel token. It is NOT the full
  30+-flag `RunArgs` surface — the bulk of those flags only matter for
  parity-receipt attachment (proof binaries, GitHub API shim, etc.) and are
  irrelevant to validation. forge-tinker calls without proof binaries; the
  receipt it cares about is "did the workflow's exit code say success."
- `ValidationOutcome` carries the resulting `RunOutput` (or an error reason
  if the run failed to start), plus the ci-forge run id so the tinker receipt
  can link to the persisted `.ci-forge/runs/<id>/` directory.
- The extraction is a refactor of `crates/forge-cli/src/run_orchestrator.rs`:
  the current `run` entry point keeps its 30+-flag CLI shape and delegates
  the inner workflow execution to `forge_core::validation::execute(...)`. The
  CLI just translates `RunArgs → ValidationRequest + extras` and passes
  through. `forge serve` and `forge run` both keep working unchanged; the
  surgery is "extract a method," not "rewrite the orchestrator."

This is the right altitude for the abstraction. The library API is the v1
two-impl moment for "ways to ask ci-forge to run a workflow" (one impl: the
CLI subcommand; second impl: forge-tinker's validation call).

#### A.4. `DependencyEcosystem` trait

Real two-impl rule satisfied in v1 — both Cargo and GitHub Actions are
implementations of:

```rust
pub trait DependencyEcosystem {
    fn name(&self) -> &'static str;
    fn detect_manifests(&self, repo: &Path) -> Vec<Manifest>;
    fn propose_updates(&self, manifest: &Manifest, ctx: &EcosystemContext) -> Vec<Proposal>;
    fn affected_workflows(&self, proposal: &Proposal, repo: &Path) -> Vec<PathBuf>;
    fn apply_proposal(&self, proposal: &Proposal, tree: &mut WorkingTree) -> Result<(), ApplyError>;
    fn pr_body_fragment(&self, proposal: &Proposal, outcome: &ValidationOutcome) -> String;
}
```

`EcosystemContext` carries the Octocrab client (when network), the offline
action store path, and a sanitizer registry. `WorkingTree` is the tempdir
abstraction (see §H.1 for hygiene).

#### A.5. `PullRequestBackend` deferred

There is no trait in v1. v1 ships `forge_tinker::pr::github::open_pr(...)`
as a free module with the four operations (branch push, PR open,
find-existing by branch name, label apply). The trait gets introduced when
the Forgejo or Codeberg backend lands in a later slice. Single-impl traits
in Rust are ceremony and bake GitHub-isms into the trait shape (App tokens,
installation IDs) that don't apply to Forgejo.

### B. Run model

```text
forge-tinker scan <repo-path>
  [--ecosystem cargo|github-actions|all]    (default: all enabled in config)
  [--apply-local | --apply-remote]           (default: dry-run)
  [--unsafe-host-validation]                 (default: docker for both)
  [--force]                                  (override safety checks)
  [--executor host|docker]                   (validation executor; default: docker)
  [--secret-file <path>]                     (App key + IDs)
```

Per scan, the pipeline:

1. **Auth:** load GitHub App private key (PEM), App ID, and the
   installation-id-per-repo map from `~/.wildmason/secrets/forge-tinker.env`.
   Refuse to load if the file mode is group- or world-readable (Unix:
   `mode & 0o077 != 0` fails; Windows: skip the check). Sign a 9-minute JWT
   (under GitHub's 10-minute cap), exchange for an installation token via
   `POST /app/installations/{id}/access_tokens`. Token lives only in
   `OctocrabClient` heap memory; nothing is exported to env. Both the
   private-key bytes and the installation token are registered with the
   redactor before any HTTP call is logged.
2. **Scanner:** dispatch to enabled `DependencyEcosystem`s for manifest
   detection. Returns `Vec<Manifest>` per ecosystem.
3. **Proposer:** per ecosystem, generate `Vec<Proposal>`. Cargo proposer runs
   `cargo update --dry-run --workspace` in a tempdir clone, diffs the
   lockfile, builds proposals. GitHub Actions proposer resolves each pinned
   `uses:` SHA against `releases/latest` (or highest semver tag) and verifies
   the new SHA is **ahead of** the current SHA on the upstream default branch
   via `GET /repos/{o}/{r}/compare/{old}...{new}` (see Security §G.1).
4. **Validator:** for each proposal, calls
   `forge_core::validation::run_workflow_for_validation` against the
   ecosystem's `affected_workflows()` list. Default executor: `docker`.
   Records conclusion + ci-forge run id.
5. **Applier:** writes the bump into a tempdir-isolated clone. Cargo: drop the
   `--dry-run` and re-run `cargo update`. GitHub Actions: rewrite `uses:`
   lines via a structured YAML-preserving rewriter (not regex on the file
   string — see §D.2). Generates a deterministic branch name
   (`forge-tinker/<ecosystem>/<short-hash>` where the hash is over the sorted
   proposal subjects + their target versions).
6. **Publisher (only `--apply-remote`):** runs `git push` via a one-shot
   credential helper that pipes the installation token. Opens the PR via
   Octocrab. Sanitizes all upstream-supplied strings (release notes, tag
   names, commit subjects) before embedding them in the commit message or
   PR body (see §G.2 for the sanitizer contract). Refuses to push to default
   or protected branches regardless of what the proposed branch name says.
7. **Receiptor:** writes
   `.ci-forge/tinker-runs/<run-id>/{run.json,receipts/*.json,logs/*.log}`,
   using the existing `RunStoreReceipt` envelope with tinker records under
   `provenance.records[]`.

### C. Cargo resolver

`cargo update --dry-run --workspace` is the right primitive. It honors the
resolver semantics, respects feature unification, and produces the lockfile
we'd ship anyway. Reimplementing cargo's resolver is a year of work.

The dry-run flow:

1. Create a tempdir under `tempfile::TempDir::new()` (auto-cleaned, mode 0700
   on Unix). Mode is verified post-creation; if `tempfile` returned a path
   the OS gave too-permissive defaults, the run aborts.
2. `git clone --local --no-hardlinks <repo> <tempdir>`. `--shared` is rejected
   because it leaks an `alternates` pointer back to the source repo through
   the working clone (and breaks across filesystems).
3. `cargo update --dry-run --workspace --manifest-path <tempdir>/Cargo.toml`,
   stdout captured.
4. Parse the `Updating X v$OLD -> v$NEW` lines with a strict regex. Also diff
   `Cargo.lock` before/after. If the parser output ≠ lockfile diff, abort
   loudly — parser regressed.
5. For Apply mode, drop `--dry-run` and re-run; the new `Cargo.lock` is the
   bump artifact.

**Build-script execution caveat:** `cargo update --dry-run` does NOT execute
`build.rs` (resolution + fetch only). But the Validator step runs
`cargo check`/`build` inside the proposed workflow, and that DOES execute
every transitive crate's `build.rs`. The Validator default-`docker` executor
is precisely to scope that execution. Per §B step 4, host execution is gated
behind `--unsafe-host-validation`.

### D. GitHub Actions resolver

#### D.1. SHA resolution and downgrade defense

For each `uses: owner/repo@<sha>`:

1. Look up `latest` release tag via
   `GET /repos/{owner}/{repo}/releases/latest`. Fall back to the highest
   semver tag from `GET /repos/{owner}/{repo}/tags` for actions that don't
   publish GitHub Releases.
2. Resolve the tag to a commit SHA via
   `GET /repos/{owner}/{repo}/git/ref/tags/{tag}`. Follow annotated tag
   objects via `GET /repos/{owner}/{repo}/git/tags/{object_sha}` until a
   commit SHA is reached.
3. **Verify the proposed SHA is ahead of the current pinned SHA on the
   upstream default branch.** Call `GET /repos/{owner}/{repo}/compare/{old}...{new}`.
   If `status` is anything other than `ahead` (so `behind`, `diverged`, or
   `identical`), classify the proposal `unsupported` with reason
   `tag-points-not-ahead-of-current-pin` and do NOT generate a bump. This
   defeats force-pushed-tag attacks and intentional rebases.
4. Also fetch `GET /repos/{o}/{r}/commits/{new}` and capture
   `verification.verified` and `verification.reason`. Surface the GitHub
   signature-verification status in the PR body. Unverified commits still
   produce bumps but are clearly flagged.
5. Rewrite the `uses:` line with the new commit SHA. Preserve or insert the
   trailing `# v1.2.3` comment.

#### D.2. YAML-preserving rewriter

`uses:` lines live inside workflow YAML files which may have arbitrary
formatting (anchors, multi-line values, trailing comments, mixed indent).
v1 rewrites by:

1. Parsing the file into `serde_yml::Value`, locating `uses:` nodes by path.
2. Capturing each `uses:` node's `Marker` (line + column) before mutation.
3. **Mutating the byte range of the original file** (not re-serializing the
   whole YAML tree), so formatting, comments, and indentation are preserved
   exactly. Only the SHA and the inline `# vX.Y.Z` comment change.

This is the same strategy GitHub's own `actions/setup-*` migrations use when
they advise users to update workflows in place. Re-serializing destroys the
file's comments and is a non-starter.

#### D.3. SHA-pinning is non-negotiable

If forge-tinker touches a workflow file, every `uses:` reference in that file
must end up pinned to a commit SHA. References that came in as `@v3`,
`@main`, or unpinned get rewritten to the resolved SHA. This is documented
GitHub hardening guidance and aligns with the supply-chain mitigations the
Actions ecosystem already recommends.

### E. Config schema (`.forge-tinker.toml`)

```toml
[forge-tinker]
schema_version = 1

[ecosystems.cargo]
enabled = true
validate_workflows = [".github/workflows/ci.yml"]
grouping = "all-in-one"                         # | "one-per-crate" | "by-kind"

[ecosystems.github-actions]
enabled = true
validate_workflows = "auto"
grouping = "all-in-one"
allow_major = false

[pull-request]
labels = ["forge-tinker", "dependencies"]
reviewers = []
draft = false
body_template = "default"

[validation]
executor = "docker"                             # default; host-only via CLI override
on_unvalidated = "open-pr-with-warning"         # | "skip" | "fail"

[safety]
refuse_in_ci = true                             # block --apply-remote when $CI set
refuse_dirty_tree = true                        # block --apply-remote with uncommitted changes
require_force_for_overrides = true
```

Defaults if no `.forge-tinker.toml`: both ecosystems enabled, validate against
any workflow named `ci.yml`, `all-in-one`, `allow_major = false`, docker
executor, all three safety knobs on.

### F. Receipt schema — `RunStoreReceipt` envelope, tinker records inside

The tinker run produces the same envelope shape as a ci-forge run:

```text
.ci-forge/tinker-runs/<run-id>/
  run.json                        # RunStoreReceipt-shaped
  receipts/
    scanner-cargo.json
    scanner-github-actions.json
    proposer-cargo.json
    proposer-github-actions.json
    validator-<proposal-id>.json   # links to .ci-forge/runs/<ci-forge-run-id>
    applier-<proposal-id>.json
    publisher-<proposal-id>.json
  logs/
    scanner.log
    proposer.log
    publisher.log
```

`run.json`'s `provenance.records[]` carries one record per stage outcome,
keyed by tool (`forge-tinker`), surface (e.g. `scanner.cargo`), subject
(manifest path or proposal id), status (`exact`/`compatible`/`simulated`/
`stubbed`/`unsupported`), summary counts, and artifact path (the per-stage
receipt JSON).

A single tinker proposal generates roughly: `proposer` record → `validator`
record (with a nested `ci_forge_run_id` pointing to
`.ci-forge/runs/<id>/run.json`) → `applier` record → `publisher` record (if
`--apply-remote`). All records share a `proposal_id` field for cross-stage
correlation.

**Receipt-content denylist:** the receipt MUST NOT contain App private key
bytes, App ID, installation ID, JWT (in any form), installation token, raw
`Authorization` headers, ETag values that span multiple repos, or rate-limit
reset headers. An explicit `SAFE_FIELDS` allowlist in the receipt serializer
keeps drift out.

### G. Security model

#### G.1. Auth surface

- **GitHub App registration:** operator runs `forge-tinker init github-app`
  one time. The command walks them through the App settings form
  (permissions: `contents: write`, `pull_requests: write`, `metadata: read`;
  webhook off; install per-repo), then writes the private key and IDs to
  `~/.wildmason/secrets/forge-tinker.env` with mode 0600 enforced at creation.
- **Permission-scope hardening:** even with `contents: write`, forge-tinker's
  Publisher refuses to push to any ref that the proposed branch name doesn't
  match `^forge-tinker/[a-z0-9-]+/[a-z0-9-]+$`, AND refuses to push to a ref
  that `GET /repos/{o}/{r}` returns as `default_branch`, AND refuses to push
  to any branch flagged `protected: true` via
  `GET /repos/{o}/{r}/branches/{branch}`. Three independent guards, because
  Defense in Depth.
- **Token lifecycle:** installation token is acquired exactly once per scan,
  held in `OctocrabClient` heap memory, never exported to env. Git push uses
  a credential helper that reads the token from stdin (one-shot, killed after
  push). Token expiry is checked against `expires_at` from GitHub's response
  body; if `expires_at` is missing or in the past, the run aborts.
- **Key rotation:** GitHub Apps support multiple active keys for zero-downtime
  rotation. forge-tinker's auth code accepts a primary + optional fallback
  PEM. `forge-tinker init github-app --rotate` walks the operator through
  adding a new key and removing the old one.
- **JWT discipline (claims and algorithm verified against GitHub Apps docs,
  see Out-of-band References):**
  - **Algorithm:** RS256 only. Signer rejects any other `alg` value
    including `none`.
  - **Required claims:** `iat`, `exp`, `iss`, `alg`. Signer refuses to mint
    a JWT missing any of these.
  - **`iss`:** set to the GitHub App's Client ID (per current GitHub docs;
    the App's numeric ID is also accepted but Client ID is the documented
    forward path).
  - **`iat`:** set 60 seconds in the past to absorb clock drift (GitHub
    recommends this; their server-side tolerance is documented as
    "approximately 60 seconds").
  - **`exp`:** at most 540 seconds after `iat` (under GitHub's 600s hard
    cap, leaving a 60s safety margin in addition to the `iat` backdate).
  - **Expiry:** signer refuses to reuse a JWT past its `exp`.
  - Adversarial tests cover each refusal.
- **Octocrab auth pattern (verified against the Rust crate's auth module,
  see Out-of-band References):** auth uses
  `OctocrabBuilder::app(app_id, key)` to construct an App-scoped client,
  then `.installation_and_token(installation_id)` to obtain both the
  installation-scoped Octocrab and the cached installation token in a
  single call. The token sticks in heap memory inside the resulting client
  and is reused for the duration of the scan. RSA key load accepts either
  PEM (default) or DER form. The `github_app_authentication_manual.rs`
  example file in the octocrab repo is the canonical reference shape.

#### G.2. Sanitizer contract for upstream-supplied content

All strings from upstream sources (release-notes body, commit subject of new
SHA, tag name, action description) pass through `forge_tinker::sanitize`
before being interpolated into ANY of: commit message body, PR title, PR
body, log line, receipt field. The sanitizer:

- Validates against a per-field charset. Tag names must match
  `^[A-Za-z0-9._/+-]{1,255}$`; refs to remote refs must match
  `^[A-Za-z0-9._/-]+$` and not contain `..`. Anything that doesn't match is
  rejected and the proposal is marked `unsupported` with reason
  `unsafe-upstream-string`.
- Truncates release-notes bodies to 4 KB and code-fences them in the PR body
  so embedded markdown doesn't activate.
- HTML-escapes content destined for the PR body (GitHub will re-render, but
  pre-escaping defeats the worst injection vectors).
- Strips embedded CR/LF from commit subjects (CWE-93 defense).

#### G.3. Git command-injection surface

All `git` invocations use `Command::new("git").arg(...)`, never shell-string
concatenation. All ref/branch/tag names are charset-validated before
interpolation. Remote URLs are never passed through a shell. Test coverage
includes an adversarial branch name (`x; rm -rf /`) and verifies the command
runner rejects it pre-spawn rather than letting `git` see it.

#### G.4. Working-tree isolation

- Tempdir via `tempfile::TempDir::new_in("forge-tinker")` under
  `$XDG_RUNTIME_DIR` (Unix, falls back to `$TMPDIR` then `/tmp`) or
  `%LOCALAPPDATA%\Temp\forge-tinker` (Windows). Mode 0700 enforced post-create.
- Drop runs on panic via RAII. The receipt indexes the tempdir path so a
  retained run can resurrect it for debugging, but normal runs nuke the
  tempdir even on the failure paths.
- No secret-bearing file ever lands in the working clone. The credential
  helper writes nothing to disk (token via stdin).

#### G.5. Rate-limit + ETag policy

- ETag cache persists under `~/.cache/forge-tinker/etag.db` (sled-style
  key/value or just JSON). Cache hits revalidate via `If-None-Match` after
  24h regardless of TTL.
- Rate-limit exhaustion fails closed: no PRs are opened, the run records a
  `rate-limited` status with the reset timestamp, and the operator must
  retry.
- The remaining-quota header is logged at the end of every run.

#### G.6. `--apply-remote` defensive checks

Refuses to run when any of: `$CI` set, `$GITHUB_ACTIONS` set, working tree
has uncommitted changes (per `git status --porcelain`), repo is on a
detached HEAD, or repo has unpushed commits ahead of upstream that conflict
with the proposed branch name. Each refusal is overridable only with
`--force`, and `--force` itself is logged as a top-level provenance record
on the receipt.

### H. Implementation sequence

1. **Crate skeleton + CLI shape** (`forge-tinker scan --help` parses).
2. **Library API extraction:** `forge_core::validation::run_workflow_for_validation`
   refactored out of `crates/forge-cli/src/run_orchestrator.rs`. Existing
   `forge run` CLI still passes through. Full test suite still green.
3. **`DependencyEcosystem` trait + skeletons** for Cargo and GHA.
4. **Cargo Proposer** with parser + lockfile-diff cross-check.
5. **GHA Proposer** with tag resolution, ancestor check, signature lookup.
6. **Receipt writer** using the `RunStoreReceipt` envelope.
7. **Validator** wiring (calls the library API from step 2).
8. **Applier** + YAML-preserving rewriter.
9. **GitHub App auth** + redactor wiring + adversarial JWT tests.
10. **Sanitizer module** + tests for each per-field charset.
11. **Publisher** module + git command-injection tests + the three
    push-target guards.
12. **`.forge-tinker.toml` parser + schema_version=1.**
13. **Integration tests** against fixture repos in `fixtures/synthetic/`.
14. **Dogfood:** scan ci-forge (`--apply-local`), then Mortar
    (`--apply-local`), then ci-forge (`--apply-remote` against an operator-
    approved App installation).

## Risks & Open Questions

- **R1 — Build-script execution attack surface.** Defended in §B step 4 by
  defaulting validation to Docker for both ecosystems. Host validation is
  gated behind `--unsafe-host-validation`. Per-ecosystem image isolation
  (the Dependabot Core model) is deferred to the npm/pip phase where it
  becomes load-bearing.

- **R2 — git2 vs shell-out (CLOSED).** Decision: shell-out via
  `Command::new("git").arg(...)`. git2 (libgit2) adds a C dep, complicates
  cross-compile, and is one more CVE surface for marginal gain. Shell-out
  matches ci-forge's existing pattern (every `actions/checkout` shells out).
  Command-injection defense lives in §G.3.

- **R3 — GitHub App approval friction.** Mitigated by `forge-tinker init
  github-app` (one-time guided setup). Operators with no prior App
  experience can complete setup in <10 minutes.

- **R4 — Validation false negatives.** A `forge run` failure today blocks the
  PR. v1 keeps this behavior (fail-closed is the safe default). A future
  `--validation-retries N` knob is acknowledged but explicitly out of scope
  for v1.

- **R5 — Concurrent PR collisions.** Deterministic branch names mean a
  second concurrent run hits the same branch name and aborts cleanly. v2
  will add supersede-and-close.

- **R6 — Rate limiting.** §G.5 covers this. Fail-closed on exhaustion.

- **R7 — Major-version bumps.** `allow_major = false` by default. The line
  between SemVer-compatible and actually-builds is exactly what validation
  is for. We let cargo's resolver decide what's compatible, then trust the
  workflow run to catch the rest.

- **R8 — Setup-actions changing toolchain versions silently.** Bumps to
  `actions/setup-node@v4 → v5` may change the default Node major. v1 surfaces
  this in the PR body as a `compatible` (not `exact`) classification, and the
  ci-forge run receipt embedded in the PR body shows the actual node version
  used. The reviewer (human) decides.

- **R9 — Codeberg / Forgejo / Gitea.** Deferred. v1 has zero abstraction
  here — one `github_pr_backend.rs` module. The `PullRequestBackend` trait
  arrives when the second backend lands.

- **R10 — Local-green ≠ hosted-green.** Real concern. The PR body explicitly
  surfaces every `simulated`/`stubbed` classification from the ci-forge run
  receipt so reviewers can see what wasn't actually exercised locally.

- **R11 — `cargo update` stdout drift.** Parser cross-checks against lockfile
  diff at every run. Divergence aborts loudly.

- **R12 — Forge App key compromise.** Documented kill-switch: operator
  rotates via `forge-tinker init github-app --rotate`, then deletes the old
  key in the GitHub App settings. The compromised key can no longer mint
  installation tokens.

- **OPEN: where exactly does the validation library API live?** §A.3 puts it
  in `crates/forge-core`. There's a case for a new `crates/forge-validation`
  crate to keep core's dependency surface minimal. Resolve during step 2 of
  §H based on what dependencies the extraction actually drags in. **Not a
  v1 blocker** — interface stays the same either way.

- **EVOLUTION: ecosystem trait granularity.** v1 uses a single
  `DependencyEcosystem` trait with five methods. Dependabot Core uses a more
  granular split (FileFetcher, FileParser, UpdateChecker, FileUpdater,
  MetadataFinder, Version/Requirement). The collapsed shape is fine for
  v1's two ecosystems; if v2/v3 adds 3+ more ecosystems and the trait gets
  unwieldy, the documented refactor path is the Dependabot-style split.
  Not a v1 blocker, just an evolution cue.

- **EVOLUTION: multi-backend PR support.** Dependabot Core supports GitHub
  Enterprise, GitLab, Azure DevOps, BitBucket, and AWS CodeCommit from day
  one — they had cross-forge users from the start. ci-forge's audience is
  GitHub-first (per Principle 1, observable GitHub Actions parity), so the
  `PullRequestBackend` trait deferral is right-sized. When/if a Wildmason
  product moves to Forgejo/Codeberg, the second backend triggers the trait.

- **OPEN: dogfood includes Mortar from day one?** §H step 14 includes it.
  Mortar's workflows are more complex than ci-forge's own — could be a
  better signal-to-noise scan target, but might also surface validation
  gaps that v1 isn't ready to address. Operator's call when we get there.

## Test Strategy

- **Unit tests (TDD per CLAUDE.md):**
  - Cargo `cargo update --dry-run` stdout parser, against locked fixture
    outputs. Cross-check: parser output must match the lockfile diff in the
    same fixture.
  - GHA `uses:` rewriter, against fixture YAML files covering:
    multi-line `uses:`, quoted refs, trailing inline comments, composite
    actions, composite-inside-composite, anchors/aliases.
  - `.forge-tinker.toml` parser including schema_version validation and
    rejection of unknown top-level keys.
  - GitHub App JWT signer **adversarial cases** (not tautological):
    - Reject `alg: none` even if signature verifies.
    - Reject any `alg` other than `RS256` (GitHub Apps mandates RS256).
    - Reject JWT missing any of the required claims (`iat`, `exp`, `iss`,
      `alg`).
    - Reject JWT with TTL > 540s (under GitHub's 600s cap).
    - Reject JWT whose `iat` is in the future (clock-skew misconfiguration
      defense).
    - Reject expired JWT (`exp` in the past).
    - Refuse to accept installation-token response without `expires_at`.
    - Refuse to accept installation-token with past `expires_at`.
    - Refuse to load a key file whose mode is group/world-readable.
  - Branch name generator (deterministic + injective):
    - Same input → same branch name (deterministic).
    - Two semantically-different inputs → different branch names (injective
      on the relevant equivalence class).
  - Sanitizer per-field charset rejections, with adversarial inputs
    (newline-injected commit subjects, CRLF injection, `<img onerror>`,
    `javascript:` URLs, malformed unicode).
  - Branch-target push guard: an attempted push to `default_branch` or a
    `protected: true` branch is rejected before the git invocation runs.
  - Git command-injection: branch name `x; rm -rf /` is rejected pre-spawn.
  - Redactor: registers a known token value, runs a log line containing it,
    asserts the value is replaced; runs a log line containing a *new*
    `ghs_...` token shape, asserts the regex pre-filter catches it even
    without registration.
  - `git clone --local --no-hardlinks` is chosen over `--shared`; the choice
    is tested by inspecting the clone's `.git/objects/info/alternates`
    (should not exist).
  - Tempdir mode is 0700 on Unix post-create; an OS that returns a more
    permissive default fails the run.

- **Integration tests:**
  - Cargo end-to-end against `fixtures/synthetic/forge-tinker-cargo/`:
    manifest with one outdated dep, one-job workflow `cargo check`, validate
    bump succeeds and receipt has expected provenance shape.
  - GHA end-to-end against `fixtures/synthetic/forge-tinker-actions/`:
    workflow pinned to old SHA, validate the rewriter pins to the new SHA
    AND that the new SHA passes the compare-ahead check.
  - Tag-move attack: fixture upstream tag that was force-pushed (simulated
    via a fixture HTTP mock). compare returns `behind`. Validator rejects
    with `tag-points-not-ahead-of-current-pin`. PR NOT opened.
  - `--dry-run` writes a receipt but no working-tree changes and no HTTP
    write calls.
  - `--apply-local` writes to a retained isolated worktree under
    `.ci-forge/tinker-runs/<id>/work/` but no HTTP write calls.
  - `--apply-remote` against a mock Octocrab: request payloads are exactly
    what we'd send (verified against a recorded golden).
  - Safety check: `--apply-remote` with `$CI=1` exits non-zero before any
    HTTP call.

- **No tautological tests:** every assertion exercises real logic. Removing
  the test would leave a real correctness gap.

- **Dogfood (in §H step 14):**
  - scan ci-forge with `--apply-local`, manually inspect diff + receipt.
  - scan Mortar with `--apply-local`.
  - scan ci-forge with `--apply-remote` against an operator-approved App.

## Acceptance Criteria

- [ ] `forge_core::validation::run_workflow_for_validation` exists, has a
      stable struct interface, and is consumed by both the `forge run` CLI
      and by `forge-tinker`. ci-forge's existing 244 forge-cli tests / 366
      workspace tests still pass after extraction.
- [ ] `forge-tinker scan <ci-forge-repo>` (dry-run) produces
      `.ci-forge/tinker-runs/<id>/run.json` with the `RunStoreReceipt`
      envelope; `provenance.records[]` contains scanner/proposer/validator
      entries with the v1 classification vocabulary.
- [ ] Every proposed bump has a corresponding validator record whose
      `ci_forge_run_id` resolves to a `.ci-forge/runs/<id>/` directory, OR
      is classified `unvalidated` with a documented reason.
- [ ] Validation runs inside Docker by default; host-mode validation
      requires `--unsafe-host-validation`.
- [ ] `forge-tinker scan --apply-local` produces a retained isolated worktree
      diff that passes `cargo check` (Cargo) or `forge mirror-actions --repo
      <worktree>` followed by a re-resolved-SHA check (GHA), against the
      fixture repos.
- [ ] `forge-tinker scan --apply-remote`:
      - against a mock backend, opens PR(s) whose bodies render the receipt
        summary, the ci-forge validator run id(s), the explicit
        compatibility classifications, and the GitHub signature-verification
        status of the new SHA.
      - is refused when `$CI` is set, when the tree is dirty, or when the
        push target is the default/protected branch — each refusal logged
        as a provenance record.
- [ ] Tag-to-SHA resolution rejects new SHAs that aren't strictly ahead of
      the current pin on the upstream default branch (`compare` status
      != `ahead`).
- [ ] All upstream-supplied strings (release notes, tag names, commit
      subjects) pass through the sanitizer before being embedded in commits,
      PR body, log lines, or receipt fields.
- [ ] GitHub App installation token is acquired exactly once per scan, never
      logged, never exported to env. The redactor catches `ghs_...` /
      `ghu_...` / `Bearer ...` token shapes even if not pre-registered.
- [ ] Secrets file mode is 0600 enforced on creation (Unix); private-key
      load refuses group/world-readable files.
- [ ] `.forge-tinker.toml schema_version = 1` parses; other values are
      rejected with a migration-pointer error.
- [ ] Unit tests cover all parsers, the JWT adversarial cases, the
      branch-name generator, the sanitizer, the redactor, and the push-target
      guard. Integration tests cover dry-run, apply-local, apply-remote, and
      the tag-move attack. All tests pass; clippy + fmt clean.
- [ ] `cargo run -p forge-tinker -- scan --help` displays the v1 CLI surface.
- [ ] Receipt schema is symmetric enough with `.ci-forge/runs/` that a single
      `RunStoreReceipt` index loader can read both stores.

## Out-of-band References

- ci-forge `docs/guiding-principles.md` (Principles 5, 6, 11, 13).
- ci-forge `docs/runner-parity-roadmap.md:147-161` for compatibility
  classification vocabulary.
- ci-forge `docs/architecture.md:260-267` for the `RunStoreReceipt`
  envelope and provenance index shape.
- ci-forge `crates/forge-cli/src/github.rs:559-571, 1671-1818` for the
  existing redaction model.
- ci-forge `crates/forge-cli/src/cli.rs:351-470` for the current `RunArgs`
  surface that the validation library API replaces.
- ci-forge `crates/forge-cli/src/run_orchestrator.rs` for the orchestrator
  extraction site.
- ci-forge `README.md:154-156` for `forge mirror-actions` resolution.
- `~/.claude/CLAUDE.md` "Mandatory Testing", "TDD for Logic, Test-After for
  UI", "No Tautological Tests", "No Amending Commits Without Permission".
- Dependabot Core source: https://github.com/dependabot/dependabot-core
  (verified Phase 4 research). Key findings: per-ecosystem Docker images
  documented; updater interface is the 6-class split (FileFetcher,
  FileParser, UpdateChecker, FileUpdater, MetadataFinder, Version /
  Requirement); validation is manifest-resolution only — Dependabot does
  NOT run host CI against bumps; supports GitHub Enterprise, GitLab, Azure
  DevOps, BitBucket, AWS CodeCommit out of the box.
- GitHub Apps JWT requirements (official docs, verified Phase 4):
  https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app
  — RS256 mandatory; max TTL 600s; required claims `iat`, `exp`, `iss`,
  `alg`; `iat` should be set 60s in past for clock-skew tolerance.
- Octocrab Rust client (verified Phase 4):
  https://github.com/XAMPPRocky/octocrab — `OctocrabBuilder::app` for App
  auth, `installation_and_token()` for installation-scoped client + cached
  token, PEM/DER key formats supported. Canonical reference:
  https://github.com/XAMPPRocky/octocrab/blob/main/examples/github_app_authentication_manual.rs
- Octocrab auth module source:
  https://github.com/XAMPPRocky/octocrab/blob/main/src/auth.rs

## Review Pass 1

- **Reviewers:** Security Engineer, Architecture Reviewer.
- **Verdicts:** Security → `needs-revision`; Architecture → `needs-revision`.
- **Outcome:** all findings either accepted (with plan updates) or addressed
  with explicit rationale. Findings table below.

### Security findings — verdicts and disposition

| # | Finding | Verdict | Disposition |
|---|---|---|---|
| S1 | `cargo update` triggers `build.rs` in untrusted graph (CWE-829). Host validation default unsafe. | ✅ ACCEPTED | §B step 4 + §H new step: Docker is the default validator executor for both ecosystems. Host execution gated behind `--unsafe-host-validation`. |
| S2 | "Reuse ci-forge redaction" claim doesn't match value-registry-only code at github.rs:1671-1818, 559-571. | ✅ ACCEPTED | Current State section now honestly maps the model: value-registry + new regex pre-filter for `ghs_/ghu_/Bearer` shapes. App key + IDs + minted tokens are registered before any logging. |
| S3 | "Scrubbed from env" implies env-passing which is wrong; Octocrab takes tokens in heap. | ✅ ACCEPTED | §G.1 rewritten: tokens never exported to env; git push uses one-shot stdin credential helper. |
| S4 | Tag→SHA rewrite vulnerable to force-pushed tag / downgrade. | ✅ ACCEPTED | §D.1 step 3: `compare` API check; reject any non-`ahead` status. §D.1 step 4: surface `verification.verified` in PR body. |
| S5 | PR body / commit injection from upstream metadata. | ✅ ACCEPTED | §G.2 sanitizer contract added; charset validation, code-fencing, HTML-escaping, CRLF stripping. |
| S6 | Shell-out command injection on refs/branches/tags. | ✅ ACCEPTED | §G.3 explicit: `Command::new("git").arg(...)` only; charset validation pre-spawn; adversarial unit test. |
| S7 | Tempdir hygiene unspecified. | ✅ ACCEPTED | §G.4 added; `tempfile::TempDir`, 0700 mode enforced post-create, RAII cleanup, no secret-bearing files inside. |
| S8 | Receipt content may encode App ID / installation ID / ETag. | ✅ ACCEPTED | §F denylist + allowlist documented. |
| S9 | `contents: write` scope is broad; need push-target guard. | ✅ ACCEPTED | §G.1 three independent push-target guards (branch-name regex + default_branch check + protected check). Scope kept at `contents: write` (Forge App API doesn't expose a narrower scope for branch-push), but enforcement is in code. |
| S10 | ETag fail-mode ambiguous. | ✅ ACCEPTED | §G.5: ETag is speed not truth; force revalidate after 24h; rate-limit exhaustion fails closed. |
| S11 | No JWT key rotation story; secrets-file mode not enforced. | ✅ ACCEPTED | §G.1 rotation story added; mode 0600 enforced at `init github-app` creation; load refuses group/world-readable. |
| S12 | JWT test "sign with K verify with K" is tautological. | ✅ ACCEPTED | Test Strategy rewritten to adversarial cases (alg=none rejection, TTL > 540s rejection, expired rejection, missing/past `expires_at` rejection, bad-mode-file rejection). |
| S13 | `--apply-remote` needs defensive checks for `$CI` and dirty tree. | ✅ ACCEPTED | §G.6 added; `[safety]` config block added; `--force` override logged as provenance. |
| S14 | `git clone --shared` semantics fragile. | ✅ ACCEPTED | §C step 2: switched to `--local --no-hardlinks`. Test asserts no `alternates` pointer. |
| S15 (strength) | App-only auth, no PATs, no webhook. | 🟢 KEPT | §G.1 explicitly retains. |
| S16 (strength) | SHA-pinning enforcement on `uses:`. | 🟢 KEPT | §D.3 explicit, marked default-not-flag. |
| S17 (strength) | Validation-before-PR loop. | 🟢 KEPT | §B step 4 preserves. |

### Architecture findings — verdicts and disposition

| # | Finding | Verdict | Disposition |
|---|---|---|---|
| A1 | Subprocess to `forge run` is fragile; 30+ flags glossed as a one-liner. | ✅ ACCEPTED | §A.3 introduces `forge_core::validation::run_workflow_for_validation` library API. §H step 2 extracts it from the existing orchestrator. Acceptance criterion added. |
| A2 | Receipt "mirroring" claim is visual sympathy not real reuse. | ✅ ACCEPTED | §F rewritten around the actual `RunStoreReceipt` envelope with tinker records in `provenance.records[]`. Acceptance criterion now verifies the shared index loader. |
| A3 | `PullRequestBackend` trait introduced too early (single-impl trait). | ✅ ACCEPTED | §A.5 + R9: no trait in v1; single module `github_pr_backend.rs`; trait introduced when second backend lands. |
| A4 | Ecosystem extensibility has no trait; v2 will rip the v1 path open. | ✅ ACCEPTED | §A.4 introduces `DependencyEcosystem` trait with both Cargo and GHA as real v1 impls. |
| A5 | God-orchestrator risk in §B. | ✅ ACCEPTED | §A.2 + §B pipeline split into Scanner/Proposer/Validator/Applier/Publisher/Receiptor with per-stage receipts. |
| A6 | Sibling-binary defense is one-sided; missing counter-arguments. | ✅ ACCEPTED | §A.1 rewritten to weigh both sides; decision still stands but rationale is now load-bearing on security-surface, not just principles. |
| A7 (nit) | R2 left open while §H committed to shell-out. | ✅ ACCEPTED | R2 closed; decision documented. |
| A8 (nit) | AC used `forge plan` as compile-check primitive for Actions, wrong tool. | ✅ ACCEPTED | AC now uses `forge mirror-actions` + re-resolved-SHA check. |
| A9 (strength) | R10 names local-green ≠ hosted-green honestly. | 🟢 KEPT | Preserved verbatim. |
| A10 (strength) | Branch-name determinism right v1 move. | 🟢 KEPT | Preserved + unit test framing. |
| A11 (strength) | Refusing unpinned `uses:` correct posture. | 🟢 KEPT | §D.3 marks it default-not-flag. |
| A12 (speculative) | 4th workspace crate may slow build. | ⚪ NOTED, NOT CHANGED | Modern cargo handles 4 crates trivially; if profiling later shows otherwise, the validation crate (§R-OPEN) is the place to split. |
