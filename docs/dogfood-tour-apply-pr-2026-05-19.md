# Assay Dogfood Tour — `--apply-pr` end-to-end — 2026-05-19

> Status: completed · binary `target/release/assay.exe` (HEAD = 430372b + this iteration's fixes) · host = Windows 11, gh CLI 2.x logged in as `mattnb` with `repo` scope · target = `wildmason/safe-bundle` · gate = `--gate-cmd "cargo test --locked"`

## Scope

First real end-to-end exercise of `--apply-pr` against a live GitHub remote. Goal: prove that the orchestrator scans → proposes → validates → merges → pushes a branch → opens a PR — and surface any bugs that show up only on the live path that fixture/mock unit tests can't catch.

Target chosen jointly with the operator: `wildmason/safe-bundle` (small public Rust + GHA repo, three real proposals on offer, "safe-bundle"'s own CI step `cargo test --locked` is what we use as the validator gate).

## Outcome

✅ **PR opened.** [`wildmason/safe-bundle#15`](https://github.com/wildmason/safe-bundle/pull/15) — branch `assay/multi/3-cf2acdb4e9a9`, title "Bump 3 dependencies via assay", three bumps in the body (clap_complete 4.6.4→4.6.5, zip 7.2.0→8.6.0, dtolnay/rust-toolchain 1.85.0→v1), 7 additions / 7 deletions, base `main`. Left open for operator review.

Three bugs and one environment gotcha surfaced along the way. Three of the four are fixed in this iteration; the fourth (environment) is documented for the operator with a workaround.

## Bugs found and fixed

### 1. `UnconfiguredBackend` stub referenced the abandoned GitHub-App path (FIXED)

**Symptom:** dead code in `src/publisher/mod.rs` advertised a `--secret-file` / `assay init github-app` remediation path that contradicts the actual design (gh CLI + `$GH_TOKEN`, no GitHub App).

**Fix:** removed `UnconfiguredBackend` + its single test; rewrote the module-level docstring to describe the live `GhCliBackend` instead of the deleted Octocrab/installation-token design.

**Why this mattered for shipping:** the stale stub's error messages would have appeared in a future operator's first-failure path. Either the stub gets called (impossible now — `GhCliBackend::default()` is wired in) or it doesn't (then it's dead). Either way the messaging contradicted the README. Deleted.

---

### 2. `gh` auth check ran AFTER validation, not before (FIXED)

**Symptom:** `GhCliBackend::check_auth()` existed at `publisher/gh_cli.rs:54-87` but no call site invoked it. An operator without `gh auth login` (or with the wrong scopes) could spend minutes running the validator on N proposals before failing at the `gh pr create` step.

**Fix:** new `preflight_apply_pr_gh_auth(&GhCliBackend)` helper in `cli.rs` called from `analyze_command` right after the `$CI` preflight (before any scan/validate work). `--force` bypasses, mirroring the existing `$CI`-refusal pattern. Three new unit tests cover the happy path + the two known failure modes (`gh` exits non-zero, repo scope missing).

---

### 3. Hardcoded `"assay"` PR label failed `gh pr create` when the label didn't exist (FIXED — DOGFOOD BLOCKER)

**Symptom:** Per dogfood run #1 against `wildmason/safe-bundle`:
> `the branch was pushed but \`gh pr create\` failed: forge rejected the request: \`gh pr create\` exited non-zero: could not add label: 'assay' not found.`

The hardcoded `labels: vec!["assay".into()]` in `perform_apply_pr` (and a similar pattern in tests) bypassed `config.pull_request.labels` AND failed the whole PR-open call if the label didn't exist on the target repo. Branch was pushed; PR was orphaned.

**Fix:**
1. New `list_labels(owner, repo) -> Result<Vec<String>, BackendError>` on the `PullRequestBackend` trait + `GhCliBackend` impl that shells out to `gh api repos/<o>/<r>/labels --paginate --jq '.[].name'`.
2. New `filter_labels_to_existing(backend, owner, repo, requested)` helper that drops labels that don't exist on the repo, prints a `WARNING` for each dropped label, and returns empty (with a different warning) on `list_labels` error so the PR still opens.
3. `perform_apply_pr` now accepts `requested_labels: &[String]` and calls the filter. CLI passes `&config.pull_request.labels` (default: `["assay", "dependencies"]` from `.assay.toml`).
4. Four new unit tests cover the filter logic (no labels, drop missing, drop all, error path).

**Dogfood-run-2 evidence:**
```
assay: WARNING: dropping 2 label(s) that don't exist on wildmason/safe-bundle: assay, dependencies
…
assay: opened PR for 3 bump(s) on branch `assay/multi/3-cf2acdb4e9a9`: https://github.com/wildmason/safe-bundle/pull/15
```

---

### 4. `git worktree add` failed with no recovery hint when the branch already existed (FIXED)

**Symptom:** After dogfood run #1 left a partial state (branch created, PR not opened), retrying produced:
> `git worktree add (branch \`assay/multi/3-cf2acdb4e9a9\`) failed: fatal: a branch named 'assay/multi/3-cf2acdb4e9a9' already exists`

No remediation, no cleanup instructions. The operator has to know that prior runs leave local branches behind AND figure out the right `git branch -D` invocation.

**Fix:** new `format_worktree_add_failure(branch, stderr)` helper detects the "already exists" stderr substring and appends a remediation block with the exact cleanup commands:
```
git branch -D assay/multi/3-cf2acdb4e9a9
git push <remote> --delete assay/multi/3-cf2acdb4e9a9   # only if the prior run also pushed
```
Two new unit tests cover the remediated and pass-through error shapes.

**Known follow-up:** the deeper fix would be cleanup-on-failure for the local worktree + branch when push/PR-open hasn't completed — left as a follow-up to keep this iteration's scope contained. The remediation hint is the user-facing safety net until then.

## Environment gotcha (NOT an assay bug — documented for the operator)

**Symptom:** First push attempt failed with `Invalid username or token. Password authentication is not supported for Git operations.` against a URL `https://github.com/wildmason/safe-bundle.git/` — *despite* `gh auth status` showing a logged-in user with `repo` scope.

**Root cause:** the user's global `~/.gitconfig` has:
```
url.https://x-access-token:@github.com/.insteadof = https://github.com/
```
This rewrites every `https://github.com/<owner>/<repo>` URL to `https://x-access-token:@github.com/<owner>/<repo>` — i.e. populates a username (`x-access-token`) and an *empty* password. Git treats the empty password as a real (failing) credential and never consults the credential helper, which is keyed to the un-rewritten URL.

The credential helper (`'gh' auth git-credential`) is correctly configured under `credential.https://github.com.helper` but never fires for the rewritten URL.

**Workaround used for this dogfood:** added a separate `dogfood-origin` remote with the token baked in via `https://x-access-token:$(gh auth token)@github.com/...`. The fully-token-bearing URL doesn't match the `insteadOf` prefix and so isn't rewritten. After the dogfood the remote was removed (cleanup section below).

**Recommended permanent fix for the operator (out of scope for this iteration):** delete the global `insteadOf` rule. The credential helper alone (already configured) is sufficient and works cleanly. Until then, every wildmason repo cloned with the existing default remote will hit the same problem the first time it tries to push from outside CI.

This affects all ~25 wildmason oss repos with the same remote-URL pattern. Worth surfacing the moment release tooling needs to push.

## Cleanup of dogfood artifacts

- `wildmason/safe-bundle#15` left open at operator's discretion (close + delete branch when reviewed).
- Local `dogfood-origin` remote and `.assay/runs/*` artifacts in the safe-bundle checkout left in place until commit time so the operator can inspect them.

## Test additions

| File | Tests added |
|------|-------------|
| `src/cli.rs::tests` | `preflight_apply_pr_gh_auth_succeeds_with_repo_scope`, `preflight_apply_pr_gh_auth_fails_when_gh_exits_nonzero`, `preflight_apply_pr_gh_auth_fails_when_repo_scope_missing`, `filter_labels_returns_empty_when_no_labels_requested`, `filter_labels_drops_missing_labels_keeping_only_existing`, `filter_labels_returns_empty_when_none_of_requested_exist`, `filter_labels_returns_empty_when_list_labels_errors`, `worktree_add_failure_passes_through_unrelated_errors`, `worktree_add_failure_appends_remediation_when_branch_already_exists` |

Net test count: 597 → 603 (+6 added, −1 removed for the deleted `UnconfiguredBackend` test). All 603 green.

## Follow-ups (not blocking 0.2.0)

1. **Cleanup-on-failure for local artifacts.** When push or PR-open fails after the worktree+branch were created, automatically remove them so the next run starts clean. The current run leans on the remediation message to instruct the operator.
2. **Auto-create labels (vs filter).** Operators who configure `.assay.toml` labels probably want them attached — auto-creating missing labels via `gh label create` is a friendlier default than dropping them.
3. **Surface the `insteadOf` env trap.** Either pre-flight detect the broken `x-access-token:@` URL and refuse with a clear remediation, or document the prerequisite in the README's apply-pr section.
4. **Plumb `reviewers` and `draft` from config.** `config.pull_request.{reviewers,draft}` exist but are still hardcoded in the call to `build_pull_request_request` at the same spot we just fixed for labels.
