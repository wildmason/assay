//! `--apply-pr` post-validation publish phase.
//!
//! Drives the branch → worktree → merge-apply → copy_back → commit
//! → push → open-PR pipeline once every proposal has been validated.
//! The flow is built around a [`PartialApplyState`] RAII guard so a
//! mid-flight failure can't leave a half-staged worktree or branch
//! behind — every early `?` return cleans up local state, and only the
//! happy path at the bottom of [`perform_apply_pr`] dismisses the
//! guard.
//!
//! Several helpers (`ensure_labels_exist`, `filter_reviewers_to_collaborators`,
//! preflight checks) treat their slice of work as "best-effort polish":
//! the PR is the load-bearing artifact, so failures around labels /
//! reviewers / `insteadOf` rewrites drop the offending input and warn
//! rather than aborting the publish.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::ecosystem::DependencyEcosystem;
use crate::error::{Error, Result};
use crate::model::{Classification, Proposal, Provenance, ProvenanceRecord};
use crate::publisher::gh_cli::{GhCliBackend, parse_owner_repo_from_origin};
use crate::publisher::{
    PullRequestBackend, PullRequestParams, build_pull_request_request, guards::guard_push_target,
};
use crate::sanitize::sanitize_commit_subject;
use crate::validator::Validator;

use super::apply_local::{build_commit_body, build_ship_plan_from_runs};
use super::git_ops::{emit_gitignored_skip_warning, git_add_paths, git_commit, git_top_level};
use super::paths::relative_prefix;
use super::run_state::{ApplyPrSummary, MergedDropInfo, ProposalRun};

/// Compute a deterministic branch name covering every shipped proposal.
///
/// Single-bump → `branch_name_for_bump(eco, subject, from, to)`.
/// Multi-bump → `assay/multi/<N>-<short-hash-of-all-ids>` so the name
/// remains injective on the set of proposals AND stable across re-runs.
pub(super) fn compute_branch_name_for_runs(runs: &[&ProposalRun]) -> String {
    if runs.len() == 1 {
        let p = &runs[0].proposal;
        return crate::publisher::branch_name::branch_name_for_bump(
            &p.ecosystem,
            &p.subject,
            &p.from,
            &p.to,
        );
    }
    let mut hasher = Sha256::new();
    hasher.update(b"assay:multi:v1:");
    for run in runs {
        hasher.update(run.proposal.id.as_bytes());
        hasher.update(b"|");
    }
    let digest = hasher.finalize();
    let hex_short: String = digest[..6].iter().map(|b| format!("{b:02x}")).collect();
    format!("assay/multi/{}-{hex_short}", runs.len())
}

/// Best-effort cleanup of local `--apply-pr` artifacts (worktree +
/// branch) after a partial run. Pure function over side-effects so it
/// can be tested directly against a temp git fixture.
///
/// REMOTE state (a pushed branch) is intentionally NOT cleaned up:
/// when push succeeds but PR-open fails, the operator may want to
/// manually open the PR from the pushed branch, so we leave that for
/// them to decide.
pub(super) fn cleanup_local_apply_state(
    git_root: &Path,
    worktree: Option<&Path>,
    local_branch: Option<&str>,
) {
    if let Some(wt) = worktree {
        let _ = std::process::Command::new("git")
            .arg("worktree")
            .arg("remove")
            .arg("--force")
            .arg(wt)
            .current_dir(git_root)
            .output();
    }
    if let Some(branch) = local_branch {
        let _ = std::process::Command::new("git")
            .arg("branch")
            .arg("-D")
            .arg(branch)
            .current_dir(git_root)
            .output();
    }
}

/// RAII guard that calls [`cleanup_local_apply_state`] on Drop unless
/// [`PartialApplyState::dismiss`] was called first. Used by
/// `perform_apply_pr` to make sure a worktree+branch created mid-run
/// doesn't survive a panic or early `?` return — that leftover branch
/// is the "branch already exists" footgun every retry stumbled over
/// before this guard existed.
pub(super) struct PartialApplyState {
    git_root: PathBuf,
    worktree: Option<PathBuf>,
    local_branch: Option<String>,
    /// When true, Drop is a no-op (worktree+branch preserved as the
    /// audit trail for a successful Published run).
    success: bool,
    /// When false, Drop still cleans up but suppresses the "cleaned up
    /// partial state" warning — used for expected no-op early-returns
    /// like `NothingToPublish` where the cleanup isn't error recovery.
    noisy: bool,
}

impl PartialApplyState {
    pub(super) fn new(git_root: PathBuf) -> Self {
        Self {
            git_root,
            worktree: None,
            local_branch: None,
            success: false,
            noisy: true,
        }
    }

    pub(super) fn track_local(&mut self, worktree: PathBuf, branch: String) {
        self.worktree = Some(worktree);
        self.local_branch = Some(branch);
    }

    /// Mark the operation successful so Drop becomes a no-op and the
    /// worktree + local branch are preserved as the run's audit trail.
    pub(super) fn dismiss(mut self) {
        self.success = true;
    }

    /// Allow Drop to clean up the local state but suppress the
    /// early-exit warning. Used when the run exited for an expected
    /// non-error reason (e.g. `NothingToPublish` post copy-back).
    pub(super) fn dismiss_quietly(mut self) {
        self.noisy = false;
    }
}

impl Drop for PartialApplyState {
    fn drop(&mut self) {
        if self.success {
            return;
        }
        let had_local = self.worktree.is_some() || self.local_branch.is_some();
        cleanup_local_apply_state(
            &self.git_root,
            self.worktree.as_deref(),
            self.local_branch.as_deref(),
        );
        if self.noisy && had_local {
            eprintln!(
                "assay: cleaned up partial --apply-pr state (worktree + local branch) after early-exit; \
                 any pushed remote branch was left alone for manual recovery."
            );
        }
    }
}

/// Filter the operator's requested reviewers down to ones the
/// publisher will let through to `gh pr create --reviewer ...`.
///
/// Team-level reviewers (the `org/team` form) bypass the collaborator
/// filter — GitHub exposes them via a different endpoint and the
/// assignability semantics differ. User-level reviewers (bare
/// usernames) must appear in `backend.list_collaborators` or `gh pr
/// create` will fail the whole PR-open call.
///
/// On `list_collaborators` error the publisher drops all user-level
/// reviewers (parallel to the label-filter fallback) — the PR is the
/// load-bearing artifact, reviewer assignment is convenience.
pub(super) fn filter_reviewers_to_collaborators(
    backend: &dyn PullRequestBackend,
    owner: &str,
    repo: &str,
    requested: &[String],
) -> Vec<String> {
    if requested.is_empty() {
        return Vec::new();
    }
    let mut teams: Vec<&str> = Vec::new();
    let mut users: Vec<&str> = Vec::new();
    for name in requested {
        if name.contains('/') {
            teams.push(name.as_str());
        } else {
            users.push(name.as_str());
        }
    }
    if users.is_empty() {
        return teams.into_iter().map(str::to_string).collect();
    }
    let collaborators = match backend.list_collaborators(owner, repo) {
        Ok(set) => set,
        Err(err) => {
            eprintln!(
                "assay: WARNING: couldn't list collaborators on {owner}/{repo} ({err}); \
                 opening the PR without user-level reviewers (team reviewers, if any, are still attached)"
            );
            return teams.into_iter().map(str::to_string).collect();
        }
    };
    let collaborator_set: std::collections::HashSet<&str> =
        collaborators.iter().map(String::as_str).collect();
    let mut keep_users: Vec<&str> = Vec::new();
    let mut drop_users: Vec<&str> = Vec::new();
    for user in users {
        if collaborator_set.contains(user) {
            keep_users.push(user);
        } else {
            drop_users.push(user);
        }
    }
    if !drop_users.is_empty() {
        eprintln!(
            "assay: WARNING: dropping {} reviewer(s) who aren't collaborators on {owner}/{repo}: {}",
            drop_users.len(),
            drop_users.join(", ")
        );
    }
    teams
        .into_iter()
        .chain(keep_users)
        .map(str::to_string)
        .collect()
}

/// Format the error message for a failed `git worktree add` during
/// --apply-pr. When stderr suggests the branch already exists (the
/// common case when a prior run failed before PR open), append a
/// remediation hint listing the exact cleanup commands.
pub(super) fn format_worktree_add_failure(branch: &str, stderr_trimmed: &str) -> String {
    if stderr_trimmed.contains("already exists") {
        return format!(
            "git worktree add (branch `{branch}`) failed: {stderr_trimmed}\n\n\
             A prior --apply-pr run likely created this branch and exited before opening the PR. \
             To retry, delete the branch first:\n  \
             git branch -D {branch}\n  \
             git push <remote> --delete {branch}   # only if the prior run also pushed"
        );
    }
    format!("git worktree add (branch `{branch}`) failed: {stderr_trimmed}")
}

/// Ensure every label in `requested` exists on the target repo, then
/// return the subset of names safe to pass to `gh pr create --label`.
///
/// Behavior:
/// 1. Look up the existing label set via `backend.list_labels`. On
///    error, drop ALL labels and warn — the PR is the load-bearing
///    artifact, labels are categorisation polish.
/// 2. For every requested label NOT already in the existing set, call
///    `backend.create_label`. On success keep the label. On failure
///    drop it and warn — same forward-progress posture as step 1.
/// 3. Return the union of already-existing labels and successfully
///    created labels (in request order).
///
/// This replaces the prior filter-only helper: operators who declared
/// labels in `.assay.toml` now have those labels auto-provisioned the
/// first time `--apply-pr` runs against a fresh repo, instead of the
/// PR opening unattended.
pub(super) fn ensure_labels_exist(
    backend: &dyn PullRequestBackend,
    owner: &str,
    repo: &str,
    requested: &[String],
) -> Vec<String> {
    if requested.is_empty() {
        return Vec::new();
    }
    let existing = match backend.list_labels(owner, repo) {
        Ok(labels) => labels,
        Err(err) => {
            eprintln!(
                "assay: WARNING: couldn't list labels on {owner}/{repo} ({err}); \
                 opening the PR without any labels"
            );
            return Vec::new();
        }
    };
    let existing_set: std::collections::HashSet<&str> =
        existing.iter().map(String::as_str).collect();
    let mut kept: Vec<String> = Vec::new();
    let mut create_failures: Vec<String> = Vec::new();
    for name in requested {
        if existing_set.contains(name.as_str()) {
            kept.push(name.clone());
            continue;
        }
        match backend.create_label(owner, repo, name) {
            Ok(()) => kept.push(name.clone()),
            Err(err) => {
                create_failures.push(format!("{name} ({err})"));
            }
        }
    }
    if !create_failures.is_empty() {
        eprintln!(
            "assay: WARNING: dropping {} label(s) that couldn't be auto-created on {owner}/{repo}: {}",
            create_failures.len(),
            create_failures.join(", ")
        );
    }
    kept
}

/// Pre-flight check that `gh` is installed and authenticated with the
/// `repo` scope before `--apply-pr` starts validating proposals.
///
/// Without this guard the operator could spend minutes on validation
/// only to fail at `gh pr create` time. `--force` bypasses upstream for
/// edge cases (`gh` in a non-standard location, plans to open the PR
/// manually after the branch lands, etc.).
pub(super) fn preflight_apply_pr_gh_auth(backend: &GhCliBackend) -> Result<()> {
    backend.check_auth().map_err(|err| {
        Error::other(format!(
            "apply-pr pre-flight: gh CLI auth check failed: {err} \
             (run `gh auth login -s repo` and retry, or pass --force to skip this check)"
        ))
    })
}

/// Config key for the specific broken `insteadOf` rewrite — when this
/// key is set with any non-empty value, `git push` to any github.com
/// URL will be rewritten through a literal `x-access-token:@` prefix
/// (empty password) which git treats as a real failing credential
/// instead of consulting its credential helper.
pub(super) const BROKEN_INSTEADOF_KEY: &str = "url.https://x-access-token:@github.com/.insteadof";

/// Pure check: given the raw `git config --get-all <KEY>` output (or
/// `None` if the key wasn't set), return Err with a remediation when
/// the broken rewrite is present. Returns the std `Result<_, String>`
/// shape (NOT the crate alias) so the pure check stays independent of
/// the crate's [`crate::error::Error`] enum.
pub(super) fn check_insteadof_rewrite(
    git_config_value: Option<&str>,
) -> std::result::Result<(), String> {
    let Some(value) = git_config_value else {
        return Ok(());
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    Err(format!(
        "apply-pr pre-flight: your global git config has \
         `{BROKEN_INSTEADOF_KEY} = {trimmed}` which rewrites every github.com URL to embed an EMPTY \
         x-access-token credential. git treats the empty token as a real (failing) credential and \
         never consults its credential helper, breaking `git push` for every wildmason repo.\n\n\
         Recommended fix (removes the broken rule globally):\n  \
         git config --global --unset url.\"https://x-access-token:@github.com/\".insteadOf\n\n\
         Workaround for this run only: pass --force to bypass this check, then push from a remote \
         whose URL embeds a real token (e.g. `git remote set-url <remote> https://x-access-token:$(gh auth token)@github.com/<owner>/<repo>.git`)."
    ))
}

/// Run the `insteadOf` rewrite check against the operator's git config.
pub(super) fn preflight_apply_pr_insteadof(repo: &Path) -> Result<()> {
    let output = std::process::Command::new("git")
        .args(["config", "--get-all", BROKEN_INSTEADOF_KEY])
        .current_dir(repo)
        .output();
    let value = match output {
        // `git config --get-all` exits non-zero when the key is absent;
        // that's the happy case, not an error.
        Ok(o) if o.status.success() => Some(String::from_utf8_lossy(&o.stdout).into_owned()),
        Ok(_) => None,
        // Couldn't invoke git at all — let downstream stages surface
        // that error in their own context rather than fail the preflight.
        Err(_) => return Ok(()),
    };
    check_insteadof_rewrite(value.as_deref()).map_err(Error::other)
}

/// Run the post-validation `--apply-pr` flow:
/// branch → worktree → merge-apply → copy_back → commit → push → open PR.
#[allow(clippy::too_many_arguments)]
pub(super) fn perform_apply_pr(
    repo: &Path,
    registry: &[Box<dyn DependencyEcosystem>],
    completed_runs: &mut [ProposalRun],
    pre_validation_failures: usize,
    provenance: &mut Provenance,
    backend: &dyn PullRequestBackend,
    remote: &str,
    run_id: &str,
    validator: &Validator,
    requested_labels: &[String],
    requested_reviewers: &[String],
    draft: bool,
) -> Result<ApplyPrSummary> {
    let red_count = pre_validation_failures
        + completed_runs
            .iter()
            .filter(|r| r.outcome.conclusion != "success")
            .count();
    let total = completed_runs.len() + pre_validation_failures;
    if total == 0 {
        return Ok(ApplyPrSummary::NothingToPublish);
    }
    if red_count > 0 {
        provenance.records.push(ProvenanceRecord {
            tool: "assay".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            stage: "publisher.apply_pr".into(),
            subject: "<aggregate>".into(),
            status: Classification::Unsupported,
            summary: format!(
                "refused to open PR: {} of {} proposal(s) didn't validate green",
                red_count, total
            ),
            artifact_path: None,
            details: None,
        });
        return Ok(ApplyPrSummary::SkippedDueToFailures { red_count, total });
    }

    completed_runs.sort_by(|a, b| a.proposal.id.cmp(&b.proposal.id));

    let ship_plan = build_ship_plan_from_runs(
        repo,
        run_id,
        registry,
        validator,
        completed_runs,
        provenance,
    )?;

    let mut shipped_flat: Vec<(usize, &ProposalRun)> = Vec::new();
    for outcome in &ship_plan {
        for run_idx in &outcome.shipped {
            shipped_flat.push((outcome.eco_idx, &completed_runs[*run_idx]));
        }
    }
    let merged_drops: Vec<MergedDropInfo> = ship_plan
        .iter()
        .flat_map(|o| {
            o.dropped.iter().map(|d| MergedDropInfo {
                proposal_id: completed_runs[d.run_idx].proposal.id.clone(),
                reason: d.reason.clone(),
            })
        })
        .collect();

    if shipped_flat.is_empty() {
        provenance.records.push(ProvenanceRecord {
            tool: "assay".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            stage: "publisher.apply_pr".into(),
            subject: "<aggregate>".into(),
            status: Classification::Unsupported,
            summary: format!(
                "refused to open PR: every individually-green proposal was dropped by the merge step ({} drop(s))",
                merged_drops.len()
            ),
            artifact_path: None,
            details: None,
        });
        return Ok(ApplyPrSummary::AllDroppedByMerge {
            drops: merged_drops,
        });
    }

    let (owner, repo_name) = parse_owner_repo_from_origin(repo, remote)
        .map_err(|err| Error::other(format!("couldn't determine owner/repo: {err}")))?;
    let shipped_runs: Vec<&ProposalRun> = shipped_flat.iter().map(|(_, r)| *r).collect();
    let branch = compute_branch_name_for_runs(&shipped_runs);
    crate::publisher::git_push::validate_branch_name(&branch).map_err(|err| {
        Error::other(format!(
            "internal: generated branch name `{branch}` fails validation: {err}"
        ))
    })?;
    crate::publisher::git_push::validate_remote_name(remote).map_err(|err| {
        Error::other(format!(
            "--remote `{remote}` fails charset validation: {err}"
        ))
    })?;

    // Create a fresh worktree on a new branch from HEAD. The worktree
    // is where copy-back + commit happen; the host main checkout is
    // never mutated by --apply-pr.
    let worktree = repo
        .join(".assay")
        .join("runs")
        .join(run_id)
        .join("pr-tree");
    if let Some(parent) = worktree.parent() {
        std::fs::create_dir_all(parent).map_err(|source| Error::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    // Same sub-dir support as `prepare_apply_local_tree`: walk up to
    // the real git root so `git worktree add` finds the shared .git.
    let git_root = git_top_level(repo)?;
    let output = std::process::Command::new("git")
        .args(["worktree", "add", "-b"])
        .arg(&branch)
        .arg(&worktree)
        .arg("HEAD")
        .current_dir(&git_root)
        .output()
        .map_err(|source| Error::Io {
            path: git_root.clone(),
            source,
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::other(format_worktree_add_failure(
            &branch,
            stderr.trim(),
        )));
    }

    // From here on, any early-exit must clean up the local worktree +
    // branch we just created. The guard's Drop runs on every code path
    // that doesn't reach `partial.dismiss()` at the bottom of this
    // function.
    let mut partial = PartialApplyState::new(git_root.clone());
    partial.track_local(worktree.clone(), branch.clone());

    // Copy back into the worktree, per merged-ecosystem set.
    let mut modified_paths: Vec<PathBuf> = Vec::new();
    for outcome in &ship_plan {
        if outcome.shipped.is_empty() {
            continue;
        }
        let ecosystem = registry[outcome.eco_idx].as_ref();
        let shipped_proposals: Vec<&Proposal> = outcome
            .shipped
            .iter()
            .map(|i| &completed_runs[*i].proposal)
            .collect();
        // Locate the worktree's mirror of this outcome's scan_root. For
        // single-root, this IS the worktree. For Tauri polyglot, this
        // is `<worktree>/<scan_root-relative-to-artifact-root>` (e.g.
        // `<worktree>/src-tauri`).
        let prefix = relative_prefix(repo, &outcome.scan_root);
        let host_target = match &prefix {
            Some(p) if !p.as_os_str().is_empty() => worktree.join(p),
            _ => worktree.clone(),
        };
        let modified = ecosystem
            .copy_back_merged(&shipped_proposals, &outcome.sandbox, &host_target)
            .map_err(|err| {
                Error::other(format!(
                    "merged copy-back failed for `{}` ecosystem: {err}",
                    ecosystem.name()
                ))
            })?;
        for path in &modified {
            let joined = match &prefix {
                Some(p) if !p.as_os_str().is_empty() => p.join(path),
                _ => path.clone(),
            };
            if !modified_paths.contains(&joined) {
                modified_paths.push(joined);
            }
        }
        provenance.records.push(ProvenanceRecord {
            tool: "assay".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            stage: "publisher.apply_pr".into(),
            subject: format!("<merged:{}>", ecosystem.name()),
            status: Classification::Exact,
            summary: format!(
                "copied back {} path(s) for {} merged proposal(s)",
                modified.len(),
                shipped_proposals.len()
            ),
            artifact_path: None,
            details: Some(serde_json::json!({
                "ecosystem": ecosystem.name(),
                "proposals": shipped_proposals.iter().map(|p| p.id.clone()).collect::<Vec<_>>(),
                "scan_root": outcome.scan_root.display().to_string(),
            })),
        });
    }

    if modified_paths.is_empty() {
        // Worktree was created but copy-back found nothing to stage.
        // Clean up quietly — this is an expected no-op, not an error.
        partial.dismiss_quietly();
        return Ok(ApplyPrSummary::NothingToPublish);
    }

    let body = build_commit_body(completed_runs, &shipped_flat, &merged_drops);
    let raw_subject = if shipped_flat.len() == 1 {
        let p = &shipped_flat[0].1.proposal;
        format!(
            "chore(deps): bump {} from {} to {}",
            p.subject, p.from, p.to
        )
    } else {
        format!("chore(deps): bump {} dependencies", shipped_flat.len())
    };
    let subject = sanitize_commit_subject(&raw_subject)
        .map_err(|err| {
            Error::other(format!(
                "internal: generated commit subject failed sanitization: {err}"
            ))
        })?
        .to_string();
    let skipped_gitignored = git_add_paths(&worktree, &modified_paths)?;
    if !skipped_gitignored.is_empty() {
        emit_gitignored_skip_warning(&skipped_gitignored);
    }
    git_commit(&worktree, &subject, &body)?;

    // Push the branch.
    crate::publisher::git_push::push_branch(&worktree, remote, &branch)
        .map_err(|err| Error::other(format!("git push failed: {err}")))?;

    // After push, fetch branch metadata and run the three-guard check.
    // Defense in depth: branch namespace is validated upstream, but the
    // default/protected-branch check needs server-side state.
    let metadata = backend.fetch_branch_metadata(&owner, &repo_name, &branch)?;
    guard_push_target(&branch, &metadata).map_err(|err| {
        Error::other(format!(
            "post-push guard rejected branch `{branch}`: {err} \
             (the branch was pushed but the PR was NOT opened; you may want to delete the remote branch)"
        ))
    })?;

    // Open the PR. Title overrides build_pull_request_request's default
    // "Bump <subject>" shape so the multi-bump case reads cleanly.
    let title = if shipped_flat.len() == 1 {
        format!(
            "Bump {} from {} to {}",
            shipped_flat[0].1.proposal.subject,
            shipped_flat[0].1.proposal.from,
            shipped_flat[0].1.proposal.to,
        )
    } else {
        format!("Bump {} dependencies via assay", shipped_flat.len())
    };
    let base = detect_default_branch(repo, remote).unwrap_or_else(|| "main".into());
    let labels = ensure_labels_exist(backend, &owner, &repo_name, requested_labels);
    let reviewers =
        filter_reviewers_to_collaborators(backend, &owner, &repo_name, requested_reviewers);
    let mut request = build_pull_request_request(PullRequestParams {
        owner: &owner,
        repo: &repo_name,
        branch: &branch,
        base: &base,
        subject: &title,
        body: body.clone(),
        labels,
        reviewers,
        draft,
    });
    request.title = title;
    let response = backend.open_pull_request(&request).map_err(|err| {
        Error::other(format!(
            "the branch was pushed but `gh pr create` failed: {err}. \
             You can open the PR manually from {}.",
            request.branch,
        ))
    })?;

    provenance.records.push(ProvenanceRecord {
        tool: "assay".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        stage: "publisher.apply_pr".into(),
        subject: "<pr>".into(),
        status: Classification::Exact,
        summary: response.url.clone(),
        artifact_path: None,
        details: Some(serde_json::json!({
            "branch": branch,
            "url": response.url,
            "number": response.number,
        })),
    });

    // Reaching here means push + branch metadata guard + PR open all
    // succeeded. The worktree + local branch are part of the run's
    // audit trail (operator can `cd .assay/runs/<run-id>/pr-tree` and
    // inspect), so dismiss the cleanup guard.
    partial.dismiss();

    Ok(ApplyPrSummary::Published {
        url: response.url,
        branch,
        bump_count: shipped_flat.len(),
        merged_drops,
    })
}

/// Detect the repository's default branch using `git remote show <remote>`.
/// Falls back to None if anything goes wrong; callers default to "main".
fn detect_default_branch(repo: &Path, remote: &str) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["remote", "show", remote])
        .current_dir(repo)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(rest) = line.trim().strip_prefix("HEAD branch: ") {
            return Some(rest.trim().to_string());
        }
    }
    None
}
