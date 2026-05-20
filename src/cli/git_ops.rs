//! Git plumbing used by the apply pipelines.
//!
//! Two roles fold cleanly into one module:
//!
//! 1. **Staging + committing** in the host repo for `--apply-local`
//!    and `--apply-pr`: [`git_add_paths`], [`git_commit`],
//!    [`working_tree_dirty_path`], plus the gitignore-aware partition
//!    helpers that keep us from blowing up on library projects whose
//!    lockfiles are ignored on purpose.
//!
//! 2. **Preparing the per-proposal sandbox**: [`prepare_apply_local_tree`]
//!    spins up an isolated `git worktree` under `.assay/runs/<id>/work/`
//!    so each proposal can be applied, validated, and copied back
//!    independently of the host tree.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Stage `paths` in `repo` and return any gitignored-and-untracked paths
/// that were skipped. Refuses when every path is gitignored — that
/// signals an empty staged set and a confusing commit if we proceeded.
pub(super) fn git_add_paths(repo: &Path, paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let (stageable, ignored) = partition_stageable_paths(repo, paths)?;
    if stageable.is_empty() {
        return Err(Error::other(format!(
            "git add refused: all {} modified path(s) are gitignored — nothing to commit \
             (paths: {})",
            ignored.len(),
            ignored
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    let mut cmd = std::process::Command::new("git");
    cmd.arg("add").arg("--").current_dir(repo);
    for path in &stageable {
        cmd.arg(path);
    }
    let output = cmd.output().map_err(|source| Error::Io {
        path: repo.to_path_buf(),
        source,
    })?;
    if !output.status.success() {
        return Err(Error::other(format!(
            "git add failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(ignored)
}

/// Print a stderr warning naming the gitignored paths that were
/// excluded from the commit. Library projects routinely gitignore
/// lockfiles — the meaningful artifact (the manifest constraint
/// widening) still ships, but the lockfile change stays as an
/// unstaged working-tree edit the user can either keep, discard with
/// `git restore`, or regenerate with `cargo update` / `npm install`.
pub(super) fn emit_gitignored_skip_warning(skipped: &[PathBuf]) {
    let joined = skipped
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    eprintln!(
        "assay: warning: {} path(s) gitignored and excluded from commit: {}",
        skipped.len(),
        joined,
    );
    eprintln!(
        "assay: note: gitignored files were updated in your working tree but stay untracked per your .gitignore. \
         Run `git restore <path>` to discard, or regenerate the lockfile to match your local toolchain."
    );
}

/// Partition `paths` into "stageable now" vs "untracked + gitignored."
///
/// The predicate for skipping is "would `git add` refuse this path?".
/// Tracked paths can always be re-staged (gitignore is irrelevant once
/// a file is in the index). Untracked paths that match a gitignore
/// rule are refused by `git add` and would abort the whole batch.
///
/// Two `git` invocations per path is fine here — the path lists this
/// function receives are bounded by what `copy_back_merged` returns
/// for a single ecosystem's merged ship plan (small).
pub(super) fn partition_stageable_paths(
    repo: &Path,
    paths: &[PathBuf],
) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut stageable: Vec<PathBuf> = Vec::new();
    let mut ignored: Vec<PathBuf> = Vec::new();
    for path in paths {
        if path_is_untracked_and_gitignored(repo, path)? {
            ignored.push(path.clone());
        } else {
            stageable.push(path.clone());
        }
    }
    Ok((stageable, ignored))
}

pub(super) fn path_is_untracked_and_gitignored(repo: &Path, path: &Path) -> Result<bool> {
    // Tracked paths can always be re-staged — gitignore rules don't
    // apply once a file is in the index. Check tracking first; if it's
    // tracked we don't even need to ask about gitignore.
    let tracked = std::process::Command::new("git")
        .args(["ls-files", "--error-unmatch", "--"])
        .arg(path)
        .current_dir(repo)
        .output()
        .map_err(|source| Error::Io {
            path: repo.to_path_buf(),
            source,
        })?;
    if tracked.status.success() {
        return Ok(false);
    }
    // Untracked — does it match a gitignore rule? `git check-ignore`
    // exits 0 when the path is ignored, 1 when not. Any other exit
    // code (e.g. 128 for "not a git repo") surfaces as a hard error.
    let ignored = std::process::Command::new("git")
        .args(["check-ignore", "--"])
        .arg(path)
        .current_dir(repo)
        .output()
        .map_err(|source| Error::Io {
            path: repo.to_path_buf(),
            source,
        })?;
    match ignored.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(Error::other(format!(
            "git check-ignore failed for `{}`: {}",
            path.display(),
            String::from_utf8_lossy(&ignored.stderr).trim()
        ))),
    }
}

/// Create a single commit on the current branch with the given subject
/// and body. Refuses to amend; if there's nothing staged, returns an
/// error rather than silently no-opping.
pub(super) fn git_commit(repo: &Path, subject: &str, body: &str) -> Result<()> {
    let mut cmd = std::process::Command::new("git");
    cmd.arg("commit").current_dir(repo);
    cmd.arg("-m").arg(subject);
    if !body.is_empty() {
        cmd.arg("-m").arg(body);
    }
    let output = cmd.output().map_err(|source| Error::Io {
        path: repo.to_path_buf(),
        source,
    })?;
    if !output.status.success() {
        return Err(Error::other(format!(
            "git commit failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Returns `Some(path_to_first_dirty_file)` if `git status --porcelain`
/// reports any uncommitted change; `None` for a clean tree or when the
/// repo isn't a git checkout (in which case there's nothing to protect).
///
/// `.assay/` (assay's own artifact directory) is filtered out of the
/// dirty-tree check — its presence is a self-inflicted dirty state and
/// would otherwise refuse every back-to-back `analyze` → `analyze
/// --apply-local`. Operators who care about scoping `.assay/` out of
/// git can `.gitignore` it; this filter just guarantees assay never
/// trips on its own output.
pub(super) fn working_tree_dirty_path(repo: &std::path::Path) -> Result<Option<String>> {
    if !repo.join(".git").exists() {
        return Ok(None);
    }
    let output = std::process::Command::new("git")
        .arg("status")
        .arg("--porcelain")
        .current_dir(repo)
        .output()
        .map_err(|source| Error::Io {
            path: repo.to_path_buf(),
            source,
        })?;
    if !output.status.success() {
        // Treat git failure as "we don't know" — better to refuse and ask the
        // operator than risk apply-local on a partial state.
        return Err(Error::other(format!(
            "git status failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .find(|line| !porcelain_line_is_assay_artifact(line))
        .map(|s| s.to_string()))
}

/// `git status --porcelain` lines start with a 2-char status code + space +
/// path. Path uses forward slashes regardless of OS. Returns `true` when
/// the path refers to assay's own `.assay/` artifact tree.
pub(super) fn porcelain_line_is_assay_artifact(line: &str) -> bool {
    // Status code is exactly 2 chars + 1 space; path starts at byte 3.
    // Quoted paths (when the path contains spaces or special chars) have
    // a leading `"` which the simple `starts_with(".assay/")` test
    // wouldn't match — handle both shapes.
    let Some(rest) = line.get(3..) else {
        return false;
    };
    let path = rest.strip_prefix('"').unwrap_or(rest);
    // Renames have the shape `R  old -> new`; the new path is what
    // matters for dirty-tree intent. We check both halves to be safe.
    if let Some((old_path, new_path)) = path.split_once(" -> ") {
        return path_is_under_assay_dir(old_path) || path_is_under_assay_dir(new_path);
    }
    path_is_under_assay_dir(path)
}

pub(super) fn path_is_under_assay_dir(path: &str) -> bool {
    let trimmed = path.trim_end_matches('"');
    trimmed == ".assay" || trimmed.starts_with(".assay/")
}

/// Spin up an isolated `git worktree` under `.assay/runs/<run_id>/work/`
/// so a proposal can be applied + validated without disturbing the host
/// tree. Returns the directory inside the worktree where the applier
/// should run (sub-dir aware: matches `scan_root`'s relationship to the
/// repo top-level).
pub(super) fn prepare_apply_local_tree(
    artifact_root: &std::path::Path,
    scan_root: &std::path::Path,
    run_id: &str,
    proposal_id: &str,
) -> Result<PathBuf> {
    // `scan_root` may point at a sub-directory of a git repo (e.g.
    // helm's `src-tauri/` under helm root, or one of several config-
    // declared roots in a Tauri polyglot layout). `git rev-parse
    // --show-toplevel` walks up to the real repo root; `git worktree
    // add` must run there to access the shared .git dir.
    //
    // `.assay/runs/<id>/work/` is anchored at `artifact_root` so all
    // sandboxes for one run live in one tree, even when proposals
    // come from multiple scan_roots. Single-root callers pass
    // artifact_root == scan_root.
    let git_root = git_top_level(scan_root)?;
    let rel_sub_dir = scan_root.canonicalize().ok().and_then(|c| {
        git_root
            .canonicalize()
            .ok()
            .and_then(|g| c.strip_prefix(&g).ok().map(Path::to_path_buf))
    });
    let work_root = artifact_root
        .join(".assay")
        .join("runs")
        .join(run_id)
        .join("work");
    std::fs::create_dir_all(&work_root).map_err(|source| Error::Io {
        path: work_root.clone(),
        source,
    })?;
    let base = safe_apply_tree_name(proposal_id);
    let mut target = work_root.join(&base);
    let mut suffix = 2usize;
    while target.exists() {
        target = work_root.join(format!("{base}-{suffix}"));
        suffix += 1;
    }
    // Convert target to absolute. `git worktree add` resolves a
    // relative target against its `current_dir` (which we set to
    // git_root), not against where assay was invoked — without this
    // canonicalization the worktree lands in the wrong place when
    // `--repo` is a sub-dir.
    let target_abs = std::path::absolute(&target).unwrap_or(target.clone());
    let output = std::process::Command::new("git")
        .arg("worktree")
        .arg("add")
        .arg("--detach")
        .arg(&target_abs)
        .arg("HEAD")
        .current_dir(&git_root)
        .output()
        .map_err(|source| Error::Io {
            path: git_root.clone(),
            source,
        })?;
    if !output.status.success() {
        return Err(Error::other(format!(
            "git worktree add failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    // Materialize external path deps (e.g. helm's
    // `wildmason-license = { path = "../../licensing/crate" }`) into
    // the sandbox so cargo's path resolution from inside the worktree
    // lands on real directories. No-op when the repo declares no
    // external path deps.
    let run_root = artifact_root.join(".assay").join("runs").join(run_id);
    crate::external_deps::materialize_external_deps_into_sandbox(
        scan_root,
        &target_abs,
        &run_root,
    )?;

    // When `repo` is a sub-directory, the applier/validator expect to
    // run inside the same sub-dir of the worktree. Otherwise they
    // wouldn't find Cargo.toml / package.json relative to the operator-
    // facing repo argument.
    let final_target = match rel_sub_dir {
        Some(rel) if !rel.as_os_str().is_empty() => target_abs.join(rel),
        _ => target_abs,
    };
    Ok(final_target)
}

/// Resolve the top-level git repo root for `path` via
/// `git rev-parse --show-toplevel`. Errors with a clear message when
/// `path` isn't under any git checkout (the operator can't use
/// `--apply-local` without git for the sandbox machinery).
pub(super) fn git_top_level(path: &Path) -> Result<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(path)
        .output()
        .map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if !output.status.success() {
        return Err(Error::other(format!(
            "--apply-local requires a git checkout so assay can retain an isolated worktree, \
             but `{}` is not under one (git rev-parse said: {})",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim(),
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(PathBuf::from(stdout.trim()))
}

/// Map a proposal id into a filesystem-safe directory name for the
/// per-proposal worktree. Lowercases, collapses non-alphanumerics into
/// single dashes, caps length at 80 chars, and trims trailing dashes.
pub(super) fn safe_apply_tree_name(proposal_id: &str) -> String {
    let mut out = String::with_capacity(proposal_id.len().min(80));
    let mut last_dash = false;
    for ch in proposal_id.chars().flat_map(char::to_lowercase) {
        let mapped = if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            ch
        } else {
            '-'
        };
        if mapped == '-' {
            if !last_dash && !out.is_empty() {
                out.push(mapped);
                last_dash = true;
            }
        } else {
            out.push(mapped);
            last_dash = false;
        }
        if out.len() >= 80 {
            break;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "proposal".into()
    } else {
        out
    }
}
