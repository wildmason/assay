//! Path-shape helpers used across the CLI orchestration code.
//!
//! Everything here is a pure, dependency-free path transformation:
//! normalizing Windows extended-length prefixes for display, picking
//! relative segments for receipt rendering, identifying the nearest
//! enclosing git checkout. No I/O beyond what's required by
//! [`canonicalize`] and `.git` existence probing.

use std::path::{Path, PathBuf};

/// Strip the `\\?\` extended-length prefix that may show up after
/// [`std::path::Path::canonicalize`] on Windows. The path is correct
/// either way, but the prefix is noise in user-facing breadcrumbs.
pub(super) fn strip_extended_length_prefix(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        path
    }
}

/// Convert any backslashes to forward slashes so receipt-emitted
/// paths are consistent across OSes. `PathBuf` on Windows happily
/// stores forward slashes; the receipt is display-only on the
/// downstream side, so we don't need to preserve native separators
/// for filesystem operations.
pub(super) fn forward_slash_path(path: PathBuf) -> PathBuf {
    PathBuf::from(path.to_string_lossy().replace('\\', "/"))
}

/// Lexical-or-canonical path equivalence. Used by scan_roots dedupe
/// where two entries might refer to the same directory by different
/// strings (`.` vs absolute, `./src-tauri` vs `src-tauri`, etc.).
pub(super) fn same_path(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Path from `base` to `target` when target lives under base. Returns
/// `None` when they're equivalent (no prefix needed) or when target
/// isn't under base. Used by the apply-local commit path to convert
/// scan_root-relative modified paths into artifact_root-relative paths
/// for `git add`.
pub(super) fn relative_prefix(base: &Path, target: &Path) -> Option<PathBuf> {
    if same_path(base, target) {
        return None;
    }
    // Try lexical first (cheap, handles the common `--repo .` shape).
    if let Ok(stripped) = target.strip_prefix(base) {
        return Some(stripped.to_path_buf());
    }
    // Canonicalize and retry — handles `./src-tauri` vs absolute, etc.
    let base_canon = base.canonicalize().ok()?;
    let target_canon = target.canonicalize().ok()?;
    target_canon
        .strip_prefix(&base_canon)
        .ok()
        .map(Path::to_path_buf)
}

/// Walk up from `start` looking for a `.git` directory or file (worktree
/// pointer). Returns the directory containing it. `None` when `start`
/// is not inside any git checkout.
pub(super) fn find_enclosing_git_root(start: &Path) -> Option<PathBuf> {
    let mut cursor = if start.is_absolute() {
        Some(start.to_path_buf())
    } else {
        std::env::current_dir().ok().map(|cwd| cwd.join(start))
    }?;
    loop {
        let dot_git = cursor.join(".git");
        // `.git` may be a directory (normal repo) OR a regular file
        // (linked worktrees / submodules); both signal a repo root.
        if dot_git.exists() {
            return Some(cursor);
        }
        if !cursor.pop() {
            return None;
        }
    }
}

/// Resolve `(artifact_root, scan_root)` for `--project <PATH>`. When
/// `scan_root_initial` lives inside a git checkout, `artifact_root`
/// becomes the repo top-level (absolute) and `scan_root` becomes the
/// matching absolute path — so `.assay/runs/...` lands next to the
/// rest of the project's git-managed state and the
/// `scan_root.canonicalize().strip_prefix(artifact_root.canonicalize())`
/// arithmetic in `prepare_apply_local_tree` works unambiguously.
///
/// When `scan_root_initial` is NOT in a git checkout, both fall back
/// to its original (caller-supplied) shape — the single-root standalone
/// behavior.
pub(super) fn anchor_artifact_root_at_git_root(scan_root_initial: &Path) -> (PathBuf, PathBuf) {
    if let Some(git_root) = find_enclosing_git_root(scan_root_initial) {
        // Canonicalize scan_root so both paths share absolute form and
        // downstream strip_prefix logic doesn't see relative-vs-absolute
        // shape mismatch.
        let scan_root_abs = scan_root_initial
            .canonicalize()
            .unwrap_or_else(|_| scan_root_initial.to_path_buf());
        return (git_root, scan_root_abs);
    }
    (
        scan_root_initial.to_path_buf(),
        scan_root_initial.to_path_buf(),
    )
}
