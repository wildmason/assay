//! Git command-injection-safe wrapper for branch push.
//!
//! Every argument goes through `Command::new("git").arg(...)`. Branch
//! names, remote names, and target refs are charset-validated before
//! invocation; no string is ever concatenated into a shell command.

use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GitPushError {
    #[error("branch name {0:?} fails charset validation; allowed: assay/<eco>/<id>")]
    InvalidBranch(String),
    #[error("remote name {0:?} fails charset validation; allowed: [a-z0-9-]")]
    InvalidRemote(String),
    #[error("working tree {0} is not a directory")]
    NotADirectory(PathBuf),
    #[error("git push exited non-zero: {0}")]
    PushFailed(String),
    #[error("git invocation failed to start: {0}")]
    SpawnFailed(String),
}

/// Validate a branch name for `git push` safety. Only branch names that
/// match assay's deterministic shape pass.
///
/// Acceptable shape: `assay/<eco>/<slug>` where `<eco>` and
/// `<slug>` are `[a-z0-9-]+` (slug additionally allows the SHA-derived
/// hash suffix from `branch_name_for_bump`).
pub fn validate_branch_name(branch: &str) -> Result<(), GitPushError> {
    let segments: Vec<&str> = branch.split('/').collect();
    if segments.len() != 3 {
        return Err(GitPushError::InvalidBranch(branch.into()));
    }
    if segments[0] != "assay" {
        return Err(GitPushError::InvalidBranch(branch.into()));
    }
    for segment in &segments[1..] {
        if segment.is_empty() {
            return Err(GitPushError::InvalidBranch(branch.into()));
        }
        for ch in segment.bytes() {
            if !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == b'-') {
                return Err(GitPushError::InvalidBranch(branch.into()));
            }
        }
        if segment.starts_with('-') || segment.ends_with('-') {
            return Err(GitPushError::InvalidBranch(branch.into()));
        }
    }
    Ok(())
}

/// Validate a git remote name (e.g. `origin`, `upstream`). Charset:
/// `[a-z0-9-]+`, no leading/trailing dash, 1..=64 chars.
pub fn validate_remote_name(remote: &str) -> Result<(), GitPushError> {
    if remote.is_empty() || remote.len() > 64 {
        return Err(GitPushError::InvalidRemote(remote.into()));
    }
    for ch in remote.bytes() {
        if !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == b'-') {
            return Err(GitPushError::InvalidRemote(remote.into()));
        }
    }
    if remote.starts_with('-') || remote.ends_with('-') {
        return Err(GitPushError::InvalidRemote(remote.into()));
    }
    Ok(())
}

/// Build the exact argv for a non-force push of a branch. Test-friendly
/// — exposes the argv so callers can assert against it without spawning
/// a real git process.
pub fn build_push_argv(remote: &str, branch: &str) -> Vec<String> {
    vec![
        "git".into(),
        "push".into(),
        "--set-upstream".into(),
        remote.into(),
        format!("{branch}:{branch}"),
    ]
}

/// Execute `git push --set-upstream <remote> <branch>:<branch>` inside
/// `working_tree`. Validates all inputs first; never shell-interpolates.
pub fn push_branch(working_tree: &Path, remote: &str, branch: &str) -> Result<(), GitPushError> {
    validate_branch_name(branch)?;
    validate_remote_name(remote)?;
    if !working_tree.is_dir() {
        return Err(GitPushError::NotADirectory(working_tree.to_path_buf()));
    }
    let argv = build_push_argv(remote, branch);
    let output = Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(working_tree)
        .output()
        .map_err(|e| GitPushError::SpawnFailed(e.to_string()))?;
    if !output.status.success() {
        return Err(GitPushError::PushFailed(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_branch_accepts_canonical_shape() {
        assert!(validate_branch_name("assay/cargo/serde-1-0-215-a3f9b2c41058").is_ok());
        assert!(validate_branch_name("assay/github-actions/actions-checkout-abcd").is_ok());
    }

    #[test]
    fn validate_branch_rejects_classic_injection_attempts() {
        // Every one of these would be catastrophic if it ever reached `git`.
        let attacks = [
            "assay/cargo/serde; rm -rf /",
            "$(curl evil)",
            "`whoami`",
            "../../../etc/passwd",
            "assay/cargo/serde\nmalicious",
            "main",              // wrong prefix
            "assay/cargo",       // missing slug segment
            "assay//slug",       // empty middle
            "assay/cargo/",      // empty slug
            "assay/Cargo/slug",  // uppercase
            "assay/cargo/-slug", // leading dash
            "assay/cargo/slug-", // trailing dash
            "assay/cargo/sl/ug", // extra slash
            "ASSAY/cargo/slug",  // uppercase prefix
        ];
        for branch in attacks {
            assert!(
                validate_branch_name(branch).is_err(),
                "hostile branch must be rejected: {branch:?}"
            );
        }
    }

    #[test]
    fn validate_remote_accepts_standard_names() {
        for name in ["origin", "upstream", "fork-1", "wm-bot"] {
            assert!(validate_remote_name(name).is_ok(), "should accept: {name}");
        }
    }

    #[test]
    fn validate_remote_rejects_injection_attempts() {
        let attacks = [
            "", "Origin",  // uppercase
            "or igin", // space
            "or;igin", // semicolon
            "-origin", // leading dash
            "origin-", // trailing dash
            "../etc",  // path
        ];
        for name in attacks {
            assert!(validate_remote_name(name).is_err(), "must reject: {name:?}");
        }
    }

    #[test]
    fn build_push_argv_has_no_shell_metacharacters() {
        let argv = build_push_argv("origin", "assay/cargo/serde-1-0-215-abc123");
        assert_eq!(argv[0], "git");
        assert_eq!(argv[1], "push");
        assert_eq!(argv[2], "--set-upstream");
        assert_eq!(argv[3], "origin");
        assert!(argv[4].contains("assay/cargo/serde-1-0-215-abc123"));
        // No argument contains shell metacharacters.
        for arg in &argv {
            for ch in arg.chars() {
                assert!(
                    !matches!(ch, ';' | '|' | '&' | '`' | '$' | '<' | '>' | '\n'),
                    "argv contains shell metacharacter {ch:?}: {arg}"
                );
            }
        }
    }

    #[test]
    fn push_branch_propagates_invalid_branch() {
        let tmp = tempfile::tempdir().unwrap();
        let result = push_branch(tmp.path(), "origin", "main");
        assert!(matches!(result, Err(GitPushError::InvalidBranch(_))));
    }

    #[test]
    fn push_branch_propagates_invalid_remote() {
        let tmp = tempfile::tempdir().unwrap();
        let result = push_branch(tmp.path(), "origin; rm -rf /", "assay/cargo/serde-abc");
        assert!(matches!(result, Err(GitPushError::InvalidRemote(_))));
    }

    #[test]
    fn push_branch_rejects_non_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("not-a-dir");
        std::fs::write(&file, "stub").unwrap();
        let result = push_branch(&file, "origin", "assay/cargo/serde-abc");
        assert!(matches!(result, Err(GitPushError::NotADirectory(_))));
    }
}
