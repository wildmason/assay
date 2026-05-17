//! Push-target guards.
//!
//! Plan §G.1 specifies three independent guards on `git push`. Even if
//! the App's `contents: write` scope were compromised, these guards
//! refuse to push to the default branch or any protected branch. They
//! also reject any branch name that doesn't match assay's own
//! deterministic shape — a defense against a confused proposal somehow
//! generating an unsafe ref.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PushTargetError {
    #[error("refusing to push to default branch {0:?}")]
    DefaultBranch(String),
    #[error("refusing to push to protected branch {0:?}")]
    ProtectedBranch(String),
    #[error("branch name {0:?} is not in assay namespace; refusing push")]
    UnsafeBranchName(String),
}

/// Per-repo branch metadata pulled from GitHub before push. Constructed
/// either from a real `GET /repos/{o}/{r}` + `GET /repos/{o}/{r}/branches/{b}`
/// pair, or from a fixture in tests.
#[derive(Debug, Clone)]
pub struct BranchMetadata {
    pub name: String,
    pub is_default: bool,
    pub is_protected: bool,
}

/// Guard 1 — branch name must live under `assay/<eco>/<slug>`.
pub fn guard_branch_namespace(branch: &str) -> Result<(), PushTargetError> {
    let segments: Vec<&str> = branch.split('/').collect();
    if segments.len() != 3 || segments[0] != "assay" {
        return Err(PushTargetError::UnsafeBranchName(branch.into()));
    }
    if segments[1].is_empty() || segments[2].is_empty() {
        return Err(PushTargetError::UnsafeBranchName(branch.into()));
    }
    Ok(())
}

/// Guard 2 — target branch must not be the repository's default branch.
pub fn guard_default_branch(metadata: &BranchMetadata) -> Result<(), PushTargetError> {
    if metadata.is_default {
        return Err(PushTargetError::DefaultBranch(metadata.name.clone()));
    }
    Ok(())
}

/// Guard 3 — target branch must not be flagged `protected` on GitHub.
pub fn guard_protected_branch(metadata: &BranchMetadata) -> Result<(), PushTargetError> {
    if metadata.is_protected {
        return Err(PushTargetError::ProtectedBranch(metadata.name.clone()));
    }
    Ok(())
}

/// Compose all three guards. The publisher must call this before any
/// `git push` — failure here blocks the push at the publisher level
/// regardless of what GitHub's server-side checks do.
pub fn guard_push_target(branch: &str, metadata: &BranchMetadata) -> Result<(), PushTargetError> {
    guard_branch_namespace(branch)?;
    guard_default_branch(metadata)?;
    guard_protected_branch(metadata)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assay_branch() -> BranchMetadata {
        BranchMetadata {
            name: "assay/cargo/serde-1-0-215-abc".into(),
            is_default: false,
            is_protected: false,
        }
    }

    #[test]
    fn guards_accept_canonical_assay_branch() {
        let meta = assay_branch();
        assert!(guard_push_target(&meta.name, &meta).is_ok());
    }

    #[test]
    fn guard_namespace_rejects_main() {
        assert!(matches!(
            guard_branch_namespace("main"),
            Err(PushTargetError::UnsafeBranchName(_))
        ));
        assert!(matches!(
            guard_branch_namespace("master"),
            Err(PushTargetError::UnsafeBranchName(_))
        ));
    }

    #[test]
    fn guard_namespace_rejects_other_bot_namespaces() {
        // A bot that thinks it's assay but uses a different prefix
        // must still be refused.
        assert!(matches!(
            guard_branch_namespace("dependabot/cargo/serde"),
            Err(PushTargetError::UnsafeBranchName(_))
        ));
    }

    #[test]
    fn guard_namespace_rejects_extra_slashes() {
        assert!(guard_branch_namespace("assay/cargo/sub/slug").is_err());
    }

    #[test]
    fn guard_default_branch_refuses_default() {
        let mut meta = assay_branch();
        meta.is_default = true;
        assert!(matches!(
            guard_default_branch(&meta),
            Err(PushTargetError::DefaultBranch(_))
        ));
    }

    #[test]
    fn guard_protected_branch_refuses_protected() {
        let mut meta = assay_branch();
        meta.is_protected = true;
        assert!(matches!(
            guard_protected_branch(&meta),
            Err(PushTargetError::ProtectedBranch(_))
        ));
    }

    #[test]
    fn composite_guard_blocks_default_even_if_namespace_passes() {
        let mut meta = assay_branch();
        meta.is_default = true;
        // Branch name is in our namespace but it ALSO somehow maps to
        // default — composite guard must still refuse.
        assert!(matches!(
            guard_push_target(&meta.name, &meta),
            Err(PushTargetError::DefaultBranch(_))
        ));
    }

    #[test]
    fn composite_guard_blocks_protected_even_if_namespace_passes() {
        let mut meta = assay_branch();
        meta.is_protected = true;
        assert!(matches!(
            guard_push_target(&meta.name, &meta),
            Err(PushTargetError::ProtectedBranch(_))
        ));
    }
}
