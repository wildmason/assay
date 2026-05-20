//! Apply + copy-back primitives for the cargo ecosystem.
//!
//! Tier-aware: `LockfileOnly` proposals only need `cargo update --workspace`;
//! `Compatible` / `Breaking` proposals widen the workspace manifests'
//! constraint on the subject crate first, then refresh the lockfile.
//! The `_merged` variants apply a set of proposals in one pass so the
//! resulting sandbox carries every shipped bump in one consistent state.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::model::{BumpTier, Proposal};

/// Apply a Cargo proposal to a working tree. Tier-aware:
///
/// - [`BumpTier::LockfileOnly`] runs `cargo update --workspace` in place
///   (the in-range bump cargo already detected as available).
/// - [`BumpTier::Compatible`] / [`BumpTier::Breaking`] widen each
///   workspace Cargo.toml's constraint on the subject crate to the
///   proposal's `to` version, then run `cargo update --workspace` so
///   the lockfile picks up the now-permitted version. Aborts loudly
///   if no manifest in the workspace carries a constraint to widen —
///   the proposer must not surface bumps the applier can't reach.
pub fn apply_cargo_proposal(proposal: &Proposal, tree_path: &Path) -> Result<()> {
    if !matches!(proposal.bump_tier, BumpTier::LockfileOnly) {
        let modified =
            crate::ecosystem::cargo_manifest_editor::apply_constraint_widening_to_workspace(
                tree_path,
                &proposal.subject,
                &proposal.to,
            )?;
        if modified.is_empty() {
            return Err(Error::other(format!(
                "expected to widen the constraint for `{}` in {} workspace but no manifest carried a matching dep entry",
                proposal.subject,
                tree_path.display(),
            )));
        }
    }
    apply_cargo_update_to_tree(tree_path)
}

/// Copy validated changes from sandbox back to host. Always carries
/// Cargo.lock; for non-LockfileOnly tiers also ships any Cargo.toml
/// whose bytes differ between sandbox and host (the constraint widening
/// done by `apply_cargo_proposal` typically lands in one manifest, but
/// a workspace with the same dep declared in multiple members may have
/// touched several).
pub fn copy_back_cargo_proposal(
    proposal: &Proposal,
    sandbox: &Path,
    host: &Path,
) -> Result<Vec<PathBuf>> {
    let mut copied: Vec<PathBuf> = Vec::new();

    let sandbox_lock = sandbox.join("Cargo.lock");
    if !sandbox_lock.is_file() {
        return Err(Error::other(format!(
            "Cargo.lock missing from sandbox at `{}`; cannot copy back",
            sandbox.display()
        )));
    }
    let host_lock = host.join("Cargo.lock");
    std::fs::copy(&sandbox_lock, &host_lock).map_err(|source| Error::Io {
        path: host_lock,
        source,
    })?;
    copied.push(PathBuf::from("Cargo.lock"));

    if !matches!(proposal.bump_tier, BumpTier::LockfileOnly) {
        let manifests = crate::ecosystem::cargo_manifest_editor::list_workspace_manifests(sandbox)?;
        for sb_manifest in manifests {
            let rel = sb_manifest
                .strip_prefix(sandbox)
                .unwrap_or(&sb_manifest)
                .to_path_buf();
            if !sb_manifest.is_file() {
                continue;
            }
            let host_manifest = host.join(&rel);
            let sb_bytes = std::fs::read(&sb_manifest).map_err(|source| Error::Io {
                path: sb_manifest.clone(),
                source,
            })?;
            let host_bytes = std::fs::read(&host_manifest).unwrap_or_default();
            if sb_bytes == host_bytes {
                continue;
            }
            std::fs::copy(&sb_manifest, &host_manifest).map_err(|source| Error::Io {
                path: host_manifest,
                source,
            })?;
            copied.push(rel);
        }
        copied.sort();
        // Dedup just in case (Cargo.lock first, manifests after).
        copied.dedup();
    }

    Ok(copied)
}

/// Apply a set of cargo proposals to ONE sandbox tree as a single merged
/// edit. Constraint widenings for all Compatible/Breaking proposals are
/// applied to the workspace manifests first, then `cargo update --workspace`
/// runs ONCE to refresh the lockfile against the merged constraint state.
///
/// This is the multi-proposal merge path used by `--apply-local` /
/// `--apply-pr` after per-proposal validation: it produces a sandbox
/// whose Cargo.toml + Cargo.lock pair reflects every shipped bump in
/// one consistent state, defeating the prior per-proposal copy-back
/// last-write-wins bug for Compatible/Breaking tiers.
pub fn apply_cargo_proposals_merged(proposals: &[&Proposal], tree_path: &Path) -> Result<()> {
    for proposal in proposals {
        if matches!(proposal.bump_tier, BumpTier::LockfileOnly) {
            continue;
        }
        let modified =
            crate::ecosystem::cargo_manifest_editor::apply_constraint_widening_to_workspace(
                tree_path,
                &proposal.subject,
                &proposal.to,
            )?;
        if modified.is_empty() {
            return Err(Error::other(format!(
                "expected to widen the constraint for `{}` in {} workspace but no manifest carried a matching dep entry",
                proposal.subject,
                tree_path.display(),
            )));
        }
    }
    apply_cargo_update_to_tree(tree_path)
}

/// Copy a merged cargo sandbox's full validated change-set back to host.
///
/// Always carries `Cargo.lock`. If ANY proposal in the merged set is
/// non-LockfileOnly, walks the workspace manifests and ships any whose
/// bytes differ between sandbox and host (the merged apply may have
/// widened constraints across several Cargo.toml files when the same
/// crate is declared in multiple workspace members).
///
/// Replaces the default per-proposal `copy_back` loop on the merge path:
/// without this override the orchestrator would copy the same lockfile +
/// manifest pair N times, which is wasteful but otherwise correct.
pub fn copy_back_cargo_proposals_merged(
    proposals: &[&Proposal],
    sandbox: &Path,
    host: &Path,
) -> Result<Vec<PathBuf>> {
    let mut copied: Vec<PathBuf> = Vec::new();

    let sandbox_lock = sandbox.join("Cargo.lock");
    if !sandbox_lock.is_file() {
        return Err(Error::other(format!(
            "Cargo.lock missing from sandbox at `{}`; cannot copy back",
            sandbox.display()
        )));
    }
    let host_lock = host.join("Cargo.lock");
    std::fs::copy(&sandbox_lock, &host_lock).map_err(|source| Error::Io {
        path: host_lock,
        source,
    })?;
    copied.push(PathBuf::from("Cargo.lock"));

    let any_non_lockfile_only = proposals
        .iter()
        .any(|p| !matches!(p.bump_tier, BumpTier::LockfileOnly));
    if any_non_lockfile_only {
        let manifests = crate::ecosystem::cargo_manifest_editor::list_workspace_manifests(sandbox)?;
        for sb_manifest in manifests {
            let rel = sb_manifest
                .strip_prefix(sandbox)
                .unwrap_or(&sb_manifest)
                .to_path_buf();
            if !sb_manifest.is_file() {
                continue;
            }
            let host_manifest = host.join(&rel);
            let sb_bytes = std::fs::read(&sb_manifest).map_err(|source| Error::Io {
                path: sb_manifest.clone(),
                source,
            })?;
            let host_bytes = std::fs::read(&host_manifest).unwrap_or_default();
            if sb_bytes == host_bytes {
                continue;
            }
            std::fs::copy(&sb_manifest, &host_manifest).map_err(|source| Error::Io {
                path: host_manifest,
                source,
            })?;
            copied.push(rel);
        }
        copied.sort();
        copied.dedup();
    }

    Ok(copied)
}

/// Apply cargo bumps to a working tree by running `cargo update --workspace`
/// in place. Idempotent: invoking it again on an already-up-to-date tree
/// produces a no-op. The Applier is called once per `Proposal` so cargo
/// gets invoked multiple times for an N-bump scan; the second through Nth
/// invocations are fast because the lockfile is already at the desired
/// state.
pub fn apply_cargo_update_to_tree(tree_path: &Path) -> Result<()> {
    let manifest_path = tree_path.join("Cargo.toml");
    if !manifest_path.is_file() {
        return Err(Error::InvalidManifest {
            path: manifest_path,
            message: "Cargo.toml not found in working tree".into(),
        });
    }
    let manifest_str = manifest_path
        .to_str()
        .ok_or_else(|| Error::other("Cargo.toml path is not valid UTF-8"))?;
    let output = std::process::Command::new("cargo")
        .args(["update", "--workspace", "--manifest-path", manifest_str])
        .env("CARGO_TERM_COLOR", "never")
        .output()
        .map_err(|source| Error::Io {
            path: tree_path.to_path_buf(),
            source,
        })?;
    if !output.status.success() {
        return Err(Error::CargoUpdate {
            message: format!(
                "cargo update (apply) exited non-zero: stderr=\n{}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        });
    }
    Ok(())
}
