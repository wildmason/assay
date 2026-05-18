//! `DependencyEcosystem` trait + per-ecosystem implementations.
//!
//! v1 ships two real implementations (Cargo, GitHub Actions). The two-impl
//! rule is satisfied, so the trait is a real abstraction rather than
//! ceremony.

use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::model::{ConsumerId, Manifest, Proposal, ValidationOutcome};

pub mod cargo;
pub mod cargo_manifest_editor;
pub mod github_actions;
pub mod npm;

/// Identifies an ecosystem by short name. Matches the string stored on
/// `Proposal.ecosystem` so the receipt index can group by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcosystemName {
    Cargo,
    GitHubActions,
    Npm,
}

impl EcosystemName {
    pub fn as_str(self) -> &'static str {
        match self {
            EcosystemName::Cargo => "cargo",
            EcosystemName::GitHubActions => "github-actions",
            EcosystemName::Npm => "npm",
        }
    }
}

/// Per-scan context passed to every ecosystem call. Carries the local
/// action store path, whether network is allowed, and (when present) the
/// Octocrab handle for tag/release lookups. The HTTP client is optional
/// because dry-run mode against fixture repos may skip it.
#[derive(Debug, Default)]
pub struct EcosystemContext {
    /// Local offline action store (`.assay/actions`) for SHA resolution.
    pub action_store: Option<PathBuf>,
    /// Whether the run is allowed to make network calls. When `false`,
    /// proposers must produce best-effort offline results and classify
    /// the proposal as `simulated` rather than `exact`.
    pub allow_network: bool,
}

/// The trait an ecosystem must implement to participate in the
/// scan/propose/validate/apply pipeline.
pub trait DependencyEcosystem: Send + Sync {
    /// Short, stable name. Returned by `EcosystemName::as_str`.
    fn name(&self) -> &'static str;

    /// Walk the repo for dependency manifests this ecosystem owns.
    fn detect_manifests(&self, repo: &Path) -> Result<Vec<Manifest>>;

    /// Given every manifest this ecosystem detected for the repo, produce
    /// zero or more bump proposals.
    ///
    /// Takes all manifests at once because some ecosystems (Cargo) resolve
    /// the whole workspace in a single call to their package manager. Per-
    /// manifest proposers would re-run the resolver N times for no benefit.
    fn propose_updates(
        &self,
        manifests: &[Manifest],
        repo: &Path,
        ctx: &EcosystemContext,
    ) -> Result<Vec<Proposal>>;

    /// Identify the workflow files this proposal should be validated
    /// against (the "gate" — what counts as 'this passes'). Returned paths
    /// are workspace-relative.
    ///
    /// Renamed from `affected_workflows` per Arch-11 in the deep-plan's
    /// Review Pass 1: "affected" suggested these workflows were touched
    /// BY the proposal, but they're actually the proposal's gate.
    fn gate_workflows(&self, proposal: &Proposal, repo: &Path) -> Result<Vec<PathBuf>>;

    /// Identify which workspace members consume the proposal's subject
    /// (i.e. depend on the bumped crate, package, etc).
    ///
    /// The Reporter filters per-consumer rows to only members in this
    /// list, so a Cargo workspace where 3 of 50 members use `serde`
    /// produces a 3-row report for a `serde` bump.
    ///
    /// Returns an empty `Vec` for ecosystems without a workspace-member
    /// axis (and for non-workspace Cargo projects) — the Reporter
    /// collapses to a flat single-project report when no consumer axis
    /// is meaningful.
    ///
    /// Cargo's impl walks `cargo metadata` (lands in Commit F); GHA
    /// returns empty in v1.
    fn affected_consumers(&self, proposal: &Proposal, tree: &Path) -> Result<Vec<ConsumerId>>;

    /// Apply the proposal to a working tree (typically a tempdir clone).
    /// The implementation owns whatever ecosystem-specific writes that
    /// entails (rewriting `Cargo.lock`, mutating `uses:` SHAs, etc.).
    fn apply_proposal(&self, proposal: &Proposal, tree_path: &Path) -> Result<()>;

    /// Apply multiple proposals against the **same** sandbox tree.
    ///
    /// The default impl loops [`apply_proposal`] in order. Each ecosystem's
    /// per-proposal apply is assumed to compose additively against a tree
    /// that already contains earlier proposals' edits (cargo widens
    /// constraints in distinct crate names and re-runs `cargo update`; npm
    /// snapshot-restores `package.json` only for the LockfileOnly path so
    /// chained Compatible/Breaking widenings survive; GHA rewrites
    /// `uses:@SHA` refs that are addressed by name and don't collide).
    ///
    /// This is the core of the multi-proposal merge applier — `--apply-local`
    /// and `--apply-pr` use it to produce a single sandbox whose state
    /// reflects ALL validated greens at once, defeating the prior
    /// last-write-wins copy-back semantic.
    ///
    /// Ecosystems can override for efficiency (e.g. defer
    /// `cargo update --workspace` to once at the end).
    fn apply_merged(&self, proposals: &[&Proposal], tree_path: &Path) -> Result<()> {
        for proposal in proposals {
            self.apply_proposal(proposal, tree_path)?;
        }
        Ok(())
    }

    /// Reports whether per-proposal sandboxes are guaranteed byte-equivalent
    /// to a fresh merged-sandbox apply for `proposals`. When true, the
    /// orchestrator skips the (otherwise expensive) merge-sandbox + revalidate
    /// dance and copies back from one of the existing per-proposal sandboxes
    /// — they're all the same shape anyway.
    ///
    /// Default: false (always merge — safe everywhere). Cargo overrides to
    /// `true` when every proposal in the set is [`BumpTier::LockfileOnly`]
    /// because `cargo update --workspace` is deterministic and comprehensive:
    /// every per-proposal sandbox lands on the same `Cargo.lock`, and no
    /// proposal touches `Cargo.toml`, so last-write-wins is byte-correct.
    fn merge_is_redundant(&self, _proposals: &[&Proposal]) -> bool {
        false
    }

    /// Copy the validated change-set from `sandbox` to `host`, returning
    /// the host-relative paths assay modified (suitable for `git add`).
    ///
    /// Per Arch-5 in the plan, the validated sandbox state is **copied
    /// back** to the operator's tree rather than re-derived. This avoids
    /// non-determinism from registry state or upstream metadata changing
    /// between sandbox-apply and host-apply.
    ///
    /// Ecosystems are responsible for refusing mid-flight host edits that
    /// would invalidate the copy-back. GHA uses its existing `from`
    /// mismatch defense (`rewrite_uses_in_workflow` errors if the host
    /// file no longer contains `<subject>@<from>`); Cargo has no such
    /// concern because `Cargo.lock` is regenerable, not a contract.
    fn copy_back(&self, proposal: &Proposal, sandbox: &Path, host: &Path) -> Result<Vec<PathBuf>>;

    /// Copy a merged sandbox's accumulated change-set back to host.
    ///
    /// Default impl runs [`copy_back`] per proposal in order and dedups
    /// returned paths. Ecosystems whose `copy_back` ships bulk artifacts
    /// (cargo: whole `Cargo.lock` + workspace manifests; npm: whole
    /// `package.json` + lockfile) override to copy ONCE — calling the
    /// per-proposal copy_back loop on a merged sandbox would just shuffle
    /// the same bytes N times. Ecosystems whose `copy_back` is a per-
    /// proposal rewrite of the host (GHA, with its `from`-mismatch defense
    /// for each `uses:@SHA`) inherit the default safely.
    fn copy_back_merged(
        &self,
        proposals: &[&Proposal],
        sandbox: &Path,
        host: &Path,
    ) -> Result<Vec<PathBuf>> {
        let mut paths: Vec<PathBuf> = Vec::new();
        for proposal in proposals {
            let modified = self.copy_back(proposal, sandbox, host)?;
            for m in modified {
                if !paths.contains(&m) {
                    paths.push(m);
                }
            }
        }
        Ok(paths)
    }

    /// Render an ecosystem-specific fragment for the PR body. Result is
    /// already sanitized (the ecosystem is responsible for routing any
    /// upstream-supplied strings through `sanitize::*` first).
    fn pr_body_fragment(&self, proposal: &Proposal, outcome: &ValidationOutcome) -> String;
}

/// Return the v1 default ecosystem registry. Order matters — scanner
/// dispatches in this order, so receipts come out deterministically.
pub fn default_registry() -> Vec<Box<dyn DependencyEcosystem>> {
    vec![
        Box::new(cargo::CargoEcosystem),
        Box::new(github_actions::GitHubActionsEcosystem),
        Box::new(npm::NpmEcosystem),
    ]
}
