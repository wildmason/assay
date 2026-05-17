//! `DependencyEcosystem` trait + per-ecosystem implementations.
//!
//! v1 ships two real implementations (Cargo, GitHub Actions). The two-impl
//! rule is satisfied, so the trait is a real abstraction rather than
//! ceremony.

use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::model::{Manifest, Proposal, ValidationOutcome};

pub mod cargo;
pub mod github_actions;

/// Identifies an ecosystem by short name. Matches the string stored on
/// `Proposal.ecosystem` so the receipt index can group by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcosystemName {
    Cargo,
    GitHubActions,
}

impl EcosystemName {
    pub fn as_str(self) -> &'static str {
        match self {
            EcosystemName::Cargo => "cargo",
            EcosystemName::GitHubActions => "github-actions",
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

    /// Identify the workflow files that should validate this proposal.
    /// Returned paths are workspace-relative.
    fn affected_workflows(&self, proposal: &Proposal, repo: &Path) -> Result<Vec<PathBuf>>;

    /// Apply the proposal to a working tree (typically a tempdir clone).
    /// The implementation owns whatever ecosystem-specific writes that
    /// entails (rewriting `Cargo.lock`, mutating `uses:` SHAs, etc.).
    fn apply_proposal(&self, proposal: &Proposal, tree_path: &Path) -> Result<()>;

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
    ]
}
