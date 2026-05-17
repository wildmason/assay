use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Compatibility classification — mirrors ci-forge's vocabulary.
///
/// Used at the proposal, validation, and stage-receipt level. The same words
/// appear in `.assay/runs/<id>/run.json` provenance entries; reusing them
/// keeps the index loader symmetric across both stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Classification {
    /// Behavior matches the upstream contract for the tested surface.
    Exact,
    /// Operationally equivalent but documented difference.
    Compatible,
    /// Intentionally modeled outcome without executing the real path.
    Simulated,
    /// Workflow shape preserved without side effect.
    Stubbed,
    /// Refused / skipped with a clear receipt.
    Unsupported,
}

impl Classification {
    pub fn as_str(self) -> &'static str {
        match self {
            Classification::Exact => "exact",
            Classification::Compatible => "compatible",
            Classification::Simulated => "simulated",
            Classification::Stubbed => "stubbed",
            Classification::Unsupported => "unsupported",
        }
    }
}

/// Kind of manifest the Scanner detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManifestKind {
    CargoToml,
    CargoLock,
    WorkflowYaml,
    CompositeActionYaml,
}

/// A dependency manifest discovered by the Scanner. Each ecosystem returns
/// one or more `Manifest`s for the repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Workspace-relative path of the manifest file.
    pub path: PathBuf,
    pub kind: ManifestKind,
    /// Ecosystem-specific opaque blob (e.g. detected `[workspace.dependencies]`
    /// for Cargo, list of `uses:` references for GitHub Actions). Kept opaque
    /// to avoid leaking ecosystem internals into shared types.
    #[serde(default)]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

/// Identifies one workspace-member (consumer) in a workspace-rooted
/// analysis.
///
/// For Cargo: the member's package name (e.g. `"web-app"`, `"shared-lib"`).
/// For ecosystems without a workspace-member axis (GHA, single-project
/// Cargo): unused — the Resolver returns an empty `Vec`, and the
/// Reporter collapses to a flat single-project report.
pub type ConsumerId = String;

/// Kind of proposed change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProposalKind {
    /// Version bump for a dependency (Cargo, npm, etc.).
    Version,
    /// SHA-pin update for a GitHub Actions `uses:` reference.
    ActionPin,
}

/// A concrete dependency update proposed by an ecosystem's Proposer stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    /// Deterministic ID used in branch names and stage-receipt correlation.
    /// Format: `<ecosystem>-<short-hash-of-subject-from-to>`.
    pub id: String,
    /// Which ecosystem produced this proposal.
    pub ecosystem: String,
    pub kind: ProposalKind,
    /// Subject identifier (crate name, action `owner/repo`, etc.).
    pub subject: String,
    /// Version or SHA before the bump.
    pub from: String,
    /// Version or SHA after the bump.
    pub to: String,
    /// Initial classification at proposal time (before validation runs).
    pub initial_classification: Classification,
    /// Manifest paths the bump would write into.
    pub manifest_paths: Vec<PathBuf>,
    /// Free-form notes for the receipt and PR body.
    #[serde(default)]
    pub notes: Vec<String>,
}

/// Outcome of validating a proposal by running its affected workflows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationOutcome {
    pub proposal_id: String,
    /// Conclusion summary: `success`, `failure`, `cancelled`, or `unvalidated`.
    pub conclusion: String,
    /// ci-forge run id(s) of the underlying `forge run` invocation(s).
    /// Resolves to `.assay/runs/<id>/run.json` paths.
    #[serde(default)]
    pub ci_forge_run_ids: Vec<String>,
    /// Workflow path(s) that were validated.
    #[serde(default)]
    pub validated_workflows: Vec<PathBuf>,
    /// Final classification after validation (may downgrade from `initial`).
    pub classification: Classification,
    #[serde(default)]
    pub notes: Vec<String>,
}

/// Top-level run receipt written to `.assay/runs/<run-id>/run.json`.
///
/// Schema-compatible with ci-forge's `RunStoreReceipt` envelope at the
/// `provenance.records[]` level — the index loader for `.assay/runs/` can
/// read this file too once the shared loader lands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssayRunReceipt {
    pub schema_version: u32,
    pub run_id: String,
    pub started_at: String,
    pub finished_at: String,
    pub repository: RepositoryRef,
    /// Aggregate counts for quick scanning.
    pub summary: RunSummary,
    /// One record per pipeline stage outcome.
    pub provenance: Provenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryRef {
    pub path: PathBuf,
    /// Best-effort: `owner/name` if a GitHub remote can be detected, else absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github: Option<String>,
    /// Git ref (typically `main` or the current branch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RunSummary {
    pub manifests_scanned: usize,
    pub proposals_total: usize,
    pub proposals_passed: usize,
    pub proposals_failed: usize,
    pub proposals_unvalidated: usize,
    pub prs_opened: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Provenance {
    pub records: Vec<ProvenanceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    /// Tool identifier — always `assay` for now.
    pub tool: String,
    /// Tool version (CARGO_PKG_VERSION).
    pub version: String,
    /// Pipeline stage: `scanner`, `proposer`, `validator`, `applier`,
    /// `publisher`, or `receiptor`.
    pub stage: String,
    /// Subject identifier (manifest path, proposal id, etc.).
    pub subject: String,
    pub status: Classification,
    /// Short human-readable summary line.
    pub summary: String,
    /// Path of the per-stage receipt JSON, if any. Workspace-relative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<PathBuf>,
    /// Optional structured payload for stage-specific details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}
