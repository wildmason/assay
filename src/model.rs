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
    /// `package.json` — npm / pnpm / yarn root or workspace member.
    PackageJson,
    /// Any of `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`.
    NpmLockfile,
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

/// Upgrade-impact tier for a version-bump proposal.
///
/// Distinct from [`Classification`] (which describes how *closely* the
/// validator matches the upstream contract). This describes how *invasive*
/// the bump is to the operator's manifest — and therefore which mode of
/// auto-apply, if any, is safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum BumpTier {
    /// Bump happens entirely within the current constraint. Cargo.lock
    /// changes; manifest doesn't. `cargo update` is sufficient. This is
    /// what `cargo update --dry-run` surfaces today, and the only tier
    /// assay's v1 auto-applies.
    #[default]
    LockfileOnly,
    /// Newest available version is outside the current constraint but
    /// stays within the current semver-major. Bumping requires a manifest
    /// edit (e.g. relaxing `=1.40.5` to `^1.40.5`, or widening `~1.40` to
    /// `^1.40`). Non-breaking by semver contract, but the operator
    /// explicitly pinned the scope so the edit is reported, not applied.
    Compatible,
    /// Newest available version crosses a semver-major boundary
    /// (`^1.40` → `2.0.0`). Bumping requires a manifest edit AND is
    /// breaking-by-spec. Reported only — operator handles the upgrade.
    Breaking,
}

impl BumpTier {
    pub fn as_str(self) -> &'static str {
        match self {
            BumpTier::LockfileOnly => "lockfile-only",
            BumpTier::Compatible => "compatible",
            BumpTier::Breaking => "breaking",
        }
    }
}

/// Structured explanation for *why* a proposal's [`BumpTier`] was chosen.
///
/// Populated by the proposer when `--explain` is set so the operator can
/// audit the classifier's verdict without re-running the analysis with
/// debug logging. The reporter surfaces this inline beneath each
/// proposal in the text format and inlines it in the JSON format.
///
/// Lives on [`Proposal`] as `Option<BumpExplanation>` — `None` keeps
/// receipt size flat when the operator didn't ask for explanations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BumpExplanation {
    /// One-line, prose summary suitable for inline display (e.g.
    /// "same major version, manifest pin keeps cargo from bumping
    /// — Compatible").
    pub summary: String,
    /// Stable rule identifier. Useful for filtering / scripting (e.g.
    /// `cargo:caret-major-1-plus`, `gha:ref-shape-loosening`,
    /// `lockfile-within-constraint`).
    pub rule: String,
    /// Structured inputs that drove the decision. Lets a future
    /// `--format json` consumer reason about classifier output without
    /// re-parsing the prose summary. BTreeMap so ordering is stable
    /// across receipts.
    pub inputs: BTreeMap<String, String>,
    /// The classifier's verdict in human prose (e.g. "Compatible" /
    /// "Breaking" / "LockfileOnly"). Matches `BumpTier::as_str()`
    /// values verbatim.
    pub decision: String,
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
    /// How invasive the bump is — drives whether assay auto-applies it.
    /// `#[serde(default)]` so receipts written before this field existed
    /// still deserialize cleanly with `LockfileOnly`.
    #[serde(default)]
    pub bump_tier: BumpTier,
    /// Workspace members that directly declare the proposal's subject
    /// as a dependency. For a 47-member monorepo where only 3 crates
    /// consume the upgraded dep, this captures the "blast radius" the
    /// operator needs to know — a bump's impact is bounded to its
    /// consumers, not the whole workspace. Populated by the proposer
    /// pipeline via `DependencyEcosystem::affected_consumers`.
    /// `#[serde(default)]` for receipt back-compat with older runs.
    #[serde(default)]
    pub affected_consumers: Vec<ConsumerId>,
    /// Structured "why this tier" explanation. Populated only when
    /// `--explain` is set on the CLI; `None` otherwise. `#[serde(default)]`
    /// so receipts written before `--explain` shipped still
    /// deserialize cleanly.
    #[serde(default)]
    pub explanation: Option<BumpExplanation>,
    /// Framework cohort this proposal belongs to (`@angular/*`,
    /// `@tiptap/*`, `next + @next/*`, etc.). When set, all proposals
    /// sharing this cohort id MUST move together — they're treated as
    /// a single atomic apply unit by the validator + applier, and the
    /// reporter groups them under one cohort header. `None` for
    /// stand-alone proposals. `#[serde(default)]` for receipt
    /// back-compat with pre-cohort runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cohort: Option<String>,
}

/// Diagnostic detail captured when a validator backend fails on a
/// workflow (or tree-mode invocation). Persisted on
/// [`ValidationOutcome::failure_details`] so the run.json receipt + the
/// human reporter can both show *why* validation failed without making
/// the operator dig into sandbox logs.
///
/// Mirrors `WorkflowOutcome` (in `crate::validator`) at the persistent
/// boundary — the in-memory shape carries a `FailureFlavor` enum + a
/// `log_path` to a tempdir; this serde-stable shape carries the flavor
/// as a plain string and drops `log_path` since the validator's
/// per-workflow tempdir is cleaned up before the receipt is written.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureDetail {
    /// Workflow path (or sentinel `<tree:<backend>>` for tree-mode
    /// backends like BuildTest and Custom).
    pub workflow: PathBuf,
    /// Backend that produced this detail (`forge-run`, `build-test`,
    /// `custom`).
    pub backend: String,
    /// Short flavor label — one of `REGRESSION`, `SETUP-FAILURE`,
    /// `TIMEOUT`. Plain string for receipt forward-compat.
    pub flavor: String,
    /// Last bytes of captured stderr (UTF-8-boundary-safe truncation at
    /// 4 KB by the existing `stderr_tail` helper in the validator).
    pub stderr_tail: String,
    /// Subprocess wall-clock duration in milliseconds.
    pub duration_ms: u128,
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
    /// Per-failed-workflow detail — populated when `conclusion` is
    /// anything other than `"success"`. `#[serde(default)]` so receipts
    /// written before this field existed still deserialize cleanly.
    #[serde(default)]
    pub failure_details: Vec<FailureDetail>,
    /// Number of per-workflow validations served from the verdict cache
    /// rather than freshly executed. Defaults to 0 for back-compat with
    /// receipts written before the cache existed.
    #[serde(default)]
    pub cached_workflow_count: usize,
    /// Total number of per-workflow validations attempted (cached +
    /// fresh). Defaults to 0 for back-compat; older receipts can recover
    /// this from `validated_workflows.len()`.
    #[serde(default)]
    pub total_workflow_count: usize,
    /// Number of gate workflows the member-precise filter dropped
    /// before this proposal entered the validator. Non-zero only
    /// when `--member-gate` is set AND at least one workflow named
    /// only non-affected members. Defaults to 0 for back-compat.
    #[serde(default)]
    pub member_skipped_workflow_count: usize,
}

/// Current on-disk schema version stamped into every
/// [`AssayRunReceipt`]. Bump only on **breaking** changes; additive
/// fields with `#[serde(default)]` (cached_workflow_count,
/// total_workflow_count, member_skipped_workflow_count, etc.) are
/// back-compatible across the same major schema version.
pub const CURRENT_RECEIPT_SCHEMA_VERSION: u32 = 1;

fn default_receipt_schema_version() -> u32 {
    CURRENT_RECEIPT_SCHEMA_VERSION
}

/// Top-level run receipt written to `.assay/runs/<run-id>/run.json`.
///
/// Schema-compatible with ci-forge's `RunStoreReceipt` envelope at the
/// `provenance.records[]` level — the index loader for `.assay/runs/` can
/// read this file too once the shared loader lands.
///
/// `schema_version` is stamped at write time from
/// [`CURRENT_RECEIPT_SCHEMA_VERSION`]. Consumers should compare against
/// that constant when reading older receipts to know what optional
/// fields to expect; `#[serde(default)]` on the field keeps
/// hypothetical pre-versioning receipts parseable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssayRunReceipt {
    #[serde(default = "default_receipt_schema_version")]
    pub schema_version: u32,
    pub run_id: String,
    pub started_at: String,
    pub finished_at: String,
    pub repository: RepositoryRef,
    /// Reproducibility context: tool version, CLI args, OS/arch.
    /// `#[serde(default, skip_serializing_if = "Option::is_none")]` for
    /// receipt back-compat — receipts written before this field
    /// existed parse without it; receipts where the context wasn't
    /// captured serialize without the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_context: Option<RunContext>,
    /// Aggregate counts for quick scanning.
    pub summary: RunSummary,
    /// One record per pipeline stage outcome.
    pub provenance: Provenance,
}

/// Reproducibility metadata captured at the top of each run.
///
/// Lifted to top-level so a CI consumer scanning receipts for "what
/// version + on which machine" doesn't have to walk every provenance
/// record (each carries `tool` + `version` redundantly today). The
/// dogfood feedback called out missing `cli_args` / `host` for
/// reproducibility audits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunContext {
    /// Exact CLI argv that produced this receipt, including the
    /// subcommand and all flags. First element is the binary path
    /// (resolved by the shell).
    pub cli_args: Vec<String>,
    /// `CARGO_PKG_VERSION` of the assay binary that produced the
    /// receipt. Duplicates the per-record `version` field for fast
    /// top-level access.
    pub tool_version: String,
    /// `os` / `arch` keys (`linux`/`macos`/`windows` × `x86_64`/
    /// `aarch64`). Other keys reserved for future host facts.
    pub host: BTreeMap<String, String>,
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
    /// Proposals whose [`BumpTier`] short-circuited apply/validate
    /// (Compatible or Breaking). Surfaces the helm-style 110-deps-
    /// behind-latest gap. `#[serde(default)]` for receipt back-compat.
    #[serde(default)]
    pub proposals_discovered: usize,
    /// Proposals that greened individually but were dropped by the
    /// multi-proposal merge applier because including them in the
    /// merged ship turned the merged-set validation red. Always
    /// `proposals_shipped + proposals_merged_dropped == proposals_passed`.
    /// `#[serde(default)]` for receipt back-compat.
    #[serde(default)]
    pub proposals_merged_dropped: usize,
    /// Proposals that landed in the resulting commit (apply-local) or
    /// pushed branch (apply-pr). `#[serde(default)]` for back-compat.
    #[serde(default)]
    pub proposals_shipped: usize,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposal_without_bump_tier_field_deserializes_as_lockfile_only() {
        // Receipts written before the BumpTier field existed must still
        // round-trip — defending the on-disk format compatibility promise.
        let legacy_json = r#"{
            "id": "cargo-serde-1-0-215",
            "ecosystem": "cargo",
            "kind": "version",
            "subject": "serde",
            "from": "1.0.200",
            "to": "1.0.215",
            "initial_classification": "exact",
            "manifest_paths": [],
            "notes": []
        }"#;
        let proposal: Proposal = serde_json::from_str(legacy_json)
            .expect("legacy receipt without bump_tier should still parse");
        assert_eq!(proposal.bump_tier, BumpTier::LockfileOnly);
    }

    #[test]
    fn proposal_without_explanation_field_deserializes_as_none() {
        // Receipts written before --explain shipped must still parse;
        // bump_tier exists in the receipt but explanation does not.
        let legacy_json = r#"{
            "id": "cargo-serde-1-0-228",
            "ecosystem": "cargo",
            "kind": "version",
            "subject": "serde",
            "from": "1.0.100",
            "to": "1.0.228",
            "initial_classification": "exact",
            "manifest_paths": [],
            "notes": [],
            "bump_tier": "compatible"
        }"#;
        let proposal: Proposal = serde_json::from_str(legacy_json)
            .expect("legacy receipt without explanation should still parse");
        assert!(proposal.explanation.is_none());
    }

    #[test]
    fn bump_explanation_round_trips_through_serde() {
        let mut inputs = BTreeMap::new();
        inputs.insert("from_major".into(), "1".into());
        inputs.insert("to_major".into(), "1".into());
        let exp = BumpExplanation {
            summary: "same major, manifest pin keeps cargo from bumping".into(),
            rule: "cargo:caret-major-1-plus".into(),
            inputs,
            decision: "compatible".into(),
        };
        let json = serde_json::to_string(&exp).unwrap();
        let back: BumpExplanation = serde_json::from_str(&json).unwrap();
        assert_eq!(back, exp);
    }

    #[test]
    fn proposal_with_explanation_round_trips() {
        let mut inputs = BTreeMap::new();
        inputs.insert("from_tag".into(), "v3.5.2".into());
        inputs.insert("to_tag".into(), "v4.0.0".into());
        let exp = BumpExplanation {
            summary: "actions: major version changed".into(),
            rule: "gha:major-bump".into(),
            inputs,
            decision: "breaking".into(),
        };
        let proposal = Proposal {
            id: "gha-actions-checkout-v4".into(),
            ecosystem: "github-actions".into(),
            kind: ProposalKind::ActionPin,
            subject: "actions/checkout".into(),
            from: "v3.5.2".into(),
            to: "v4.0.0".into(),
            initial_classification: Classification::Exact,
            manifest_paths: vec![],
            notes: vec![],
            bump_tier: BumpTier::Breaking,
            affected_consumers: vec![],
            explanation: Some(exp.clone()),
            cohort: None,
        };
        let json = serde_json::to_string(&proposal).unwrap();
        let back: Proposal = serde_json::from_str(&json).unwrap();
        assert_eq!(back.explanation, Some(exp));
    }

    #[test]
    fn receipt_stamps_current_schema_version_when_serialized() {
        let receipt = AssayRunReceipt {
            schema_version: CURRENT_RECEIPT_SCHEMA_VERSION,
            run_id: "assay-test".into(),
            started_at: "2026-05-19T00:00:00Z".into(),
            finished_at: "2026-05-19T00:00:01Z".into(),
            repository: RepositoryRef {
                path: PathBuf::from("/tmp/x"),
                github: None,
                git_ref: None,
            },
            run_context: None,
            summary: RunSummary::default(),
            provenance: Provenance { records: vec![] },
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.get("schema_version").and_then(|v| v.as_u64()),
            Some(CURRENT_RECEIPT_SCHEMA_VERSION as u64),
            "receipt must carry the current schema_version on disk"
        );
    }

    #[test]
    fn receipt_without_schema_version_defaults_to_current() {
        // A receipt written before schema_version was a field (hypothetical
        // pre-versioning past) MUST still parse — serde defaults to the
        // current constant via `default_receipt_schema_version`.
        let legacy_json = r#"{
            "run_id": "assay-legacy",
            "started_at": "2026-05-19T00:00:00Z",
            "finished_at": "2026-05-19T00:00:01Z",
            "repository": { "path": "/tmp/x" },
            "summary": {
                "manifests_scanned": 0,
                "proposals_total": 0,
                "proposals_passed": 0,
                "proposals_failed": 0,
                "proposals_unvalidated": 0,
                "prs_opened": 0
            },
            "provenance": { "records": [] }
        }"#;
        let receipt: AssayRunReceipt = serde_json::from_str(legacy_json)
            .expect("legacy receipt without schema_version should parse");
        assert_eq!(receipt.schema_version, CURRENT_RECEIPT_SCHEMA_VERSION);
    }

    #[test]
    fn receipt_round_trips_with_legacy_schema_version() {
        // A receipt carrying an explicit older `schema_version` is
        // preserved verbatim on read — consumers can detect the drift.
        let receipt = AssayRunReceipt {
            schema_version: 0, // hypothetical legacy
            run_id: "assay-legacy".into(),
            started_at: "2026-05-19T00:00:00Z".into(),
            finished_at: "2026-05-19T00:00:01Z".into(),
            repository: RepositoryRef {
                path: PathBuf::from("/tmp/x"),
                github: None,
                git_ref: None,
            },
            run_context: None,
            summary: RunSummary::default(),
            provenance: Provenance { records: vec![] },
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let back: AssayRunReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schema_version, 0);
    }

    #[test]
    fn bump_tier_serializes_with_kebab_case_strings() {
        // The .as_str() helper and the serde wire format must agree —
        // both are read by the reporter, and divergence would silently
        // break grouping.
        for (tier, wire) in [
            (BumpTier::LockfileOnly, "lockfile-only"),
            (BumpTier::Compatible, "compatible"),
            (BumpTier::Breaking, "breaking"),
        ] {
            assert_eq!(tier.as_str(), wire);
            let json = serde_json::to_string(&tier).unwrap();
            assert_eq!(json, format!("\"{wire}\""));
        }
    }
}
