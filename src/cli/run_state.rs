//! Cross-module data carriers used by the analyze pipeline.
//!
//! These types thread through the orchestrator (`mod.rs`), the
//! reporter ([`super::reporting`]), and the apply pipelines
//! ([`super::apply_local`], [`super::apply_pr`]). Keeping them in one
//! module keeps the import graph tidy — every consumer pulls from
//! `super::run_state` rather than tunnelling through the orchestrator
//! file.

use std::path::PathBuf;

use crate::model::{Proposal, ProvenanceRecord};

/// One unit dispatched to the worker pool — a single (ecosystem, proposal)
/// pair. Workers pull these and run apply + validate sequentially.
pub(super) struct WorkUnit {
    pub(super) eco_idx: usize,
    /// Cached for the worker pool's per-ecosystem semaphore lookup.
    pub(super) ecosystem_name: &'static str,
    pub(super) proposal: Proposal,
    /// Cohort lockstep siblings to apply atomically alongside
    /// `proposal`. Empty for stand-alone proposals (the common case).
    /// When non-empty this unit represents a multi-member cohort
    /// (`@angular/*`, `@tiptap/*`, etc.) — the worker applies
    /// `proposal` + every member to the SAME sandbox via
    /// `apply_merged`, validates once, and the aggregator expands
    /// the shared outcome into one `ProposalRun` per member. This
    /// prevents partial-cohort applies (e.g. `@angular/core@22`
    /// without `@angular/common@22`, which pnpm/npm would refuse to
    /// resolve).
    pub(super) lockstep_members: Vec<Proposal>,
    /// The scan_root this proposal originated from. For Tauri-style
    /// polyglot layouts, sibling ecosystems live in different
    /// subdirectories under the artifact root — apply/validate must
    /// run inside the scan_root, not against the artifact root.
    pub(super) scan_root: PathBuf,
}

/// What a worker thread produces for one [`WorkUnit`].
///
/// `eco_idx` and `proposal` are carried on the failure variants for
/// future error-reporting that wants to address the failed proposal by
/// id. The current aggregator only reads them via the structural match
/// in `analyze_command`, so allow the dead-code lint here.
///
/// The `Completed` variant carries a `ValidationOutcome` (large struct
/// with provenance vectors) while the failure variants are smaller; the
/// `large_enum_variant` clippy lint flags the size disparity but
/// boxing every variant would muddy the call sites and the enum is
/// only ever held on one thread at a time. Allow the lint.
#[allow(dead_code, clippy::large_enum_variant)]
#[derive(Debug)]
pub(super) enum WorkerOutcome {
    /// Apply tree preparation or `apply_proposal` failed before validation
    /// could run.
    PreValidationFailure {
        eco_idx: usize,
        proposal: Proposal,
        provenance: Vec<ProvenanceRecord>,
        /// One-line reason carried separately from the provenance
        /// records so the reporter can render per-failed-proposal
        /// detail without scanning the provenance trail.
        summary: String,
    },
    /// Validator couldn't run at all (e.g. forge not on PATH AND no
    /// recognized manifest).
    ValidatorErrored {
        eco_idx: usize,
        proposal: Proposal,
        provenance: Vec<ProvenanceRecord>,
        summary: String,
    },
    /// Pipeline completed with a real validation outcome.
    Completed {
        eco_idx: usize,
        proposal: Proposal,
        sandbox: PathBuf,
        outcome: crate::model::ValidationOutcome,
        provenance: Vec<ProvenanceRecord>,
        /// Forwarded from the input `WorkUnit` so the merge planner can
        /// group by (eco_idx, scan_root) when proposals come from
        /// multiple sub-projects (Tauri polyglot).
        scan_root: PathBuf,
    },
    /// All members of a multi-member cohort group validated together
    /// in ONE sandbox. The shared `outcome` applies atomically to
    /// every proposal in `members` (primary + lockstep siblings).
    /// The aggregator expands this into one `ProposalRun` per
    /// member; the merger detects the shared-sandbox signature and
    /// skips redundant re-merge, and the bisect step treats the
    /// cohort as one drop unit so partial applies are impossible.
    CohortCompleted {
        eco_idx: usize,
        /// All cohort members (primary + siblings) in deterministic
        /// order. Every entry shares `sandbox` and `outcome`.
        members: Vec<Proposal>,
        sandbox: PathBuf,
        outcome: crate::model::ValidationOutcome,
        provenance: Vec<ProvenanceRecord>,
        scan_root: PathBuf,
    },
}

/// One proposal's full lifecycle through the apply-local pipeline:
/// applier produced a sandbox tree, validator scored it. Held in memory
/// until the post-loop commit phase decides whether to copy-back.
#[derive(Clone)]
pub(super) struct ProposalRun {
    pub(super) eco_idx: usize,
    pub(super) proposal: Proposal,
    pub(super) sandbox: PathBuf,
    pub(super) outcome: crate::model::ValidationOutcome,
    /// Where this proposal's manifest lived on the host. Threaded
    /// into the merge planner so copy-back lands in the right
    /// sub-project tree (Tauri polyglot: cargo proposals go back to
    /// `src-tauri`, npm proposals to `ui`).
    pub(super) scan_root: PathBuf,
}

/// Per-proposal apply-stage failure row, surfaced alongside
/// [`ProposalRun`]-tracked validation failures so the reporter can
/// render "why" details for both.
#[derive(Debug)]
pub(super) struct PreValidationFailureRow {
    #[allow(dead_code)]
    pub(super) eco_idx: usize,
    pub(super) proposal: Proposal,
    pub(super) summary: String,
}

/// What happened during the post-validation `--apply-local` commit phase.
#[derive(Debug)]
pub(super) enum CommitSummary {
    /// At least one proposal validated green individually AND survived
    /// the merge step. The atomic commit captures whatever the merge
    /// step shipped (which may exclude individually-green proposals
    /// the merge step had to drop — see `merged_drops`).
    Committed {
        bump_count: usize,
        paths: Vec<PathBuf>,
        subject: String,
        /// Individually-green proposals that the merge step dropped
        /// because including them turned the merged validation red.
        /// The commit ships the largest subset that greened.
        merged_drops: Vec<MergedDropInfo>,
    },
    /// One or more proposals didn't validate green individually; refusing
    /// to commit preserves the "atomic, all-individually-green" precondition
    /// of `--apply-local`.
    SkippedDueToFailures { red_count: usize, total: usize },
    /// Every individually-green proposal was dropped by the merge step —
    /// no subset of the greens validated together. Nothing to commit but
    /// the per-proposal greens are visible in the receipt and the operator
    /// can split into smaller batches.
    AllDroppedByMerge { drops: Vec<MergedDropInfo> },
    /// No proposals reached validation cleanly — nothing to commit.
    NothingToCommit,
}

/// Receipt-friendly view of a merge-step drop.
#[derive(Debug, Clone)]
pub(crate) struct MergedDropInfo {
    pub proposal_id: String,
    pub reason: String,
}

/// Outcome of `--apply-pr` orchestration.
#[derive(Debug)]
pub(super) enum ApplyPrSummary {
    Published {
        url: String,
        branch: String,
        bump_count: usize,
        merged_drops: Vec<MergedDropInfo>,
    },
    SkippedDueToFailures {
        red_count: usize,
        total: usize,
    },
    /// Every individually-green proposal was dropped by the merge step.
    AllDroppedByMerge {
        drops: Vec<MergedDropInfo>,
    },
    NothingToPublish,
}
