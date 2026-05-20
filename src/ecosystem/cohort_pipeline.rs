//! Shared cohort-pipeline helpers used by both the npm and cargo
//! ecosystems.
//!
//! - [`widen_cohort_tiers`] elevates every cohort member's
//!   `bump_tier` to the cohort's max tier when ≥2 members appear
//!   in the same proposal set. Pure mutation pass on
//!   `Proposal.cohort` + `Proposal.bump_tier` — ecosystem-agnostic.
//! - [`tier_severity`] is the ordering helper backing the
//!   widening. Kept as a local utility (rather than `impl Ord on
//!   BumpTier`) so the public enum stays free of implicit
//!   ordering semantics.
//!
//! Both functions are `pub(crate)` because they're consumed only
//! by the per-ecosystem proposer pipelines and not part of the
//! public 1.0 stability surface.

use crate::model::{BumpTier, Proposal};

/// Multi-cohort lockstep tier widening. When two or more proposals
/// share a cohort id, the lockstep nature of family upgrades
/// (e.g. `@angular/core` + `@angular/common` must move together;
/// `tokio` + `tokio-util` must share major) means the *effective*
/// tier of every member is the most invasive tier among them. A
/// `tokio` Breaking bump bundled with a `tokio-util` Compatible
/// bump can NOT be applied as "Compatible for util, Breaking for
/// core" — cargo would resolve the lockfile but compilation
/// against the wrong macro/ABI surface would still break the
/// build.
///
/// This function raises each lockstep member's `bump_tier` to the
/// cohort's max tier (Breaking > Compatible > LockfileOnly) so
/// that downstream gating, reporting, and apply decisions treat
/// the whole group consistently. Members already at the max tier
/// are untouched. Widened members get a structured note
/// (`cohort-lockstep: widened from <orig> to <max> to match
/// <cohort>`) so the operator can see at a glance why a normally
/// Compatible bump is being flagged as Breaking.
///
/// Single-member cohorts are NOT widened — there is no lockstep
/// to enforce when only one member is in scope. The function is a
/// no-op on proposal sets without cohorts.
///
/// Order of operations matters: this MUST run AFTER the per-
/// ecosystem `tag_proposals_with_cohorts` step (so `cohort` is
/// populated) and BEFORE any ecosystem-specific note-attaching
/// pass (e.g. npm's `annotate_proposals_with_overrides`) so the
/// widening note appears alongside override notes rather than
/// being shoved aside by a later mutation pass.
pub(crate) fn widen_cohort_tiers(proposals: &mut [Proposal]) {
    use std::collections::BTreeMap;

    let mut max_tier_by_cohort: BTreeMap<String, BumpTier> = BTreeMap::new();
    let mut cohort_member_count: BTreeMap<String, usize> = BTreeMap::new();
    for p in proposals.iter() {
        let Some(cohort) = p.cohort.as_deref() else {
            continue;
        };
        *cohort_member_count.entry(cohort.to_string()).or_insert(0) += 1;
        let entry = max_tier_by_cohort
            .entry(cohort.to_string())
            .or_insert(BumpTier::LockfileOnly);
        if tier_severity(p.bump_tier) > tier_severity(*entry) {
            *entry = p.bump_tier;
        }
    }
    for p in proposals.iter_mut() {
        let Some(cohort) = p.cohort.as_deref() else {
            continue;
        };
        let count = cohort_member_count.get(cohort).copied().unwrap_or(0);
        if count < 2 {
            continue;
        }
        let max = max_tier_by_cohort
            .get(cohort)
            .copied()
            .unwrap_or(BumpTier::LockfileOnly);
        if tier_severity(max) > tier_severity(p.bump_tier) {
            let orig = p.bump_tier;
            p.bump_tier = max;
            p.notes.push(format!(
                "cohort-lockstep: widened from {} to {} to match {} (lockstep with {} member{})",
                orig.as_str(),
                max.as_str(),
                cohort,
                count,
                if count == 1 { "" } else { "s" }
            ));
        }
    }
}

/// Severity ranking for [`BumpTier`] — higher = more invasive.
/// Used by cohort lockstep widening to pick the dominant tier
/// across cohort members. Kept as a local helper rather than
/// `impl Ord` on `BumpTier` so the public enum stays free of
/// implicit ordering semantics (a future tier reorder would
/// otherwise silently change behavior).
fn tier_severity(t: BumpTier) -> u8 {
    match t {
        BumpTier::LockfileOnly => 0,
        BumpTier::Compatible => 1,
        BumpTier::Breaking => 2,
    }
}
