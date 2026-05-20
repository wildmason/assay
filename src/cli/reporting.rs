//! Text-mode reporting helpers for `assay analyze`.
//!
//! The `analyze` orchestrator delegates every human-readable summary
//! line through this module. Splitting the rendering from the
//! orchestration code means future format work (alignment tweaks,
//! coloration, alternative summaries) doesn't have to thread through
//! the worker-pool driver.

use std::collections::BTreeSet;

use crate::failure_context::{FailureCluster, cluster_failures};
use crate::model::Proposal;

use super::run_state::{ApplyPrSummary, CommitSummary, PreValidationFailureRow, ProposalRun};

/// Maximum lines of captured stderr to render per failed proposal in
/// the human reporter. Anything past this gets a one-line truncation
/// marker so the operator knows there's more in the receipt.
const REPORTER_STDERR_LINE_LIMIT: usize = 12;

/// Returns `(lockfile_only, compatible, breaking)` counts from a stream of
/// proposals. Used by the text reporter to surface the tier breakdown
/// without re-walking the worker pool outcomes.
pub(super) fn tier_counts<'a>(
    proposals: impl IntoIterator<Item = &'a Proposal>,
) -> (usize, usize, usize) {
    use crate::model::BumpTier;
    let mut lockfile_only = 0usize;
    let mut compatible = 0usize;
    let mut breaking = 0usize;
    for proposal in proposals {
        match proposal.bump_tier {
            BumpTier::LockfileOnly => lockfile_only += 1,
            BumpTier::Compatible => compatible += 1,
            BumpTier::Breaking => breaking += 1,
        }
    }
    (lockfile_only, compatible, breaking)
}

/// Prints the per-tier upgrade table to stdout.
///
/// Format:
///
/// ```text
/// assay: per-tier upgrades:
///   compatible (within-major; manifest constraint widening applied):
///     cargo_metadata  0.18.1 -> 0.20.0
///   breaking (crosses semver-major; manifest edit applied):
///     serde  1.0.215 -> 2.0.0
/// ```
pub(super) fn print_discovered_section<'a>(proposals: impl IntoIterator<Item = &'a Proposal>) {
    use crate::model::BumpTier;
    let mut lockfile_only: Vec<&Proposal> = Vec::new();
    let mut compatible: Vec<&Proposal> = Vec::new();
    let mut breaking: Vec<&Proposal> = Vec::new();
    for p in proposals {
        match p.bump_tier {
            BumpTier::LockfileOnly => lockfile_only.push(p),
            BumpTier::Compatible => compatible.push(p),
            BumpTier::Breaking => breaking.push(p),
        }
    }
    // Lockfile-only is shown in the per-tier section only when it
    // carries at least one cohort — otherwise it stays collapsed into
    // the top-of-run "tier breakdown: N lockfile-only / ..." count to
    // keep single-package cargo runs lean. The dogfood (slate, aegis,
    // mortar) flagged 33-line @angular/* + @tiptap/* lockfile-only
    // walls; surfacing the cohort header as one line under
    // `lockfile-only:` is the dense-but-informative pivot.
    let lockfile_has_cohort = lockfile_only.iter().any(|p| p.cohort.is_some());
    if compatible.is_empty() && breaking.is_empty() && !lockfile_has_cohort {
        return;
    }
    println!("assay: per-tier upgrades:");
    let print_group = |label: &str, group: Vec<&Proposal>| {
        if group.is_empty() {
            return;
        }
        println!("  {label}:");
        print_group_with_cohorts(&group);
    };
    if lockfile_has_cohort {
        print_group("lockfile-only", lockfile_only);
    }
    print_group("compatible", compatible);
    print_group("breaking", breaking);
}

/// Render one tier-group with cohort awareness: cohort members
/// collapse into one header line plus a member list; stand-alones
/// render as-is. Stable ordering — cohorts first (alphabetical by id),
/// then stand-alones (alphabetical by subject). This keeps the dense
/// "@angular/* family" line at the top of a tier when an Angular
/// project has half a dozen lockfile-only minor bumps; previously the
/// reader had to mentally regroup them. See the 2026-05-20 dogfood
/// against slate/aegis/wildmason.dev where this gap surfaced 3×.
fn print_group_with_cohorts(group: &[&Proposal]) {
    use std::collections::BTreeMap;
    let mut by_cohort: BTreeMap<String, Vec<&Proposal>> = BTreeMap::new();
    let mut standalone: Vec<&Proposal> = Vec::new();
    for &p in group {
        match &p.cohort {
            Some(id) => by_cohort.entry(id.clone()).or_default().push(p),
            None => standalone.push(p),
        }
    }
    // Single-member cohorts (only one cohort package present in this
    // tier — e.g. `@angular/cdk` alone with no `@angular/material`)
    // render as stand-alone lines: a one-element cohort header
    // wrapping a single member is pure overhead and obscures the
    // version. Multi-member cohorts (the actual lockstep-bump value-
    // prop) get the cohort header.
    for (cohort_id, mut members) in by_cohort {
        members.sort_by(|a, b| a.subject.cmp(&b.subject));
        if members.len() == 1 {
            standalone.push(members.into_iter().next().unwrap());
        } else {
            print_cohort_block(&cohort_id, &members);
        }
    }
    standalone.sort_by(|a, b| a.subject.cmp(&b.subject));
    for p in standalone {
        print_single_proposal_line(p);
    }
}

/// Render a cohort group as a single header line plus an indented
/// member list. Shows the version range when members target
/// different versions (e.g. `@angular/cdk` lags `@angular/core` by 2
/// patches in some Angular releases) and a single version when they
/// all converge.
fn print_cohort_block(cohort_id: &str, members: &[&Proposal]) {
    let display = crate::ecosystem::npm_cohorts::KNOWN_COHORTS
        .iter()
        .find(|c| c.id == cohort_id)
        .map(|c| c.display)
        .unwrap_or(cohort_id);
    let from_versions: BTreeSet<&str> = members.iter().map(|p| p.from.as_str()).collect();
    let to_versions: BTreeSet<&str> = members.iter().map(|p| p.to.as_str()).collect();
    let from_str = format_version_set(&from_versions);
    let to_str = format_version_set(&to_versions);
    let n = members.len();
    let word = if n == 1 { "package" } else { "packages" };
    println!("    {display} cohort ({n} {word}, {from_str} -> {to_str}):");
    for p in members {
        let mut line = format!("      - {}", p.subject);
        // Only show per-member version when it diverges from the
        // group's range — otherwise the cohort header already covers
        // it and the per-member line is noise.
        if from_versions.len() > 1 || to_versions.len() > 1 {
            line.push_str(&format!("  {} -> {}", p.from, p.to));
        }
        if !p.notes.is_empty() {
            line.push_str(&format!("  [{}]", p.notes.join(", ")));
        }
        line.push_str(&format_consumers_suffix(&p.affected_consumers));
        println!("{line}");
        if let Some(exp) = &p.explanation {
            println!("        [{}] {}", exp.rule, exp.summary);
        }
    }
}

fn print_single_proposal_line(p: &Proposal) {
    let mut line = format!("    {}  {} -> {}", p.subject, p.from, p.to);
    if !p.notes.is_empty() {
        line.push_str(&format!("  [{}]", p.notes.join(", ")));
    }
    line.push_str(&format_consumers_suffix(&p.affected_consumers));
    println!("{line}");
    if let Some(exp) = &p.explanation {
        println!("      [{}] {}", exp.rule, exp.summary);
    }
}

/// Display a set of version strings as either a single value (when
/// everyone agrees) or a `min..max` range. Used by the cohort header
/// to show convergent vs divergent member versions in one line.
fn format_version_set(versions: &BTreeSet<&str>) -> String {
    let mut iter = versions.iter();
    let first = match iter.next() {
        Some(v) => *v,
        None => return String::new(),
    };
    if versions.len() == 1 {
        return first.to_string();
    }
    let last = versions.iter().last().copied().unwrap_or(first);
    format!("{first}..{last}")
}

/// Render a parenthesized "(N consumer(s): a, b, c)" suffix for the
/// reporter line. Returns an empty string when no consumers were
/// recorded — that's the GHA case (no workspace-member axis) and the
/// "the proposed dep isn't declared in any other member" case. Long
/// lists are truncated to the first 4 names with a trailing `, …+N`
/// marker so the line stays scannable.
pub(super) fn format_consumers_suffix(consumers: &[crate::model::ConsumerId]) -> String {
    if consumers.is_empty() {
        return String::new();
    }
    const MAX_NAMES: usize = 4;
    let mut sorted: Vec<&crate::model::ConsumerId> = consumers.iter().collect();
    sorted.sort();
    let n = sorted.len();
    let label = if n == 1 { "consumer" } else { "consumers" };
    let head_count = sorted.len().min(MAX_NAMES);
    let head: Vec<String> = sorted
        .iter()
        .take(head_count)
        .map(|s| s.to_string())
        .collect();
    let tail = if n > MAX_NAMES {
        format!(", …+{}", n - MAX_NAMES)
    } else {
        String::new()
    };
    format!("  ({n} {label}: {}{tail})", head.join(", "))
}

/// Aggregate cached/fresh per-workflow validation counts across every
/// completed proposal run. Returns `(cached, fresh)`. Used by the
/// reporter to surface the verdict cache hit rate; the receipt records
/// the breakdown elsewhere.
pub(super) fn aggregate_cache_counts(completed_runs: &[ProposalRun]) -> (usize, usize) {
    let mut cached = 0usize;
    let mut total = 0usize;
    for run in completed_runs {
        cached += run.outcome.cached_workflow_count;
        total += run.outcome.total_workflow_count;
    }
    let fresh = total.saturating_sub(cached);
    (cached, fresh)
}

/// Sum [`crate::model::ValidationOutcome::member_skipped_workflow_count`]
/// across all completed proposal runs. Returns the total number of
/// workflows the member-precise filter dropped this pass.
pub(super) fn aggregate_member_skipped_count(completed_runs: &[ProposalRun]) -> usize {
    completed_runs
        .iter()
        .map(|r| r.outcome.member_skipped_workflow_count)
        .sum()
}

/// Walk every completed run, harvest the first `failure_context`
/// from each red proposal, and group them by shared fingerprint.
/// Returns the deterministic cluster list (singletons excluded) used
/// by both the text report and the NDJSON `run_completed` event.
pub(super) fn build_failure_clusters(completed_runs: &[ProposalRun]) -> Vec<FailureCluster> {
    let mut pairs: Vec<(String, crate::failure_context::FailureContext)> = Vec::new();
    for run in completed_runs {
        if run.outcome.conclusion == "success" || run.outcome.conclusion == "unvalidated" {
            continue;
        }
        if let Some(ctx) = run
            .outcome
            .failure_details
            .first()
            .and_then(|d| d.failure_context.clone())
        {
            pairs.push((run.proposal.id.clone(), ctx));
        }
    }
    cluster_failures(&pairs)
}

/// Render the root-cause cluster block appended to the text report
/// when any cluster has more than one member. Returns `None` when
/// `clusters` is empty (callers don't print a header for nothing).
pub(super) fn format_failure_clusters_section(clusters: &[FailureCluster]) -> Option<String> {
    if clusters.is_empty() {
        return None;
    }
    let mut out = String::new();
    out.push_str(&format!(
        "assay: root-cause clusters ({}):\n",
        clusters.len()
    ));
    for cluster in clusters {
        let n = cluster.proposal_ids.len();
        let first_finding_msg = cluster
            .representative
            .findings
            .first()
            .map(|f| f.message.as_str())
            .unwrap_or_else(|| cluster.representative.summary.as_str());
        let code = cluster
            .representative
            .findings
            .first()
            .and_then(|f| f.code.as_deref());
        let code_str = code.map(|c| format!("{c}: ")).unwrap_or_default();
        out.push_str(&format!(
            "  cluster {} ({}): {n} proposals share this failure\n",
            cluster.fingerprint, cluster.representative.rule,
        ));
        out.push_str(&format!(
            "    representative finding: {code_str}{first_finding_msg}\n",
        ));
        out.push_str(&format!(
            "    proposal ids: {}\n",
            cluster.proposal_ids.join(", ")
        ));
    }
    Some(out)
}

/// Render the "why did these proposals fail" block for the human
/// reporter. Returns `None` when no proposals failed — caller skips
/// the section entirely (no empty header).
///
/// The block lists every red proposal once, with its
/// `subject from → to` line, a flavor tag (`[REGRESSION]`,
/// `[SETUP-FAILURE]`, `[TIMEOUT]`, or `[APPLY-FAILURE]` for pre-
/// validation failures), and either the last N lines of captured
/// stderr (validator failures) or the apply-stage summary string
/// (pre-validation failures). Ordering is alphabetical by proposal
/// id so successive runs produce byte-identical output.
pub(super) fn format_red_proposal_section(
    completed_runs: &[ProposalRun],
    pre_val_failures: &[PreValidationFailureRow],
) -> Option<String> {
    let mut validation_failures: Vec<&ProposalRun> = completed_runs
        .iter()
        .filter(|r| r.outcome.conclusion != "success" && r.outcome.conclusion != "unvalidated")
        .collect();
    let mut pv_sorted: Vec<&PreValidationFailureRow> = pre_val_failures.iter().collect();
    if validation_failures.is_empty() && pv_sorted.is_empty() {
        return None;
    }
    validation_failures.sort_by(|a, b| a.proposal.id.cmp(&b.proposal.id));
    pv_sorted.sort_by(|a, b| a.proposal.id.cmp(&b.proposal.id));

    let total = validation_failures.len() + pv_sorted.len();
    let mut out = String::new();
    out.push_str(&format!("assay: red proposals ({total}):\n"));

    for run in &validation_failures {
        let flavor = run
            .outcome
            .failure_details
            .first()
            .map(|d| d.flavor.as_str())
            .unwrap_or("FAILURE");
        out.push_str(&format!(
            "  {} {} {} → {} [{}]{}\n",
            run.proposal.id,
            run.proposal.subject,
            run.proposal.from,
            run.proposal.to,
            flavor,
            format_consumers_suffix(&run.proposal.affected_consumers),
        ));
        for detail in &run.outcome.failure_details {
            // 1.6.0: structured failure context renders first —
            // operators see the parsed error inline rather than
            // hunting through a raw stderr tail.
            if let Some(ctx) = &detail.failure_context {
                out.push_str(&format!("    [{}] {}\n", ctx.rule, ctx.summary,));
                for finding in &ctx.findings {
                    let code = finding.code.as_deref().unwrap_or("");
                    let loc = match (&finding.file, finding.line, finding.column) {
                        (Some(f), Some(l), Some(c)) => format!(" at {f}:{l}:{c}"),
                        (Some(f), Some(l), None) => format!(" at {f}:{l}"),
                        (Some(f), None, _) => format!(" at {f}"),
                        _ => String::new(),
                    };
                    let code_prefix = if code.is_empty() {
                        String::new()
                    } else {
                        format!("{code} ")
                    };
                    out.push_str(&format!("      - {code_prefix}{}{loc}\n", finding.message,));
                }
            }
            // Raw log appendix — kept for the "trust but verify"
            // case where the parser missed something interesting.
            if detail.stderr_tail.trim().is_empty() {
                continue;
            }
            out.push_str(&format!("    raw log ({}):\n", detail.backend));
            let lines: Vec<&str> = detail.stderr_tail.lines().collect();
            let total_lines = lines.len();
            let start = total_lines.saturating_sub(REPORTER_STDERR_LINE_LIMIT);
            if start > 0 {
                out.push_str(&format!(
                    "        [... {} earlier line(s) elided; see receipt for full tail ...]\n",
                    start
                ));
            }
            for line in &lines[start..] {
                out.push_str("        ");
                out.push_str(line);
                out.push('\n');
            }
        }
    }

    for row in &pv_sorted {
        out.push_str(&format!(
            "  {} {} {} → {} [APPLY-FAILURE]{}\n    {}\n",
            row.proposal.id,
            row.proposal.subject,
            row.proposal.from,
            row.proposal.to,
            format_consumers_suffix(&row.proposal.affected_consumers),
            row.summary,
        ));
    }

    Some(out)
}

/// Compute the `(proposals_shipped, proposals_merged_dropped)` counters
/// for the `RunSummary` from the apply outcome.
///
/// For modes that never run apply (report-only, or no proposals at all):
/// shipped is 0 and dropped is 0. For apply-local + apply-pr:
/// shipped is the count that landed in the commit/PR, dropped is the
/// count of individually-green proposals the merge step rejected.
/// The invariant `shipped + dropped == proposals_passed` holds for the
/// happy path; on the `SkippedDueToFailures` / `NothingToCommit` paths
/// nothing ships but greens haven't been dropped by the merge step
/// either, so both counters return 0.
pub(super) fn ship_counts(
    commit: &Option<CommitSummary>,
    pr: &Option<ApplyPrSummary>,
    _proposals_passed: usize,
) -> (usize, usize) {
    match (commit, pr) {
        (
            Some(CommitSummary::Committed {
                bump_count,
                merged_drops,
                ..
            }),
            _,
        ) => (*bump_count, merged_drops.len()),
        (Some(CommitSummary::AllDroppedByMerge { drops }), _) => (0, drops.len()),
        (
            _,
            Some(ApplyPrSummary::Published {
                bump_count,
                merged_drops,
                ..
            }),
        ) => (*bump_count, merged_drops.len()),
        (_, Some(ApplyPrSummary::AllDroppedByMerge { drops })) => (0, drops.len()),
        _ => (0, 0),
    }
}

#[cfg(test)]
mod failure_cluster_tests {
    use super::*;
    use crate::failure_context::{FailureContext, FailureFinding};

    fn cluster(rule: &str, msg: &str, ids: &[&str]) -> FailureCluster {
        let ctx = FailureContext::new(
            rule,
            format!("{rule}: {msg}"),
            vec![FailureFinding {
                code: Some("E0277".into()),
                message: msg.into(),
                file: None,
                line: None,
                column: None,
            }],
        );
        FailureCluster {
            fingerprint: ctx.fingerprint.clone(),
            proposal_ids: ids.iter().map(|s| s.to_string()).collect(),
            representative: ctx,
        }
    }

    #[test]
    fn format_failure_clusters_section_returns_none_when_empty() {
        assert!(format_failure_clusters_section(&[]).is_none());
    }

    #[test]
    fn format_failure_clusters_section_renders_cluster_count_and_ids() {
        let c = cluster(
            "cargo:rustc-error",
            "trait not impl",
            &["p-1", "p-2", "p-3"],
        );
        let out = format_failure_clusters_section(std::slice::from_ref(&c)).unwrap();
        assert!(out.contains("root-cause clusters (1)"));
        assert!(out.contains(&c.fingerprint));
        assert!(out.contains("3 proposals share this failure"));
        assert!(out.contains("p-1, p-2, p-3"));
        assert!(out.contains("trait not impl"));
    }

    #[test]
    fn format_failure_clusters_section_renders_multiple_clusters() {
        let a = cluster("cargo:rustc-error", "alpha", &["a-1", "a-2"]);
        let b = cluster("npm:eresolve", "beta", &["b-1", "b-2"]);
        let out = format_failure_clusters_section(&[a, b]).unwrap();
        assert!(out.contains("root-cause clusters (2)"));
        assert!(out.contains("cargo:rustc-error"));
        assert!(out.contains("npm:eresolve"));
    }
}
