//! Multi-proposal merge applier.
//!
//! Solves the "last-write-wins copy-back" problem: per-proposal sandboxes
//! each carry only THEIR proposal's edits, so copying them sequentially
//! to the host overwrites earlier proposals' bumps. The merge applier
//! produces ONE sandbox per ecosystem with ALL greens applied together,
//! validates the merged state, and copies back from that single sandbox.
//!
//! If the merged sandbox reds (greens that conflict when combined), a
//! greedy bisect drops one proposal at a time and re-validates, accepting
//! the largest size-(N-1) subset that greens. If no size-(N-1) subset
//! greens, the ecosystem ships nothing — recursing further is O(2^N) and
//! surfaces less actionable information than the "drop these N and
//! revalidate manually" hand-off.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::ecosystem::DependencyEcosystem;
use crate::error::{Error, Result};
use crate::model::{
    Classification, Proposal, ProposalKind, Provenance, ProvenanceRecord, ValidationOutcome,
};
use crate::validator::Validator;

/// Borrow-only view of one per-proposal validation result fed into the
/// merge planner. Mirrors cli.rs's `ProposalRun` without forcing a
/// circular module dep.
pub struct RunRef<'a> {
    pub eco_idx: usize,
    pub proposal: &'a Proposal,
    pub sandbox: &'a Path,
    pub outcome: &'a ValidationOutcome,
    /// Where the manifest this proposal came from lives. For polyglot
    /// Tauri layouts proposals from cargo and npm have different
    /// scan_roots; the merge planner groups by (eco_idx, scan_root)
    /// so each sub-project's merge sandbox is set up against the
    /// right directory.
    pub scan_root: &'a Path,
}

/// Per-ecosystem outcome of the merge pass. With polyglot layouts the
/// effective grouping is (eco_idx, scan_root) — each `scan_root` field
/// pairs with the ecosystem to identify the sub-project this outcome
/// targets, so copy-back lands in the right host directory.
#[derive(Debug)]
pub struct EcosystemMergeOutcome {
    pub eco_idx: usize,
    /// The host-side directory the shipped proposals modify. Copy-back
    /// runs `ecosystem.copy_back_merged(..., scan_root)` so manifests
    /// land back in the originating sub-project, not the artifact
    /// root.
    pub scan_root: PathBuf,
    /// Sandbox to copy back from. For groups with one green this is
    /// the per-proposal sandbox passed in via `runs`. For groups with
    /// two or more greens whose merged set went green, this is the
    /// merge worktree created here. When bisect kept a size-(N-1)
    /// subset, this is the worktree of that subset's attempt. When
    /// the group ships nothing, this path is empty.
    pub sandbox: PathBuf,
    /// Indices into the input `runs` slice — which proposals will be
    /// shipped from `sandbox`.
    pub shipped: Vec<usize>,
    /// Proposals that greened individually but were dropped from the
    /// merged ship because including them turned the merged validation
    /// red. Each carries a short reason for the receipt.
    pub dropped: Vec<MergedDrop>,
}

#[derive(Debug)]
pub struct MergedDrop {
    pub run_idx: usize,
    pub reason: String,
}

/// Compute the per-ecosystem ship plan for a set of per-proposal runs.
///
/// Only runs with `outcome.conclusion == "success"` are eligible.
/// Ecosystems with exactly one green pass through unchanged (the per-
/// proposal sandbox is byte-correct already). Ecosystems with two or
/// more greens get a fresh merged worktree where every green is applied
/// together; the merged sandbox is validated, and on red the bisect
/// strategy drops the highest-ID proposal at a time until a green
/// subset is found or the search is exhausted.
pub fn build_ship_plan(
    artifact_root: &Path,
    run_id: &str,
    registry: &[Box<dyn DependencyEcosystem>],
    validator: &Validator,
    runs: &[RunRef<'_>],
    provenance: &mut Provenance,
) -> Result<Vec<EcosystemMergeOutcome>> {
    // Group by (eco_idx, scan_root) so each sub-project's proposals
    // merge in their own sandbox. Two cargo workspaces in different
    // scan_roots would never share a merge sandbox (different
    // Cargo.lock files); same logic for any other ecosystem with
    // per-root state.
    let mut by_group: BTreeMap<(usize, PathBuf), Vec<usize>> = BTreeMap::new();
    for (i, run) in runs.iter().enumerate() {
        if run.outcome.conclusion == "success" {
            by_group
                .entry((run.eco_idx, run.scan_root.to_path_buf()))
                .or_default()
                .push(i);
        }
    }
    let mut outcomes: Vec<EcosystemMergeOutcome> = Vec::new();
    for ((eco_idx, scan_root), green_indices) in by_group {
        let ecosystem = registry[eco_idx].as_ref();
        if green_indices.len() == 1 {
            outcomes.push(EcosystemMergeOutcome {
                eco_idx,
                scan_root: scan_root.clone(),
                sandbox: runs[green_indices[0]].sandbox.to_path_buf(),
                shipped: green_indices,
                dropped: Vec::new(),
            });
            continue;
        }
        // Ecosystems can declare per-proposal sandboxes byte-equivalent
        // for this set (cargo does so for all-LockfileOnly bumps because
        // `cargo update --workspace` is deterministic + comprehensive).
        // When that's the case the merge sandbox + revalidate is pure
        // overhead — copy back from the first per-proposal sandbox.
        let proposals: Vec<&Proposal> = green_indices.iter().map(|i| runs[*i].proposal).collect();
        if ecosystem.merge_is_redundant(&proposals) {
            provenance.records.push(ProvenanceRecord {
                tool: "assay".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                stage: format!("applier.merge.{}", ecosystem.name()),
                subject: format!("<merged:{}>", ecosystem.name()),
                status: Classification::Exact,
                summary: format!(
                    "skipped merge sandbox: ecosystem reports per-proposal sandboxes byte-equivalent for {} proposal(s)",
                    proposals.len()
                ),
                artifact_path: None,
                details: Some(serde_json::json!({
                    "ecosystem": ecosystem.name(),
                    "proposals": proposals.iter().map(|p| p.id.clone()).collect::<Vec<_>>(),
                })),
            });
            outcomes.push(EcosystemMergeOutcome {
                eco_idx,
                scan_root: scan_root.clone(),
                sandbox: runs[green_indices[0]].sandbox.to_path_buf(),
                shipped: green_indices,
                dropped: Vec::new(),
            });
            continue;
        }
        let merge = merge_with_bisect(
            artifact_root,
            &scan_root,
            run_id,
            eco_idx,
            ecosystem,
            validator,
            runs,
            &green_indices,
            provenance,
        )?;
        outcomes.push(merge);
    }
    Ok(outcomes)
}

#[allow(clippy::too_many_arguments)]
fn merge_with_bisect(
    artifact_root: &Path,
    scan_root: &Path,
    run_id: &str,
    eco_idx: usize,
    ecosystem: &dyn DependencyEcosystem,
    validator: &Validator,
    runs: &[RunRef<'_>],
    green_indices: &[usize],
    provenance: &mut Provenance,
) -> Result<EcosystemMergeOutcome> {
    let attempt = try_merged_apply_and_validate(
        artifact_root,
        scan_root,
        run_id,
        eco_idx,
        ecosystem,
        validator,
        runs,
        green_indices,
        provenance,
    )?;
    if let MergedAttempt::Green { sandbox } = attempt {
        return Ok(EcosystemMergeOutcome {
            eco_idx,
            scan_root: scan_root.to_path_buf(),
            sandbox,
            shipped: green_indices.to_vec(),
            dropped: Vec::new(),
        });
    }
    let reason = match attempt {
        MergedAttempt::Red { reason, .. } => reason,
        MergedAttempt::Green { .. } => unreachable!(),
    };
    // Cohort-aware bisect. The unit of drop is a "drop group", not a
    // single proposal: cohort-lockstep siblings (`@angular/core` +
    // `@angular/common`, `@tiptap/core` + `@tiptap/starter-kit`,
    // etc.) MUST move together, so the bisect drops them as a unit.
    // Dropping a single cohort member alone would either (a) re-
    // expose the lockstep violation we just dodged or (b) succeed
    // by accident on a config that doesn't enforce the lockstep,
    // shipping a partial cohort that pnpm/npm will refuse to
    // resolve on the host. Both outcomes are unacceptable.
    //
    // Drop ordering: highest-id-first within each group, groups
    // sorted by their max member id descending — keeps the bisect
    // deterministic across re-runs and matches the existing
    // "drop biggest id first" intent at the granularity that
    // respects cohort atomicity.
    let drop_groups = build_drop_groups(runs, green_indices);
    let mut last_red_reason = reason.clone();
    for drop_group in &drop_groups {
        let drop_set: std::collections::BTreeSet<usize> = drop_group.iter().copied().collect();
        let subset: Vec<usize> = green_indices
            .iter()
            .copied()
            .filter(|i| !drop_set.contains(i))
            .collect();
        if subset.is_empty() {
            // Last drop group would empty the merge set; no point
            // re-running the validator on zero proposals — the
            // empty merge has nothing to validate.
            continue;
        }
        let attempt2 = try_merged_apply_and_validate(
            artifact_root,
            scan_root,
            run_id,
            eco_idx,
            ecosystem,
            validator,
            runs,
            &subset,
            provenance,
        )?;
        match attempt2 {
            MergedAttempt::Green { sandbox } => {
                let drop_label = if drop_group.len() == 1 {
                    format!("merged set red until dropped: {reason}")
                } else {
                    format!(
                        "merged set red until cohort dropped ({} members): {reason}",
                        drop_group.len()
                    )
                };
                let dropped: Vec<MergedDrop> = drop_group
                    .iter()
                    .copied()
                    .map(|idx| MergedDrop {
                        run_idx: idx,
                        reason: drop_label.clone(),
                    })
                    .collect();
                return Ok(EcosystemMergeOutcome {
                    eco_idx,
                    scan_root: scan_root.to_path_buf(),
                    sandbox,
                    shipped: subset,
                    dropped,
                });
            }
            MergedAttempt::Red { reason: r2, .. } => {
                last_red_reason = r2;
            }
        }
    }
    // No drop group cleared the merge — ship nothing for this group.
    let dropped: Vec<MergedDrop> = green_indices
        .iter()
        .copied()
        .map(|idx| MergedDrop {
            run_idx: idx,
            reason: format!(
                "no size-(N-1) merged subset went green (last seen: {last_red_reason})"
            ),
        })
        .collect();
    Ok(EcosystemMergeOutcome {
        eco_idx,
        scan_root: scan_root.to_path_buf(),
        sandbox: PathBuf::new(),
        shipped: Vec::new(),
        dropped,
    })
}

enum MergedAttempt {
    Green {
        sandbox: PathBuf,
    },
    Red {
        /// Kept so future receipt-detail expansions can attach the red
        /// sandbox's path for forensic inspection. Currently unread.
        #[allow(dead_code)]
        sandbox: PathBuf,
        reason: String,
    },
}

/// Group `green_indices` into bisect-drop units. A drop unit is
/// either:
///
/// - a single run_idx (the proposal has no cohort, or is the only
///   cohort member in this green set), OR
/// - the full set of run_idx values whose proposals share the same
///   `cohort` id (≥2 members) — cohort siblings MUST drop as one
///   atomic unit, never alone.
///
/// Drop ordering: groups sorted by their highest-id member
/// descending, so the bisect tries the "newest-feeling" drop
/// first and stays deterministic across re-runs (matches the
/// original "drop highest id first" intent at the right
/// granularity).
fn build_drop_groups(runs: &[RunRef<'_>], green_indices: &[usize]) -> Vec<Vec<usize>> {
    use std::collections::BTreeMap;
    // Bucket greens by their cohort id; non-cohort proposals get
    // their own singleton bucket via a synthetic key that no real
    // cohort id collides with.
    let mut by_cohort: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for &run_idx in green_indices {
        let proposal = runs[run_idx].proposal;
        let bucket_key = match proposal.cohort.as_deref() {
            Some(cohort) => format!("cohort:{cohort}"),
            // Use the proposal id as a unique solo bucket key.
            None => format!("solo:{}", proposal.id),
        };
        by_cohort.entry(bucket_key).or_default().push(run_idx);
    }
    // Each cohort bucket with ≥2 members is one drop unit; cohort
    // buckets with 1 member, and solo buckets, are singletons.
    let mut groups: Vec<Vec<usize>> = by_cohort.into_values().collect();
    // Sort by max member id descending for determinism.
    groups.sort_by(|a, b| {
        let a_max = a.iter().map(|i| &runs[*i].proposal.id).max();
        let b_max = b.iter().map(|i| &runs[*i].proposal.id).max();
        b_max.cmp(&a_max)
    });
    groups
}

#[cfg(test)]
mod drop_group_tests {
    use super::*;
    use crate::model::{BumpTier, Classification, Proposal, ProposalKind, ValidationOutcome};
    use std::path::Path;

    fn proposal(id: &str, subject: &str, cohort: Option<&str>) -> Proposal {
        Proposal {
            id: id.into(),
            ecosystem: "npm".into(),
            kind: ProposalKind::Version,
            subject: subject.into(),
            from: "1.0.0".into(),
            to: "2.0.0".into(),
            initial_classification: Classification::Exact,
            manifest_paths: vec![],
            notes: vec![],
            bump_tier: BumpTier::Compatible,
            affected_consumers: vec![],
            explanation: None,
            cohort: cohort.map(str::to_string),
        }
    }

    fn outcome() -> ValidationOutcome {
        ValidationOutcome {
            proposal_id: "p".into(),
            conclusion: "success".into(),
            ci_forge_run_ids: vec![],
            validated_workflows: vec![],
            classification: Classification::Exact,
            notes: vec![],
            failure_details: vec![],
            cached_workflow_count: 0,
            total_workflow_count: 0,
            member_skipped_workflow_count: 0,
        }
    }

    fn run_ref<'a>(
        p: &'a Proposal,
        sandbox: &'a Path,
        outcome: &'a ValidationOutcome,
    ) -> RunRef<'a> {
        RunRef {
            eco_idx: 0,
            proposal: p,
            sandbox,
            outcome,
            scan_root: sandbox,
        }
    }

    #[test]
    fn build_drop_groups_keeps_cohort_members_together() {
        // Two cohorts: angular-framework (2 members), tiptap (2
        // members). The bisect must treat each cohort as ONE drop
        // unit, never bisect within.
        let p_a1 = proposal("npm-a1", "@angular/core", Some("angular-framework"));
        let p_a2 = proposal("npm-a2", "@angular/common", Some("angular-framework"));
        let p_t1 = proposal("npm-t1", "@tiptap/core", Some("tiptap"));
        let p_t2 = proposal("npm-t2", "@tiptap/starter-kit", Some("tiptap"));
        let sb = Path::new("/tmp/sb");
        let oc = outcome();
        let runs = vec![
            run_ref(&p_a1, sb, &oc),
            run_ref(&p_a2, sb, &oc),
            run_ref(&p_t1, sb, &oc),
            run_ref(&p_t2, sb, &oc),
        ];
        let groups = build_drop_groups(&runs, &[0, 1, 2, 3]);
        assert_eq!(groups.len(), 2, "two cohorts → two drop groups");
        let by_size: Vec<usize> = groups.iter().map(|g| g.len()).collect();
        assert_eq!(by_size, vec![2, 2]);
    }

    #[test]
    fn build_drop_groups_mixes_solo_and_cohort() {
        let p_a1 = proposal("npm-a1", "@angular/core", Some("angular-framework"));
        let p_a2 = proposal("npm-a2", "@angular/common", Some("angular-framework"));
        let p_ts = proposal("npm-ts", "typescript", None);
        let p_ld = proposal("npm-ld", "lodash", None);
        let sb = Path::new("/tmp/sb");
        let oc = outcome();
        let runs = vec![
            run_ref(&p_a1, sb, &oc),
            run_ref(&p_a2, sb, &oc),
            run_ref(&p_ts, sb, &oc),
            run_ref(&p_ld, sb, &oc),
        ];
        let groups = build_drop_groups(&runs, &[0, 1, 2, 3]);
        // Expect 3 drop groups: angular cohort (size 2), typescript
        // (size 1), lodash (size 1).
        assert_eq!(groups.len(), 3);
        let sizes: std::collections::BTreeMap<usize, usize> =
            groups.iter().fold(Default::default(), |mut acc, g| {
                *acc.entry(g.len()).or_insert(0) += 1;
                acc
            });
        assert_eq!(sizes.get(&2).copied(), Some(1), "one 2-member group");
        assert_eq!(sizes.get(&1).copied(), Some(2), "two 1-member groups");
    }

    #[test]
    fn build_drop_groups_treats_singleton_cohort_as_solo() {
        // Only one cohort member in scope — it's a singleton, so it
        // can be dropped alone (no lockstep partner to break).
        let p_a1 = proposal("npm-a1", "@angular/core", Some("angular-framework"));
        let p_ts = proposal("npm-ts", "typescript", None);
        let sb = Path::new("/tmp/sb");
        let oc = outcome();
        let runs = vec![run_ref(&p_a1, sb, &oc), run_ref(&p_ts, sb, &oc)];
        let groups = build_drop_groups(&runs, &[0, 1]);
        assert_eq!(groups.len(), 2);
        // Each is a singleton.
        assert!(groups.iter().all(|g| g.len() == 1));
    }
}

#[allow(clippy::too_many_arguments)]
fn try_merged_apply_and_validate(
    artifact_root: &Path,
    scan_root: &Path,
    run_id: &str,
    eco_idx: usize,
    ecosystem: &dyn DependencyEcosystem,
    validator: &Validator,
    runs: &[RunRef<'_>],
    indices: &[usize],
    provenance: &mut Provenance,
) -> Result<MergedAttempt> {
    let proposals: Vec<&Proposal> = indices.iter().map(|i| runs[*i].proposal).collect();
    let label = format!(
        "merge-{}-{}",
        ecosystem.name(),
        short_hash_of_proposals(&proposals)
    );
    let merge_tree = prepare_isolated_worktree(artifact_root, scan_root, run_id, &label)?;
    ecosystem.apply_merged(&proposals, &merge_tree)?;
    let synth = synthesize_merged_proposal(eco_idx, ecosystem, &proposals);
    let workflows = collect_gate_workflows(ecosystem, &proposals, &merge_tree);
    provenance.records.push(ProvenanceRecord {
        tool: "assay".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        stage: format!("applier.merge.{}", ecosystem.name()),
        subject: synth.id.clone(),
        status: Classification::Exact,
        summary: format!("merged {} proposal(s) into one sandbox", proposals.len()),
        artifact_path: None,
        details: Some(serde_json::json!({
            "sandbox": merge_tree,
            "proposals": proposals.iter().map(|p| p.id.clone()).collect::<Vec<_>>(),
        })),
    });
    let outcome = validator.validate(&synth, &merge_tree, &workflows)?;
    provenance.records.push(ProvenanceRecord {
        tool: "assay".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        stage: format!("validator.merge.{}", ecosystem.name()),
        subject: synth.id.clone(),
        status: outcome.classification,
        summary: format!(
            "merged validation {} ({} run(s))",
            outcome.conclusion,
            outcome.ci_forge_run_ids.len()
        ),
        artifact_path: None,
        details: serde_json::to_value(&outcome).ok(),
    });
    if outcome.conclusion == "success" {
        Ok(MergedAttempt::Green {
            sandbox: merge_tree,
        })
    } else {
        Ok(MergedAttempt::Red {
            sandbox: merge_tree,
            reason: outcome.conclusion,
        })
    }
}

fn synthesize_merged_proposal(
    _eco_idx: usize,
    ecosystem: &dyn DependencyEcosystem,
    proposals: &[&Proposal],
) -> Proposal {
    let mut manifest_paths: Vec<PathBuf> = Vec::new();
    for p in proposals {
        for path in &p.manifest_paths {
            if !manifest_paths.contains(path) {
                manifest_paths.push(path.clone());
            }
        }
    }
    Proposal {
        id: format!(
            "merge-{}-{}",
            ecosystem.name(),
            short_hash_of_proposals(proposals)
        ),
        ecosystem: ecosystem.name().into(),
        kind: ProposalKind::Version,
        subject: format!("<merged {} proposal(s)>", proposals.len()),
        from: "<merged>".into(),
        to: "<merged>".into(),
        initial_classification: Classification::Exact,
        manifest_paths,
        notes: proposals.iter().map(|p| p.id.clone()).collect(),
        bump_tier: Default::default(),
        affected_consumers: Vec::new(),
        explanation: None,
        cohort: None,
    }
}

fn collect_gate_workflows(
    ecosystem: &dyn DependencyEcosystem,
    proposals: &[&Proposal],
    tree: &Path,
) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for p in proposals {
        if let Ok(paths) = ecosystem.gate_workflows(p, tree) {
            for path in paths {
                if !out.contains(&path) {
                    out.push(path);
                }
            }
        }
    }
    out
}

fn short_hash_of_proposals(proposals: &[&Proposal]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"assay:merge:v1:");
    for p in proposals {
        hasher.update(p.id.as_bytes());
        hasher.update(b"|");
    }
    let digest = hasher.finalize();
    digest[..6].iter().map(|b| format!("{b:02x}")).collect()
}

/// Create an isolated git worktree under
/// `<artifact_root>/.assay/runs/<run-id>/work/<label>`.
///
/// `artifact_root` is the assay run's anchor (where `.assay/` lives).
/// `scan_root` is the ecosystem's project root inside the repo (may be
/// a subdirectory like `src-tauri/`); the returned `final_target`
/// descends into that subdir of the worktree so the ecosystem applier
/// finds manifests at the expected relative locations. Single-root
/// callers pass `artifact_root == scan_root`.
pub fn prepare_isolated_worktree(
    artifact_root: &Path,
    scan_root: &Path,
    run_id: &str,
    label: &str,
) -> Result<PathBuf> {
    // Walk up to the git top-level via `git rev-parse --show-toplevel`
    // — supports running assay against a sub-directory (Tauri layouts
    // place Cargo.toml under `src-tauri/`, for example).
    let git_root = resolve_git_top_level(scan_root)?;
    let rel_sub_dir = scan_root.canonicalize().ok().and_then(|c| {
        git_root
            .canonicalize()
            .ok()
            .and_then(|g| c.strip_prefix(&g).ok().map(Path::to_path_buf))
    });
    let work_root = artifact_root
        .join(".assay")
        .join("runs")
        .join(run_id)
        .join("work");
    std::fs::create_dir_all(&work_root).map_err(|source| Error::Io {
        path: work_root.clone(),
        source,
    })?;
    let base = safe_tree_label(label);
    let mut target = work_root.join(&base);
    let mut suffix = 2usize;
    while target.exists() {
        target = work_root.join(format!("{base}-{suffix}"));
        suffix += 1;
    }
    let target_abs = std::path::absolute(&target).unwrap_or(target.clone());
    let output = std::process::Command::new("git")
        .arg("worktree")
        .arg("add")
        .arg("--detach")
        .arg(&target_abs)
        .arg("HEAD")
        .current_dir(&git_root)
        .output()
        .map_err(|source| Error::Io {
            path: git_root.clone(),
            source,
        })?;
    if !output.status.success() {
        return Err(Error::other(format!(
            "git worktree add failed for merge sandbox: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    // Materialize external path deps into the merge sandbox too.
    // Same arithmetic + safety boundary as `prepare_apply_local_tree`;
    // the merge worktree shares the same run-id-scoped directory so
    // the materialization is shared across per-proposal and merge
    // sandboxes within a run.
    let run_root = artifact_root.join(".assay").join("runs").join(run_id);
    crate::external_deps::materialize_external_deps_into_sandbox(
        scan_root,
        &target_abs,
        &run_root,
    )?;

    let final_target = match rel_sub_dir {
        Some(rel) if !rel.as_os_str().is_empty() => target_abs.join(rel),
        _ => target_abs,
    };
    Ok(final_target)
}

fn resolve_git_top_level(path: &Path) -> Result<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(path)
        .output()
        .map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if !output.status.success() {
        return Err(Error::other(format!(
            "merge applier requires a git checkout so assay can retain an isolated worktree, \
             but `{}` is not under one (git rev-parse said: {})",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim(),
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(PathBuf::from(stdout.trim()))
}

fn safe_tree_label(label: &str) -> String {
    let mut out = String::with_capacity(label.len().min(80));
    let mut last_dash = false;
    for ch in label.chars().flat_map(char::to_lowercase) {
        let mapped = if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            ch
        } else {
            '-'
        };
        if mapped == '-' {
            if !last_dash && !out.is_empty() {
                out.push(mapped);
                last_dash = true;
            }
        } else {
            out.push(mapped);
            last_dash = false;
        }
        if out.len() >= 80 {
            break;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        out = "merge".into();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use crate::ecosystem::EcosystemContext;
    use crate::model::{Manifest, ValidationOutcome};

    #[test]
    fn safe_tree_label_normalizes_uppercase_and_non_alnum() {
        assert_eq!(safe_tree_label("Merge-NPM/Foo"), "merge-npm-foo");
        assert_eq!(safe_tree_label("a@b@c"), "a-b-c");
        assert_eq!(safe_tree_label("___"), "merge");
        assert_eq!(safe_tree_label(""), "merge");
    }

    #[test]
    fn safe_tree_label_collapses_dashes() {
        assert_eq!(safe_tree_label("a--b---c"), "a-b-c");
        assert_eq!(safe_tree_label("-a-"), "a");
    }

    #[test]
    fn short_hash_is_stable_for_same_proposal_ids() {
        let a = make_test_proposal("cargo-a");
        let b = make_test_proposal("cargo-b");
        let h1 = short_hash_of_proposals(&[&a, &b]);
        let h2 = short_hash_of_proposals(&[&a, &b]);
        assert_eq!(h1, h2);
        let h3 = short_hash_of_proposals(&[&b, &a]);
        assert_ne!(h1, h3, "order-sensitive by design");
    }

    fn make_test_proposal(id: &str) -> Proposal {
        Proposal {
            id: id.into(),
            ecosystem: "fake".into(),
            kind: ProposalKind::Version,
            subject: id.into(),
            from: "1".into(),
            to: "2".into(),
            initial_classification: Classification::Exact,
            manifest_paths: vec![],
            notes: vec![],
            bump_tier: Default::default(),
            affected_consumers: Vec::new(),
            explanation: None,
            cohort: None,
        }
    }

    fn make_test_outcome(conclusion: &str) -> ValidationOutcome {
        ValidationOutcome {
            proposal_id: "fake".into(),
            conclusion: conclusion.into(),
            ci_forge_run_ids: vec![],
            validated_workflows: vec![],
            classification: Classification::Exact,
            notes: vec![],
            failure_details: vec![],
            cached_workflow_count: 0,
            total_workflow_count: 0,
            member_skipped_workflow_count: 0,
        }
    }

    // -------------------------------------------------------------------------
    // Mock ecosystem that lets tests record apply_merged calls and feed
    // back configurable success outcomes.
    // -------------------------------------------------------------------------

    struct MockEcosystem {
        apply_calls: Mutex<Vec<Vec<String>>>,
    }

    impl MockEcosystem {
        fn new() -> Self {
            Self {
                apply_calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl crate::ecosystem::DependencyEcosystem for MockEcosystem {
        fn name(&self) -> &'static str {
            "mock"
        }
        fn detect_manifests(&self, _repo: &Path) -> Result<Vec<Manifest>> {
            Ok(vec![])
        }
        fn propose_updates(
            &self,
            _manifests: &[Manifest],
            _repo: &Path,
            _ctx: &EcosystemContext,
        ) -> Result<Vec<Proposal>> {
            Ok(vec![])
        }
        fn gate_workflows(&self, _proposal: &Proposal, _repo: &Path) -> Result<Vec<PathBuf>> {
            Ok(vec![])
        }
        fn affected_consumers(
            &self,
            _proposal: &Proposal,
            _tree: &Path,
        ) -> Result<Vec<crate::model::ConsumerId>> {
            Ok(vec![])
        }
        fn apply_proposal(&self, _proposal: &Proposal, _tree_path: &Path) -> Result<()> {
            Ok(())
        }
        fn apply_merged(&self, proposals: &[&Proposal], _tree_path: &Path) -> Result<()> {
            self.apply_calls
                .lock()
                .unwrap()
                .push(proposals.iter().map(|p| p.id.clone()).collect());
            Ok(())
        }
        fn copy_back(
            &self,
            _proposal: &Proposal,
            _sandbox: &Path,
            _host: &Path,
        ) -> Result<Vec<PathBuf>> {
            Ok(vec![])
        }
        fn pr_body_fragment(&self, _proposal: &Proposal, _outcome: &ValidationOutcome) -> String {
            String::new()
        }
    }

    /// Mock ecosystem that always reports per-proposal sandboxes byte-
    /// equivalent for any non-empty set — the merge step should skip
    /// the sandbox + revalidate dance entirely.
    struct RedundantMergeEcosystem(MockEcosystem);

    impl crate::ecosystem::DependencyEcosystem for RedundantMergeEcosystem {
        fn name(&self) -> &'static str {
            "mock-redundant"
        }
        fn detect_manifests(&self, repo: &Path) -> Result<Vec<Manifest>> {
            self.0.detect_manifests(repo)
        }
        fn propose_updates(
            &self,
            manifests: &[Manifest],
            repo: &Path,
            ctx: &EcosystemContext,
        ) -> Result<Vec<Proposal>> {
            self.0.propose_updates(manifests, repo, ctx)
        }
        fn gate_workflows(&self, proposal: &Proposal, repo: &Path) -> Result<Vec<PathBuf>> {
            self.0.gate_workflows(proposal, repo)
        }
        fn affected_consumers(
            &self,
            proposal: &Proposal,
            tree: &Path,
        ) -> Result<Vec<crate::model::ConsumerId>> {
            self.0.affected_consumers(proposal, tree)
        }
        fn apply_proposal(&self, proposal: &Proposal, tree_path: &Path) -> Result<()> {
            self.0.apply_proposal(proposal, tree_path)
        }
        fn merge_is_redundant(&self, _proposals: &[&Proposal]) -> bool {
            true
        }
        fn copy_back(
            &self,
            proposal: &Proposal,
            sandbox: &Path,
            host: &Path,
        ) -> Result<Vec<PathBuf>> {
            self.0.copy_back(proposal, sandbox, host)
        }
        fn pr_body_fragment(&self, proposal: &Proposal, outcome: &ValidationOutcome) -> String {
            self.0.pr_body_fragment(proposal, outcome)
        }
    }

    #[test]
    fn build_ship_plan_passes_through_single_green_per_ecosystem() {
        // Single green for an ecosystem must NOT trigger merge worktree
        // creation. The per-proposal sandbox is byte-correct already.
        let registry: Vec<Box<dyn crate::ecosystem::DependencyEcosystem>> =
            vec![Box::new(MockEcosystem::new())];
        let proposal = make_test_proposal("mock-a");
        let outcome = make_test_outcome("success");
        let sandbox = PathBuf::from("/tmp/per-proposal-sandbox");
        let runs = vec![RunRef {
            eco_idx: 0,
            proposal: &proposal,
            sandbox: &sandbox,
            outcome: &outcome,
            scan_root: std::path::Path::new("."),
        }];
        let validator = make_test_validator();
        // Repo path isn't accessed for the single-green path — any
        // existing directory works.
        let tmp = tempfile::tempdir().unwrap();
        let mut provenance = Provenance::default();
        let plan = build_ship_plan(
            tmp.path(),
            "rid",
            &registry,
            &validator,
            &runs,
            &mut provenance,
        )
        .expect("single-green plan should succeed");
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].eco_idx, 0);
        assert_eq!(plan[0].sandbox, sandbox);
        assert_eq!(plan[0].shipped, vec![0]);
        assert!(plan[0].dropped.is_empty());
        // The mock's apply_merged was never invoked.
        let mock = registry[0].as_ref();
        let mock_eco = mock as *const dyn crate::ecosystem::DependencyEcosystem;
        // We can't downcast the trait object, but the test's intent is
        // captured: the plan's sandbox matches the input sandbox, not a
        // freshly created merge sandbox.
        let _ = mock_eco;
    }

    #[test]
    fn build_ship_plan_skips_merge_when_ecosystem_declares_redundant() {
        // When merge_is_redundant returns true, the planner must reuse
        // the first per-proposal sandbox — no new worktree.
        let registry: Vec<Box<dyn crate::ecosystem::DependencyEcosystem>> =
            vec![Box::new(RedundantMergeEcosystem(MockEcosystem::new()))];
        let p_a = make_test_proposal("mock-a");
        let p_b = make_test_proposal("mock-b");
        let p_c = make_test_proposal("mock-c");
        let outcome = make_test_outcome("success");
        let sandbox_a = PathBuf::from("/tmp/per-proposal-a");
        let sandbox_b = PathBuf::from("/tmp/per-proposal-b");
        let sandbox_c = PathBuf::from("/tmp/per-proposal-c");
        let runs = vec![
            RunRef {
                eco_idx: 0,
                proposal: &p_a,
                sandbox: &sandbox_a,
                outcome: &outcome,
                scan_root: std::path::Path::new("."),
            },
            RunRef {
                eco_idx: 0,
                proposal: &p_b,
                sandbox: &sandbox_b,
                outcome: &outcome,
                scan_root: std::path::Path::new("."),
            },
            RunRef {
                eco_idx: 0,
                proposal: &p_c,
                sandbox: &sandbox_c,
                outcome: &outcome,
                scan_root: std::path::Path::new("."),
            },
        ];
        let validator = make_test_validator();
        let tmp = tempfile::tempdir().unwrap();
        let mut provenance = Provenance::default();
        let plan = build_ship_plan(
            tmp.path(),
            "rid",
            &registry,
            &validator,
            &runs,
            &mut provenance,
        )
        .expect("redundant-merge plan should succeed");
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].shipped, vec![0, 1, 2]);
        assert_eq!(plan[0].sandbox, sandbox_a, "must reuse the first sandbox");
        assert!(plan[0].dropped.is_empty());
        // A provenance record describing the skip should have been
        // pushed so operators can audit the decision.
        let has_skip_record = provenance.records.iter().any(|r| {
            r.summary.contains("skipped merge sandbox")
                && r.stage.contains("applier.merge.mock-redundant")
        });
        assert!(
            has_skip_record,
            "skip decision must be auditable in provenance"
        );
    }

    #[test]
    fn build_ship_plan_skips_reds() {
        // Reds shouldn't make it into a ship plan.
        let registry: Vec<Box<dyn crate::ecosystem::DependencyEcosystem>> =
            vec![Box::new(RedundantMergeEcosystem(MockEcosystem::new()))];
        let p_green = make_test_proposal("mock-green");
        let p_red = make_test_proposal("mock-red");
        let green_outcome = make_test_outcome("success");
        let red_outcome = make_test_outcome("failure");
        let sb1 = PathBuf::from("/tmp/sb1");
        let sb2 = PathBuf::from("/tmp/sb2");
        let runs = vec![
            RunRef {
                eco_idx: 0,
                proposal: &p_green,
                sandbox: &sb1,
                outcome: &green_outcome,
                scan_root: std::path::Path::new("."),
            },
            RunRef {
                eco_idx: 0,
                proposal: &p_red,
                sandbox: &sb2,
                outcome: &red_outcome,
                scan_root: std::path::Path::new("."),
            },
        ];
        let validator = make_test_validator();
        let tmp = tempfile::tempdir().unwrap();
        let mut provenance = Provenance::default();
        let plan = build_ship_plan(
            tmp.path(),
            "rid",
            &registry,
            &validator,
            &runs,
            &mut provenance,
        )
        .expect("should succeed");
        // Only the green run made it.
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].shipped, vec![0]);
    }

    fn make_test_validator() -> crate::validator::Validator {
        // CustomBackend with a never-invoked argv — the tests that use
        // this take paths where the validator is never called (single-
        // green, merge-redundant, red-skipped).
        crate::validator::Validator::with_backend(Box::new(crate::validator::CustomBackend::new(
            vec!["__never_invoked__".into()],
        )))
    }
}
