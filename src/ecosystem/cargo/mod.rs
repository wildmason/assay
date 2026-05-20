//! Cargo ecosystem.
//!
//! Detects `Cargo.toml` + `Cargo.lock` files in a repo (workspace root and
//! per-crate manifests), runs `cargo update --dry-run --workspace` to
//! enumerate available bumps, and cross-checks the stdout parser against a
//! direct lockfile diff to defend against cargo stdout format drift.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::model::{BumpTier, Manifest, ManifestKind, Proposal, ValidationOutcome};
#[cfg(test)]
use crate::model::{Classification, ProposalKind};

use super::{DependencyEcosystem, EcosystemContext, EcosystemName};

mod apply;
mod classify;
mod consumers;
mod parse;
mod propose;

pub use apply::{
    apply_cargo_proposal, apply_cargo_proposals_merged, apply_cargo_update_to_tree,
    copy_back_cargo_proposal, copy_back_cargo_proposals_merged,
};
pub use classify::{classify_unchanged_bump, explain_lockfile_only_bump, explain_unchanged_bump};
pub use parse::{
    CargoUnchangedLine, CargoUpdateLine, diff_lockfiles, parse_cargo_unchanged_output,
    parse_cargo_update_output,
};
pub(crate) use propose::{filter_ignored_crates, tag_proposals_with_cargo_cohorts};
pub use propose::{
    propose_from_cargo_dry_run, propose_from_cargo_stdout, propose_unchanged_from_cargo_stdout,
};

#[cfg(test)]
use propose::filter_to_direct_deps;

use consumers::resolve_cargo_consumers;
use propose::{run_cargo_proposer, synthesize_dep_proposal};

#[derive(Debug, Default, Clone)]
pub struct CargoEcosystem;

impl DependencyEcosystem for CargoEcosystem {
    fn name(&self) -> &'static str {
        EcosystemName::Cargo.as_str()
    }

    fn detect_manifests(&self, repo: &Path) -> Result<Vec<Manifest>> {
        if !repo.is_dir() {
            return Err(Error::RepoNotFound(repo.to_path_buf()));
        }
        let mut found = Vec::new();
        let root_toml = repo.join("Cargo.toml");
        if root_toml.is_file() {
            found.push(Manifest {
                path: PathBuf::from("Cargo.toml"),
                kind: ManifestKind::CargoToml,
                metadata: BTreeMap::new(),
            });
        }
        let root_lock = repo.join("Cargo.lock");
        if root_lock.is_file() {
            found.push(Manifest {
                path: PathBuf::from("Cargo.lock"),
                kind: ManifestKind::CargoLock,
                metadata: BTreeMap::new(),
            });
        }
        // Member manifests are owned by the workspace root; we don't list
        // each one separately because `cargo update --workspace` resolves
        // the whole graph from the root.
        Ok(found)
    }

    fn propose_updates(
        &self,
        manifests: &[Manifest],
        repo: &Path,
        ctx: &EcosystemContext,
    ) -> Result<Vec<Proposal>> {
        // A Cargo workspace produces one resolver invocation per scan, not
        // per-manifest. If no lockfile was detected, there's nothing to bump.
        let has_lock = manifests
            .iter()
            .any(|m| matches!(m.kind, ManifestKind::CargoLock));
        if !has_lock {
            return Ok(Vec::new());
        }
        let mut proposals = run_cargo_proposer(repo, manifests)?;
        tag_proposals_with_cargo_cohorts(&mut proposals);
        super::cohort_pipeline::widen_cohort_tiers(&mut proposals);
        Ok(filter_ignored_crates(proposals, &ctx.ignored_subjects))
    }

    fn synthesize_dep_proposal(
        &self,
        name: &str,
        target_version: &str,
        manifests: &[Manifest],
        repo: &Path,
        _ctx: &EcosystemContext,
    ) -> Result<Option<Proposal>> {
        synthesize_dep_proposal(name, target_version, manifests, repo)
    }

    fn gate_workflows(&self, _proposal: &Proposal, repo: &Path) -> Result<Vec<PathBuf>> {
        // Default: every CI-named workflow in the repo. The Validator
        // narrows this further via config (`validate_workflows`).
        let workflows_dir = repo.join(".github").join("workflows");
        if !workflows_dir.is_dir() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&workflows_dir).map_err(|source| Error::Io {
            path: workflows_dir.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| Error::Io {
                path: workflows_dir.clone(),
                source,
            })?;
            let path = entry.path();
            let extension = path.extension().and_then(|e| e.to_str());
            if matches!(extension, Some("yml") | Some("yaml")) {
                let rel = path
                    .strip_prefix(repo)
                    .map(Path::to_path_buf)
                    .unwrap_or(path);
                out.push(rel);
            }
        }
        out.sort();
        Ok(out)
    }

    fn affected_consumers(
        &self,
        proposal: &Proposal,
        tree: &Path,
    ) -> Result<Vec<crate::model::ConsumerId>> {
        resolve_cargo_consumers(proposal, tree)
    }

    fn apply_proposal(&self, proposal: &Proposal, tree_path: &Path) -> Result<()> {
        apply_cargo_proposal(proposal, tree_path)
    }

    fn apply_merged(&self, proposals: &[&Proposal], tree_path: &Path) -> Result<()> {
        apply_cargo_proposals_merged(proposals, tree_path)
    }

    fn merge_is_redundant(&self, proposals: &[&Proposal]) -> bool {
        // All-LockfileOnly proposals don't touch Cargo.toml, and
        // `cargo update --workspace` produces a deterministic Cargo.lock
        // shared across every per-proposal sandbox. The merge step's
        // sandbox + revalidate is pure overhead for this case.
        proposals
            .iter()
            .all(|p| matches!(p.bump_tier, BumpTier::LockfileOnly))
    }

    fn copy_back(&self, proposal: &Proposal, sandbox: &Path, host: &Path) -> Result<Vec<PathBuf>> {
        copy_back_cargo_proposal(proposal, sandbox, host)
    }

    fn copy_back_merged(
        &self,
        proposals: &[&Proposal],
        sandbox: &Path,
        host: &Path,
    ) -> Result<Vec<PathBuf>> {
        copy_back_cargo_proposals_merged(proposals, sandbox, host)
    }

    fn pr_body_fragment(&self, proposal: &Proposal, outcome: &ValidationOutcome) -> String {
        format!(
            "- **{crate}**: `{from}` → `{to}` ({classification})",
            crate = proposal.subject,
            from = proposal.from,
            to = proposal.to,
            classification = outcome.classification.as_str(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_STDOUT: &str = "\
    Updating crates.io index
          Updating serde v1.0.200 -> v1.0.215
          Updating tokio v1.40.0 -> v1.42.1
            Adding  brand-new v0.1.0
          Removing oldcrate v0.5.0
";

    #[test]
    fn parse_picks_only_real_version_bumps() {
        let parsed = parse_cargo_update_output(SAMPLE_STDOUT);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].crate_name, "serde");
        assert_eq!(parsed[0].from, "1.0.200");
        assert_eq!(parsed[0].to, "1.0.215");
        assert_eq!(parsed[1].crate_name, "tokio");
        assert_eq!(parsed[1].from, "1.40.0");
        assert_eq!(parsed[1].to, "1.42.1");
    }

    // -------------------------------------------------------------------------
    // parse_cargo_unchanged_output — the constraint-pinned tier feed.
    //
    // Real output captured from `cargo update --dry-run --workspace --verbose`
    // against this repo on 2026-05-17 — covers the three actionable shapes
    // (plain available, available + MSRV note, no available clause) plus
    // build-metadata-suffixed versions (toml's `1.1.2+spec-1.1.0`).
    // -------------------------------------------------------------------------

    const SAMPLE_UNCHANGED_STDOUT: &str = "\
     Locking 0 packages to latest Rust 1.85 compatible versions
   Unchanged cargo_metadata v0.18.1 (available: v0.20.0)
   Unchanged sha2 v0.10.9 (available: v0.11.0)
   Unchanged toml v0.8.23 (available: v1.1.2+spec-1.1.0)
   Unchanged wasip2 v1.0.1+wasi-0.2.4 (available: v1.0.3+wasi-0.2.9, requires Rust 1.87.0)
   Unchanged wasip3 v0.4.0+wasi-0.3.0-rc-2026-01-06 (requires Rust 1.87.0)
warning: not updating lockfile due to dry run
";

    #[test]
    fn parse_unchanged_picks_lines_with_available_clause() {
        let parsed = parse_cargo_unchanged_output(SAMPLE_UNCHANGED_STDOUT);
        // wasip3 has no "available: v..." → skipped. 4 actionable lines.
        assert_eq!(parsed.len(), 4, "got: {parsed:?}");
        assert_eq!(parsed[0].crate_name, "cargo_metadata");
        assert_eq!(parsed[0].from, "0.18.1");
        assert_eq!(parsed[0].to, "0.20.0");
        assert!(parsed[0].requires_rust.is_none());
    }

    #[test]
    fn parse_unchanged_preserves_build_metadata_in_target() {
        let parsed = parse_cargo_unchanged_output(SAMPLE_UNCHANGED_STDOUT);
        let toml = parsed.iter().find(|l| l.crate_name == "toml").unwrap();
        assert_eq!(toml.from, "0.8.23");
        // Build metadata (after `+`) round-trips into the proposal target.
        assert_eq!(toml.to, "1.1.2+spec-1.1.0");
    }

    #[test]
    fn parse_unchanged_splits_msrv_suffix_from_target() {
        let parsed = parse_cargo_unchanged_output(SAMPLE_UNCHANGED_STDOUT);
        let wasip2 = parsed.iter().find(|l| l.crate_name == "wasip2").unwrap();
        assert_eq!(wasip2.from, "1.0.1+wasi-0.2.4");
        // MSRV note must NOT leak into the version string.
        assert_eq!(wasip2.to, "1.0.3+wasi-0.2.9");
        assert_eq!(wasip2.requires_rust.as_deref(), Some("1.87.0"));
    }

    #[test]
    fn parse_unchanged_skips_lines_without_available_clause() {
        // "Unchanged X vOLD (requires Rust X.Y.Z)" — published version is
        // MSRV-blocked but cargo offers no different target. Nothing to
        // propose. The full sample contains a wasip3 line of this shape.
        let parsed = parse_cargo_unchanged_output(SAMPLE_UNCHANGED_STDOUT);
        assert!(!parsed.iter().any(|l| l.crate_name == "wasip3"));
    }

    #[test]
    fn parse_unchanged_ignores_updating_and_other_lines() {
        // A run with both `Updating` and `Unchanged` lines — each parser
        // must yield only its own shape. Verifies they don't poach.
        let stdout = "\
   Updating serde v1.0.200 -> v1.0.215
   Unchanged tokio v1.40.0 (available: v1.42.1)
warning: not updating lockfile due to dry run
";
        let unchanged = parse_cargo_unchanged_output(stdout);
        assert_eq!(unchanged.len(), 1);
        assert_eq!(unchanged[0].crate_name, "tokio");
        let updates = parse_cargo_update_output(stdout);
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].crate_name, "serde");
    }

    // -------------------------------------------------------------------------
    // classify_unchanged_bump — Cargo caret-compat groups.
    // -------------------------------------------------------------------------

    #[test]
    fn classify_within_major_one_or_higher_is_compatible() {
        // 1.x.y / 1.x.y' — same major, any minor/patch difference is in-range.
        assert_eq!(
            classify_unchanged_bump("1.0.0", "1.5.0"),
            BumpTier::Compatible
        );
        assert_eq!(
            classify_unchanged_bump("1.40.0", "1.45.2"),
            BumpTier::Compatible
        );
        assert_eq!(
            classify_unchanged_bump("2.0.0", "2.0.1"),
            BumpTier::Compatible
        );
    }

    #[test]
    fn classify_cross_major_is_breaking() {
        assert_eq!(
            classify_unchanged_bump("1.0.0", "2.0.0"),
            BumpTier::Breaking
        );
        assert_eq!(
            classify_unchanged_bump("0.8.23", "1.1.2"),
            BumpTier::Breaking
        );
    }

    #[test]
    fn classify_zero_dot_x_groups_by_minor() {
        // 0.18.x and 0.18.y are caret-compatible; 0.18.x and 0.20.y are not.
        assert_eq!(
            classify_unchanged_bump("0.18.1", "0.18.7"),
            BumpTier::Compatible
        );
        assert_eq!(
            classify_unchanged_bump("0.18.1", "0.20.0"),
            BumpTier::Breaking
        );
    }

    #[test]
    fn classify_zero_zero_x_treats_every_patch_as_breaking() {
        // Per Cargo's caret rules, every 0.0.x is its own compat group.
        assert_eq!(
            classify_unchanged_bump("0.0.5", "0.0.10"),
            BumpTier::Breaking
        );
        assert_eq!(
            classify_unchanged_bump("0.0.1", "0.0.2"),
            BumpTier::Breaking
        );
    }

    #[test]
    fn classify_handles_build_metadata_suffix() {
        // Build metadata (after `+`) is informational per semver and must
        // not affect the compat-group determination.
        assert_eq!(
            classify_unchanged_bump("1.0.1+wasi-0.2.4", "1.0.3+wasi-0.2.9"),
            BumpTier::Compatible
        );
    }

    #[test]
    fn classify_unparseable_input_defaults_to_breaking() {
        // Defensive — when cargo emits something we can't parse, surface
        // it to the operator (loud) rather than silently treating as
        // compatible. The operator can decide whether to act.
        assert_eq!(
            classify_unchanged_bump("not-a-version", "1.0.0"),
            BumpTier::Breaking
        );
        assert_eq!(
            classify_unchanged_bump("1.0.0", "also-bogus"),
            BumpTier::Breaking
        );
    }

    // -------------------------------------------------------------------------
    // explain_unchanged_bump — structured rationale for --explain.
    // -------------------------------------------------------------------------

    #[test]
    fn explain_same_major_1_plus_returns_compatible_with_major_rule() {
        let exp = explain_unchanged_bump("1.0.100", "1.0.228");
        assert_eq!(exp.decision, "compatible");
        assert_eq!(exp.rule, "cargo:caret-major-1-plus");
        assert_eq!(exp.inputs.get("from").map(String::as_str), Some("1.0.100"));
        assert_eq!(exp.inputs.get("to").map(String::as_str), Some("1.0.228"));
        assert_eq!(
            exp.inputs.get("from_compat_group").map(String::as_str),
            Some("1.0.0")
        );
    }

    #[test]
    fn explain_same_minor_0_x_returns_compatible_with_minor_rule() {
        let exp = explain_unchanged_bump("0.18.1", "0.18.7");
        assert_eq!(exp.decision, "compatible");
        assert_eq!(exp.rule, "cargo:caret-0-x-same-minor");
    }

    #[test]
    fn explain_same_patch_0_0_x_returns_compatible_with_patch_rule() {
        let exp = explain_unchanged_bump("0.0.5", "0.0.5");
        assert_eq!(exp.decision, "compatible");
        assert_eq!(exp.rule, "cargo:caret-0-0-x-same-patch");
    }

    #[test]
    fn explain_cross_major_returns_breaking_with_major_crossed_rule() {
        let exp = explain_unchanged_bump("1.0.0", "2.0.0");
        assert_eq!(exp.decision, "breaking");
        assert_eq!(exp.rule, "cargo:caret-major-crossed");
        assert!(exp.summary.contains("major=1"));
        assert!(exp.summary.contains("major=2"));
    }

    #[test]
    fn explain_cross_minor_in_0_x_returns_breaking_with_minor_crossed_rule() {
        let exp = explain_unchanged_bump("0.18.1", "0.20.0");
        assert_eq!(exp.decision, "breaking");
        assert_eq!(exp.rule, "cargo:caret-0-x-minor-crossed");
    }

    #[test]
    fn explain_cross_patch_in_0_0_x_returns_breaking_with_patch_crossed_rule() {
        let exp = explain_unchanged_bump("0.0.5", "0.0.10");
        assert_eq!(exp.decision, "breaking");
        assert_eq!(exp.rule, "cargo:caret-0-0-x-patch-crossed");
    }

    #[test]
    fn explain_unparseable_returns_breaking_with_unparseable_rule() {
        let exp = explain_unchanged_bump("not-a-version", "1.0.0");
        assert_eq!(exp.decision, "breaking");
        assert_eq!(exp.rule, "cargo:unparseable-semver");
    }

    #[test]
    fn explain_lockfile_only_carries_constraint_when_supplied() {
        let exp = explain_lockfile_only_bump("1.0.100", "1.0.228", Some("^1.0"));
        assert_eq!(exp.decision, "lockfile-only");
        assert_eq!(exp.rule, "cargo:lockfile-within-constraint");
        assert_eq!(
            exp.inputs.get("constraint").map(String::as_str),
            Some("^1.0")
        );
        assert!(exp.summary.contains("^1.0"));
    }

    #[test]
    fn explain_lockfile_only_omits_constraint_when_unknown() {
        let exp = explain_lockfile_only_bump("1.0.100", "1.0.228", None);
        assert!(!exp.inputs.contains_key("constraint"));
        assert!(!exp.summary.contains("`"));
    }

    #[test]
    fn parse_unchanged_returns_empty_for_no_verbose_output() {
        // The non-verbose `cargo update --dry-run` output contains a
        // `note:` line about hidden deps but no `Unchanged` lines. Must
        // parse cleanly to an empty list, not crash on the suggestion.
        let stdout = "     Locking 0 packages to latest Rust 1.93.1 compatible versions\nnote: pass `--verbose` to see 110 unchanged dependencies behind latest\n";
        let parsed = parse_cargo_unchanged_output(stdout);
        assert!(parsed.is_empty());
    }

    #[test]
    fn parse_handles_indented_and_unindented_lines() {
        let stdout = "Updating serde v1.0.200 -> v1.0.215\n   Updating tokio v1.0.0 -> v1.1.0\n";
        let parsed = parse_cargo_update_output(stdout);
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn parse_skips_index_update_header() {
        let stdout = "Updating crates.io index\n";
        let parsed = parse_cargo_update_output(stdout);
        assert!(parsed.is_empty());
    }

    #[test]
    fn propose_from_cargo_stdout_builds_proposal_per_updating_line() {
        let stdout = "Updating crates.io index\n   Updating serde v1.0.200 -> v1.0.215\n   Updating tokio v1.40.0 -> v1.42.0\n";
        let proposals = propose_from_cargo_stdout(stdout, &[PathBuf::from("Cargo.lock")]).unwrap();
        assert_eq!(proposals.len(), 2);
        let serde = proposals.iter().find(|p| p.subject == "serde").unwrap();
        assert_eq!(serde.from, "1.0.200");
        assert_eq!(serde.to, "1.0.215");
        assert_eq!(serde.id, "cargo-serde-1-0-200-to-1-0-215");
        assert_eq!(serde.manifest_paths, vec![PathBuf::from("Cargo.lock")]);
        assert!(
            proposals.iter().any(|p| p.subject == "tokio"),
            "tokio proposal must be present"
        );
    }

    // -------------------------------------------------------------------------
    // propose_unchanged_from_cargo_stdout — Compatible/Breaking proposals.
    // -------------------------------------------------------------------------

    #[test]
    fn propose_unchanged_emits_tier_aware_proposals() {
        let stdout = "\
   Unchanged cargo_metadata v0.18.1 (available: v0.20.0)
   Unchanged tokio v1.40.0 (available: v1.45.2)
   Unchanged serde v1.0.200 (available: v2.0.0)
";
        let proposals = propose_unchanged_from_cargo_stdout(stdout, &[PathBuf::from("Cargo.toml")]);
        assert_eq!(proposals.len(), 3);

        let by_subject: BTreeMap<&str, &Proposal> =
            proposals.iter().map(|p| (p.subject.as_str(), p)).collect();

        // 0.18.1 -> 0.20.0 crosses Cargo's 0.x compat group → Breaking.
        let meta = by_subject["cargo_metadata"];
        assert_eq!(meta.bump_tier, crate::model::BumpTier::Breaking);
        assert_eq!(meta.from, "0.18.1");
        assert_eq!(meta.to, "0.20.0");

        // 1.40 -> 1.45 stays within major 1 → Compatible.
        let tokio = by_subject["tokio"];
        assert_eq!(tokio.bump_tier, crate::model::BumpTier::Compatible);

        // 1.0 -> 2.0 crosses major → Breaking.
        let serde = by_subject["serde"];
        assert_eq!(serde.bump_tier, crate::model::BumpTier::Breaking);
    }

    #[test]
    fn propose_unchanged_attaches_msrv_note_when_present() {
        let stdout = "   Unchanged wasip2 v1.0.1+wasi-0.2.4 (available: v1.0.3+wasi-0.2.9, requires Rust 1.87.0)\n";
        let proposals = propose_unchanged_from_cargo_stdout(stdout, &[]);
        assert_eq!(proposals.len(), 1);
        let p = &proposals[0];
        assert_eq!(p.bump_tier, crate::model::BumpTier::Compatible);
        assert!(
            p.notes.iter().any(|n| n.contains("Rust 1.87.0")),
            "MSRV note must ride along: {:?}",
            p.notes,
        );
    }

    #[test]
    fn propose_unchanged_returns_empty_when_no_unchanged_lines() {
        let stdout = "   Updating serde v1.0.200 -> v1.0.215\n";
        let proposals = propose_unchanged_from_cargo_stdout(stdout, &[]);
        assert!(proposals.is_empty());
    }

    #[test]
    fn filter_to_direct_deps_keeps_only_named_subjects() {
        // Real-world failure mode caught in dogfood: cargo's verbose
        // output mentions transitive deps (generic-array, wasip2) that
        // aren't in any of our manifests. The applier would refuse to
        // widen them. The proposer must drop them before they ship.
        use std::collections::BTreeSet;
        let proposals = vec![
            sample_cargo_proposal_named("serde"),
            sample_cargo_proposal_named("generic-array"),
            sample_cargo_proposal_named("tokio"),
            sample_cargo_proposal_named("wasip2"),
        ];
        let direct: BTreeSet<String> = ["serde", "tokio"].iter().map(|s| s.to_string()).collect();
        let kept = filter_to_direct_deps(proposals, &direct);
        let subjects: Vec<&str> = kept.iter().map(|p| p.subject.as_str()).collect();
        assert_eq!(subjects, vec!["serde", "tokio"]);
    }

    fn sample_cargo_proposal_named(name: &str) -> Proposal {
        Proposal {
            id: format!("cargo-{name}-test"),
            ecosystem: "cargo".into(),
            kind: crate::model::ProposalKind::Version,
            subject: name.into(),
            from: "1.0.0".into(),
            to: "1.5.0".into(),
            initial_classification: crate::model::Classification::Exact,
            manifest_paths: vec![],
            notes: vec![],
            bump_tier: BumpTier::Compatible,
            affected_consumers: Vec::new(),
            explanation: None,
            cohort: None,
        }
    }

    #[test]
    fn propose_from_cargo_stdout_returns_empty_when_nothing_to_update() {
        // Cargo's "Locking 0 packages..." line + a verbose note. No
        // "Updating X v1 -> v2" lines means no proposals — assay should
        // report nothing-to-do cleanly, not crash.
        let stdout = "     Locking 0 packages to latest Rust 1.93.1 compatible versions\nnote: pass `--verbose` to see 110 unchanged dependencies behind latest\nwarning: not updating lockfile due to dry run\n";
        let proposals = propose_from_cargo_stdout(stdout, &[PathBuf::from("Cargo.lock")]).unwrap();
        assert!(proposals.is_empty());
    }

    fn lockfile_with(packages: &[(&str, &str)]) -> String {
        let mut out = String::from("version = 3\n");
        for (name, ver) in packages {
            out.push_str(&format!(
                "[[package]]\nname = \"{name}\"\nversion = \"{ver}\"\n\n"
            ));
        }
        out
    }

    #[test]
    fn diff_lockfiles_detects_version_change() {
        let before = lockfile_with(&[("serde", "1.0.200"), ("tokio", "1.40.0")]);
        let after = lockfile_with(&[("serde", "1.0.215"), ("tokio", "1.40.0")]);
        let diff = diff_lockfiles(&before, &after).expect("diff ok");
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].crate_name, "serde");
        assert_eq!(diff[0].from, "1.0.200");
        assert_eq!(diff[0].to, "1.0.215");
    }

    #[test]
    fn diff_lockfiles_ignores_new_packages() {
        let before = lockfile_with(&[("serde", "1.0.200")]);
        let after = lockfile_with(&[("serde", "1.0.200"), ("new", "0.1.0")]);
        let diff = diff_lockfiles(&before, &after).expect("diff ok");
        assert!(diff.is_empty(), "added packages aren't bumps: {diff:?}");
    }

    #[test]
    fn cross_check_passes_when_stdout_matches_lockfile() {
        let stdout = "Updating serde v1.0.200 -> v1.0.215\n";
        let before = lockfile_with(&[("serde", "1.0.200")]);
        let after = lockfile_with(&[("serde", "1.0.215")]);
        let proposals = propose_from_cargo_dry_run(stdout, &before, &after, &[])
            .expect("cross-check should pass");
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].subject, "serde");
        assert_eq!(proposals[0].from, "1.0.200");
        assert_eq!(proposals[0].to, "1.0.215");
        assert!(proposals[0].id.starts_with("cargo-serde-"));
    }

    #[test]
    fn cross_check_fails_when_stdout_omits_a_real_bump() {
        // stdout claims nothing changed, but the lockfile shows serde bumped.
        let stdout = "Updating crates.io index\n";
        let before = lockfile_with(&[("serde", "1.0.200")]);
        let after = lockfile_with(&[("serde", "1.0.215")]);
        let err = propose_from_cargo_dry_run(stdout, &before, &after, &[])
            .expect_err("must fail when parser disagrees");
        assert!(
            matches!(err, Error::CargoParserMismatch { .. }),
            "expected CargoParserMismatch, got {err:?}"
        );
    }

    #[test]
    fn cross_check_fails_when_stdout_fabricates_a_bump() {
        // stdout claims serde bumped but the lockfile shows no change.
        let stdout = "Updating serde v1.0.200 -> v1.0.215\n";
        let lock = lockfile_with(&[("serde", "1.0.200")]);
        let err = propose_from_cargo_dry_run(stdout, &lock, &lock, &[])
            .expect_err("must fail when stdout invents a bump");
        assert!(matches!(err, Error::CargoParserMismatch { .. }));
    }

    #[test]
    fn cross_check_fails_when_versions_disagree() {
        let stdout = "Updating serde v1.0.200 -> v1.0.215\n";
        let before = lockfile_with(&[("serde", "1.0.200")]);
        // Lockfile diff says it went to a different version.
        let after = lockfile_with(&[("serde", "1.0.300")]);
        let err = propose_from_cargo_dry_run(stdout, &before, &after, &[])
            .expect_err("must fail on version mismatch");
        assert!(matches!(err, Error::CargoParserMismatch { .. }));
    }

    #[test]
    fn proposal_id_is_deterministic_and_safe() {
        let stdout = "Updating Foo-Bar v1.0.0-alpha+build.5 -> v1.1.0-beta+build.6\n";
        let before = lockfile_with(&[("Foo-Bar", "1.0.0-alpha+build.5")]);
        let after = lockfile_with(&[("Foo-Bar", "1.1.0-beta+build.6")]);
        let proposals = propose_from_cargo_dry_run(stdout, &before, &after, &[]).unwrap();
        assert_eq!(proposals.len(), 1);
        let id = &proposals[0].id;
        // ID must be branch-safe: lowercase, alphanumeric or '-' only,
        // no leading/trailing dashes.
        assert!(id.starts_with("cargo-foo-bar-"));
        for ch in id.chars() {
            assert!(
                ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-',
                "id contains illegal char {ch:?}: {id}"
            );
        }
        assert!(!id.starts_with('-') && !id.ends_with('-'));
    }

    #[test]
    fn synthesize_dep_proposal_builds_proposal_when_dep_in_lockfile() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        std::fs::write(repo.join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
        std::fs::write(
            repo.join("Cargo.lock"),
            lockfile_with(&[("serde", "1.0.100")]),
        )
        .unwrap();
        let eco = CargoEcosystem;
        let manifests = eco.detect_manifests(repo).unwrap();
        let ctx = EcosystemContext::default();
        let proposal = eco
            .synthesize_dep_proposal("serde", "1.0.228", &manifests, repo, &ctx)
            .unwrap()
            .expect("synthesize should produce a proposal");
        assert_eq!(proposal.subject, "serde");
        assert_eq!(proposal.from, "1.0.100");
        assert_eq!(proposal.to, "1.0.228");
        // Same caret group (^1) → Compatible.
        assert!(matches!(proposal.bump_tier, BumpTier::Compatible));
        // The `--dep` notes marker exists so the receipt explains
        // why this proposal isn't paired with a discovered bump.
        assert!(
            proposal.notes.iter().any(|n| n.contains("--dep")),
            "expected --dep source marker, got {:?}",
            proposal.notes,
        );
    }

    #[test]
    fn synthesize_dep_proposal_returns_none_when_dep_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        std::fs::write(repo.join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
        std::fs::write(
            repo.join("Cargo.lock"),
            lockfile_with(&[("serde", "1.0.100")]),
        )
        .unwrap();
        let eco = CargoEcosystem;
        let manifests = eco.detect_manifests(repo).unwrap();
        let ctx = EcosystemContext::default();
        let result = eco
            .synthesize_dep_proposal("nonexistent-crate", "1.0.0", &manifests, repo, &ctx)
            .unwrap();
        assert!(result.is_none(), "expected None for absent crate");
    }

    #[test]
    fn synthesize_dep_proposal_returns_none_when_already_at_target() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        std::fs::write(repo.join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
        std::fs::write(
            repo.join("Cargo.lock"),
            lockfile_with(&[("tokio", "1.45.0")]),
        )
        .unwrap();
        let eco = CargoEcosystem;
        let manifests = eco.detect_manifests(repo).unwrap();
        let ctx = EcosystemContext::default();
        let result = eco
            .synthesize_dep_proposal("tokio", "1.45.0", &manifests, repo, &ctx)
            .unwrap();
        assert!(result.is_none(), "expected None when already at target");
    }

    #[test]
    fn synthesize_dep_proposal_classifies_major_bump_as_breaking() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        std::fs::write(repo.join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
        std::fs::write(repo.join("Cargo.lock"), lockfile_with(&[("clap", "3.2.0")])).unwrap();
        let eco = CargoEcosystem;
        let manifests = eco.detect_manifests(repo).unwrap();
        let ctx = EcosystemContext::default();
        let proposal = eco
            .synthesize_dep_proposal("clap", "4.0.0", &manifests, repo, &ctx)
            .unwrap()
            .expect("synthesize should produce a proposal");
        assert!(matches!(proposal.bump_tier, BumpTier::Breaking));
    }

    #[test]
    fn detect_manifests_finds_root_toml_and_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        std::fs::write(repo.join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
        std::fs::write(repo.join("Cargo.lock"), lockfile_with(&[])).unwrap();
        let eco = CargoEcosystem;
        let manifests = eco.detect_manifests(repo).unwrap();
        assert_eq!(manifests.len(), 2);
        assert!(
            manifests
                .iter()
                .any(|m| matches!(m.kind, ManifestKind::CargoToml))
        );
        assert!(
            manifests
                .iter()
                .any(|m| matches!(m.kind, ManifestKind::CargoLock))
        );
    }

    #[test]
    fn detect_manifests_returns_empty_for_non_cargo_repo() {
        let tmp = tempfile::tempdir().unwrap();
        let eco = CargoEcosystem;
        let manifests = eco.detect_manifests(tmp.path()).unwrap();
        assert!(manifests.is_empty());
    }

    #[test]
    fn apply_cargo_update_rejects_tree_without_cargo_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let err = apply_cargo_update_to_tree(tmp.path()).expect_err("missing Cargo.toml must fail");
        match err {
            Error::InvalidManifest { path, message } => {
                assert!(path.ends_with("Cargo.toml"));
                assert!(message.contains("not found"));
            }
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn copy_back_copies_sandbox_lockfile_to_host() {
        let sandbox = tempfile::tempdir().unwrap();
        let host = tempfile::tempdir().unwrap();
        std::fs::write(sandbox.path().join("Cargo.toml"), "[workspace]\n").unwrap();
        std::fs::write(host.path().join("Cargo.toml"), "[workspace]\n").unwrap();
        let sandbox_lock_contents = lockfile_with(&[("serde", "1.0.215")]);
        std::fs::write(sandbox.path().join("Cargo.lock"), &sandbox_lock_contents).unwrap();
        // Host starts with an older lock — copy-back must overwrite.
        std::fs::write(
            host.path().join("Cargo.lock"),
            lockfile_with(&[("serde", "1.0.200")]),
        )
        .unwrap();

        let eco = CargoEcosystem;
        let proposal = sample_cargo_proposal();
        let modified = eco
            .copy_back(&proposal, sandbox.path(), host.path())
            .expect("copy-back should succeed");
        assert_eq!(modified, vec![PathBuf::from("Cargo.lock")]);
        let post = std::fs::read_to_string(host.path().join("Cargo.lock")).unwrap();
        assert_eq!(post, sandbox_lock_contents);
    }

    #[test]
    fn copy_back_errors_when_sandbox_lockfile_missing() {
        let sandbox = tempfile::tempdir().unwrap();
        let host = tempfile::tempdir().unwrap();
        std::fs::write(host.path().join("Cargo.toml"), "[workspace]\n").unwrap();
        let eco = CargoEcosystem;
        let proposal = sample_cargo_proposal();
        let err = eco
            .copy_back(&proposal, sandbox.path(), host.path())
            .expect_err("copy-back without sandbox lock should fail");
        assert!(
            err.to_string().contains("missing from sandbox"),
            "error should explain the missing lockfile: {err}"
        );
    }

    fn sample_cargo_proposal() -> Proposal {
        Proposal {
            id: "cargo-serde-1-0-215".into(),
            ecosystem: "cargo".into(),
            kind: crate::model::ProposalKind::Version,
            subject: "serde".into(),
            from: "1.0.200".into(),
            to: "1.0.215".into(),
            initial_classification: crate::model::Classification::Exact,
            manifest_paths: vec![],
            notes: vec![],
            bump_tier: BumpTier::LockfileOnly,
            affected_consumers: Vec::new(),
            explanation: None,
            cohort: None,
        }
    }

    #[test]
    fn gate_workflows_lists_yml_files_only() {
        let tmp = tempfile::tempdir().unwrap();
        let workflows = tmp.path().join(".github").join("workflows");
        std::fs::create_dir_all(&workflows).unwrap();
        std::fs::write(workflows.join("ci.yml"), "name: ci\n").unwrap();
        std::fs::write(workflows.join("release.yaml"), "name: release\n").unwrap();
        std::fs::write(workflows.join("README.md"), "# notes\n").unwrap();
        let eco = CargoEcosystem;
        let stub_proposal = Proposal {
            id: "stub".into(),
            ecosystem: EcosystemName::Cargo.as_str().into(),
            kind: ProposalKind::Version,
            subject: "serde".into(),
            from: "1".into(),
            to: "2".into(),
            initial_classification: Classification::Exact,
            manifest_paths: vec![],
            notes: vec![],
            bump_tier: BumpTier::LockfileOnly,
            affected_consumers: Vec::new(),
            explanation: None,
            cohort: None,
        };
        let mut workflows = eco.gate_workflows(&stub_proposal, tmp.path()).unwrap();
        workflows.sort();
        assert_eq!(workflows.len(), 2);
        assert!(workflows.iter().any(|p| p.ends_with("ci.yml")));
        assert!(workflows.iter().any(|p| p.ends_with("release.yaml")));
    }

    // -------------------------------------------------------------------------
    // affected_consumers (Resolver — plan §C.3.5)
    // -------------------------------------------------------------------------

    /// Helper: scaffolds a synthetic Cargo workspace with members named
    /// `a`, `b`, `c` where the supplied closure decides each member's deps.
    /// Empty src/lib.rs files keep the manifests valid for `cargo metadata`.
    fn build_workspace_with(root: &Path, dep_lines: &[(&str, &str)]) {
        std::fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nresolver = \"2\"\nmembers = [\"a\", \"b\", \"c\"]\n",
        )
        .unwrap();
        let mut deps_per_member: BTreeMap<&str, &str> = BTreeMap::new();
        for (member, dep_line) in dep_lines {
            deps_per_member.insert(member, dep_line);
        }
        for member in ["a", "b", "c"] {
            let dir = root.join(member);
            std::fs::create_dir(&dir).unwrap();
            std::fs::create_dir(dir.join("src")).unwrap();
            std::fs::write(dir.join("src/lib.rs"), "").unwrap();
            let deps = deps_per_member.get(member).unwrap_or(&"");
            std::fs::write(
                dir.join("Cargo.toml"),
                format!(
                    "[package]\nname = \"{member}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n{deps}\n"
                ),
            )
            .unwrap();
        }
    }

    fn proposal_for(subject: &str) -> Proposal {
        Proposal {
            id: format!("cargo-{subject}-bump"),
            ecosystem: EcosystemName::Cargo.as_str().into(),
            kind: ProposalKind::Version,
            subject: subject.into(),
            from: "0.1.0".into(),
            to: "0.2.0".into(),
            initial_classification: Classification::Exact,
            manifest_paths: vec![],
            notes: vec![],
            bump_tier: BumpTier::LockfileOnly,
            affected_consumers: Vec::new(),
            explanation: None,
            cohort: None,
        }
    }

    #[test]
    fn affected_consumers_lists_workspace_members_consuming_target() {
        // Workspace: a and c depend on b; b stands alone.
        // affected_consumers(b) should return [a, c] — b is NOT its own
        // consumer.
        let tmp = tempfile::tempdir().unwrap();
        build_workspace_with(
            tmp.path(),
            &[
                ("a", "b = { path = \"../b\" }"),
                ("c", "b = { path = \"../b\" }"),
            ],
        );
        let eco = CargoEcosystem;
        let consumers = eco
            .affected_consumers(&proposal_for("b"), tmp.path())
            .unwrap();
        assert_eq!(consumers, vec!["a".to_string(), "c".to_string()]);
    }

    #[test]
    fn affected_consumers_returns_empty_when_target_absent_from_workspace() {
        // No member depends on `nowhere-crate`; no package named that exists
        // in the workspace. Resolver returns empty.
        let tmp = tempfile::tempdir().unwrap();
        build_workspace_with(tmp.path(), &[]);
        let eco = CargoEcosystem;
        let consumers = eco
            .affected_consumers(&proposal_for("nowhere-crate"), tmp.path())
            .unwrap();
        assert!(
            consumers.is_empty(),
            "non-consumed target should yield empty list: {consumers:?}"
        );
    }

    #[test]
    fn affected_consumers_excludes_self_when_target_is_workspace_member() {
        // Only `b` itself "consumes" b's identity — but the Resolver should
        // not list b as a consumer of itself. With no other members
        // depending on b, the result is empty.
        let tmp = tempfile::tempdir().unwrap();
        build_workspace_with(tmp.path(), &[]); // nobody depends on b
        let eco = CargoEcosystem;
        let consumers = eco
            .affected_consumers(&proposal_for("b"), tmp.path())
            .unwrap();
        assert!(
            consumers.is_empty(),
            "b should not be its own consumer: {consumers:?}"
        );
    }

    #[test]
    fn affected_consumers_rejects_tree_without_cargo_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let eco = CargoEcosystem;
        let result = eco.affected_consumers(&proposal_for("anything"), tmp.path());
        match result {
            Err(Error::InvalidManifest { path, .. }) => {
                assert!(path.ends_with("Cargo.toml"));
            }
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn affected_consumers_includes_optional_feature_gated_consumers() {
        // Real-world case caught by the ruff stress dogfood (2026-05-18):
        // `crates/ruff_benchmark/Cargo.toml` declares
        //   codspeed-criterion-compat = { workspace = true,
        //                                  default-features = false,
        //                                  optional = true }
        // gated by the `codspeed` feature. Pre-fix this disappeared from
        // the consumer list because `cargo metadata` (default features
        // only) excluded it from the resolve graph, leaving the proposal
        // line with no consumer suffix — silently understating the blast
        // radius. With `CargoOpt::AllFeatures` the optional dep enters
        // the resolve graph and the consumer is reported.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("Cargo.toml"),
            "[workspace]\nresolver = \"2\"\nmembers = [\"a\", \"b\"]\n",
        )
        .unwrap();
        for member in ["a", "b"] {
            let dir = tmp.path().join(member);
            std::fs::create_dir(&dir).unwrap();
            std::fs::create_dir(dir.join("src")).unwrap();
            std::fs::write(dir.join("src/lib.rs"), "").unwrap();
        }
        std::fs::write(
            tmp.path().join("a/Cargo.toml"),
            "[package]\n\
                name = \"a\"\n\
                version = \"0.1.0\"\n\
                edition = \"2021\"\n\
                \n\
                [dependencies]\n\
                b = { path = \"../b\", optional = true }\n\
                \n\
                [features]\n\
                codspeed = [\"b\"]\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("b/Cargo.toml"),
            "[package]\nname = \"b\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        let eco = CargoEcosystem;
        let consumers = eco
            .affected_consumers(&proposal_for("b"), tmp.path())
            .unwrap();
        assert_eq!(
            consumers,
            vec!["a".to_string()],
            "optional+feature-gated consumer must appear in blast-radius list",
        );
    }

    // -------------------------------------------------------------------------
    // Multi-proposal merge applier — apply_cargo_proposals_merged
    // -------------------------------------------------------------------------

    fn proposal_with_tier(subject: &str, tier: BumpTier) -> Proposal {
        Proposal {
            bump_tier: tier,
            affected_consumers: Vec::new(),
            explanation: None,
            subject: subject.into(),
            id: format!("cargo-{subject}-1-2-3"),
            ..sample_cargo_proposal()
        }
    }

    #[test]
    fn merge_is_redundant_returns_true_for_all_lockfile_only() {
        let eco = CargoEcosystem;
        let a = proposal_with_tier("serde", BumpTier::LockfileOnly);
        let b = proposal_with_tier("tokio", BumpTier::LockfileOnly);
        let c = proposal_with_tier("reqwest", BumpTier::LockfileOnly);
        let proposals: Vec<&Proposal> = vec![&a, &b, &c];
        assert!(eco.merge_is_redundant(&proposals));
    }

    #[test]
    fn merge_is_redundant_returns_false_when_any_compatible_present() {
        let eco = CargoEcosystem;
        let a = proposal_with_tier("serde", BumpTier::LockfileOnly);
        let b = proposal_with_tier("tokio", BumpTier::Compatible);
        let proposals: Vec<&Proposal> = vec![&a, &b];
        assert!(!eco.merge_is_redundant(&proposals));
    }

    #[test]
    fn merge_is_redundant_returns_false_when_any_breaking_present() {
        let eco = CargoEcosystem;
        let a = proposal_with_tier("serde", BumpTier::LockfileOnly);
        let b = proposal_with_tier("tokio", BumpTier::Breaking);
        let proposals: Vec<&Proposal> = vec![&a, &b];
        assert!(!eco.merge_is_redundant(&proposals));
    }

    #[test]
    fn copy_back_merged_ships_lockfile_for_all_lockfile_only_set() {
        // All-LockfileOnly: copy_back_merged must ship JUST Cargo.lock
        // — manifest scan is skipped because no proposal touched
        // Cargo.toml in the merge sandbox.
        let sandbox = tempfile::tempdir().unwrap();
        let host = tempfile::tempdir().unwrap();
        // Sandbox + host both look like a single-crate workspace.
        std::fs::write(
            sandbox.path().join("Cargo.toml"),
            "[workspace]\nresolver = \"2\"\nmembers = []\n",
        )
        .unwrap();
        std::fs::write(
            host.path().join("Cargo.toml"),
            "[workspace]\nresolver = \"2\"\nmembers = []\n",
        )
        .unwrap();
        let sandbox_lock = lockfile_with(&[("serde", "1.0.215")]);
        std::fs::write(sandbox.path().join("Cargo.lock"), &sandbox_lock).unwrap();
        std::fs::write(host.path().join("Cargo.lock"), "version = 3\n").unwrap();

        let a = proposal_with_tier("serde", BumpTier::LockfileOnly);
        let b = proposal_with_tier("tokio", BumpTier::LockfileOnly);
        let proposals: Vec<&Proposal> = vec![&a, &b];
        let modified = copy_back_cargo_proposals_merged(&proposals, sandbox.path(), host.path())
            .expect("copy-back-merged should succeed");
        assert_eq!(modified, vec![PathBuf::from("Cargo.lock")]);
        let post = std::fs::read_to_string(host.path().join("Cargo.lock")).unwrap();
        assert_eq!(post, sandbox_lock);
    }

    #[test]
    fn copy_back_merged_ships_lockfile_and_diffed_manifests_for_mixed_set() {
        // Mixed-tier (any non-LockfileOnly present): walks the workspace
        // manifests and ships any whose bytes differ between sandbox + host.
        let sandbox = tempfile::tempdir().unwrap();
        let host = tempfile::tempdir().unwrap();
        // Workspace root, one member `a`. Both sandbox + host start
        // identical except for `a/Cargo.toml` — sandbox's manifest has
        // a widened constraint on tokio.
        for root in [sandbox.path(), host.path()] {
            std::fs::write(
                root.join("Cargo.toml"),
                "[workspace]\nresolver = \"2\"\nmembers = [\"a\"]\n",
            )
            .unwrap();
            std::fs::create_dir(root.join("a")).unwrap();
            std::fs::create_dir(root.join("a/src")).unwrap();
            std::fs::write(root.join("a/src/lib.rs"), "").unwrap();
        }
        // Sandbox has the widened constraint; host has the narrower one.
        std::fs::write(
            sandbox.path().join("a/Cargo.toml"),
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ntokio = \"1.45\"\n",
        )
        .unwrap();
        std::fs::write(
            host.path().join("a/Cargo.toml"),
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ntokio = \"1.40\"\n",
        )
        .unwrap();
        let sandbox_lock = lockfile_with(&[("tokio", "1.45.0")]);
        std::fs::write(sandbox.path().join("Cargo.lock"), &sandbox_lock).unwrap();
        std::fs::write(
            host.path().join("Cargo.lock"),
            lockfile_with(&[("tokio", "1.40.0")]),
        )
        .unwrap();

        let p = proposal_with_tier("tokio", BumpTier::Compatible);
        let proposals: Vec<&Proposal> = vec![&p];
        let modified = copy_back_cargo_proposals_merged(&proposals, sandbox.path(), host.path())
            .expect("copy-back-merged should succeed");
        // Cargo.lock + a/Cargo.toml (workspace root unchanged → not
        // copied).
        assert!(modified.contains(&PathBuf::from("Cargo.lock")));
        assert!(
            modified.contains(&PathBuf::from("a").join("Cargo.toml")),
            "the widened member manifest must be in the copy-back set: got {modified:?}"
        );
        // Workspace root is identical in both → must NOT appear.
        assert!(
            !modified.contains(&PathBuf::from("Cargo.toml")),
            "unchanged workspace root must not be copied: got {modified:?}"
        );
        let post_member = std::fs::read_to_string(host.path().join("a/Cargo.toml")).unwrap();
        assert!(post_member.contains("tokio = \"1.45\""));
        let post_lock = std::fs::read_to_string(host.path().join("Cargo.lock")).unwrap();
        assert_eq!(post_lock, sandbox_lock);
    }

    #[test]
    fn copy_back_merged_errors_when_sandbox_lockfile_missing() {
        let sandbox = tempfile::tempdir().unwrap();
        let host = tempfile::tempdir().unwrap();
        std::fs::write(host.path().join("Cargo.toml"), "[workspace]\n").unwrap();
        let p = proposal_with_tier("serde", BumpTier::LockfileOnly);
        let proposals: Vec<&Proposal> = vec![&p];
        let err = copy_back_cargo_proposals_merged(&proposals, sandbox.path(), host.path())
            .expect_err("must reject missing sandbox lock");
        assert!(
            format!("{err}").contains("Cargo.lock missing"),
            "error should explain the missing lockfile: {err}"
        );
    }

    #[test]
    fn apply_cargo_proposals_merged_errors_when_constraint_widening_target_absent() {
        // Compatible/Breaking proposal targeting a crate that's NOT in
        // the workspace manifest must fail with the cargo applier's
        // canonical "no manifest carried a matching dep entry" message.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("Cargo.toml"),
            "[workspace]\nresolver = \"2\"\nmembers = []\n",
        )
        .unwrap();
        let p = proposal_with_tier("nonexistent-crate", BumpTier::Compatible);
        let proposals: Vec<&Proposal> = vec![&p];
        let err = apply_cargo_proposals_merged(&proposals, tmp.path())
            .expect_err("must fail when no manifest carries the target");
        assert!(
            format!("{err}").contains("no manifest carried a matching dep entry"),
            "error should explain the missing target: {err}"
        );
    }

    #[test]
    fn propose_from_cargo_stdout_id_disambiguates_by_source_version() {
        // `cargo update` against a transitive crate present at two
        // different versions in the lockfile (helm/mortar dogfood
        // case: reqwest 0.12.28 AND 0.13.2 both bumping to 0.13.3)
        // must produce distinct proposal IDs so apply-pr's branch-
        // per-proposal flow doesn't clobber one branch with another.
        // The fix wedges the `from` segment between the crate name
        // and the target version: `cargo-reqwest-0-12-28-to-0-13-3`.
        let stdout = "    Updating reqwest v0.12.28 -> v0.13.3\n\
                      Updating reqwest v0.13.2 -> v0.13.3\n";
        let manifest_paths = vec![PathBuf::from("Cargo.toml")];
        let proposals = propose_from_cargo_stdout(stdout, &manifest_paths).unwrap();
        assert_eq!(proposals.len(), 2);
        assert_ne!(
            proposals[0].id, proposals[1].id,
            "same-target multi-version transitive bumps must produce distinct IDs"
        );
        for p in &proposals {
            assert!(
                p.id.starts_with("cargo-reqwest-") && p.id.contains("-to-0-13-3"),
                "id should include both from and to segments: {}",
                p.id
            );
        }
    }

    #[test]
    fn filter_ignored_crates_drops_matching_subject() {
        let proposals = vec![
            Proposal {
                subject: "reqwest".into(),
                ..proposal_with_tier("reqwest", BumpTier::Compatible)
            },
            Proposal {
                subject: "tokio".into(),
                ..proposal_with_tier("tokio", BumpTier::Compatible)
            },
        ];
        let kept = filter_ignored_crates(proposals, &["reqwest".to_string()]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].subject, "tokio");
    }
}
