//! npm / pnpm ecosystem.
//!
//! Detects `package.json` + a lockfile (`package-lock.json`, `pnpm-lock.yaml`,
//! or `yarn.lock`) and proposes version bumps by shelling out to the matching
//! package manager's `outdated` reporter. Both npm and pnpm emit a
//! near-identical JSON shape:
//!
//! ```json
//! {
//!   "lodash": {
//!     "current": "4.17.20",
//!     "wanted":  "4.17.21",
//!     "latest":  "5.0.0"
//!   }
//! }
//! ```
//!
//! - `current` — what's resolved in the lockfile.
//! - `wanted` — highest in-range version (lockfile would pick this on
//!   `npm update <pkg>`).
//! - `latest` — most recent publish on the registry.
//!
//! Tier mapping:
//! - `wanted == latest` → [`BumpTier::LockfileOnly`]. Constraint allows
//!   latest; only the lockfile needs to change.
//! - `wanted != latest` → [`BumpTier::Compatible`] or [`BumpTier::Breaking`]
//!   based on the caret-compat group of (`current`, `latest`). The
//!   manifest constraint must be widened.
//!
//! Yarn 1 emits a different NDJSON shape (`{"type":"table","data":{...}}`)
//! which the proposer parses via `parse_yarn1_outdated_output`. The
//! applier shells out to `yarn upgrade <pkg>@<v> --exact` with the same
//! snapshot/restore wrapper used for npm LockfileOnly bumps. Yarn 2+
//! ("Berry") offers `yarn npm outdated --json` in the npm shape and
//! could be added later — it falls through the npm path if the operator
//! has set up `nodeLinker: node-modules`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::model::{ConsumerId, Manifest, ManifestKind, Proposal, ValidationOutcome};

use super::{DependencyEcosystem, EcosystemContext, EcosystemName};

mod apply;
mod berry;
mod classify;
mod direct_deps;
mod flavor;
mod outdated;
mod peer_walk;
mod propose;
mod workspaces;

pub(crate) use classify::{explain_npm_bump, explain_npm_lockfile_only_bump};

#[cfg(test)]
use crate::model::{BumpTier, Classification, ProposalKind};
#[cfg(test)]
use std::collections::BTreeSet;

#[cfg(test)]
use apply::{
    preserve_constraint_prefix, resolve_install_version, try_edit_package_json,
    update_package_json_constraint,
};
#[cfg(test)]
use berry::{parse_berry_descriptor_name, parse_berry_lockfile, propose_berry_updates};
#[cfg(test)]
use classify::classify_npm_bump;
#[cfg(test)]
use direct_deps::{collect_direct_dep_names, collect_direct_deps_with_constraints};
#[cfg(test)]
use flavor::{NpmFlavor, yarn_lock_is_berry};
#[cfg(test)]
use outdated::{
    NpmOutdatedRow, parse_npm_outdated_output, parse_yarn1_outdated_output, read_lockfile_versions,
};
#[cfg(test)]
use peer_walk::find_peer_dep_consumers;
#[cfg(test)]
use propose::{
    build_npm_proposals, filter_to_direct_deps, override_key_to_package_name,
};
#[cfg(test)]
use workspaces::detect_workspace_members;

use apply::{apply_npm_proposal, copy_back_npm_sandbox};
use flavor::detect_flavor;
use propose::{
    annotate_proposals_with_overrides, filter_ignored_packages, run_npm_proposer,
    tag_proposals_with_cohorts, widen_cohort_tiers,
};
use workspaces::resolve_npm_consumers;

#[derive(Debug, Default, Clone)]
pub struct NpmEcosystem;

impl DependencyEcosystem for NpmEcosystem {
    fn name(&self) -> &'static str {
        EcosystemName::Npm.as_str()
    }

    fn detect_manifests(&self, repo: &Path) -> Result<Vec<Manifest>> {
        if !repo.is_dir() {
            return Err(Error::RepoNotFound(repo.to_path_buf()));
        }
        let mut found = Vec::new();
        let package_json = repo.join("package.json");
        let package_json_present = package_json.is_file();
        if package_json_present {
            found.push(Manifest {
                path: PathBuf::from("package.json"),
                kind: ManifestKind::PackageJson,
                metadata: BTreeMap::new(),
            });
        }
        // Don't report orphan lockfiles (lockfile without sibling
        // package.json) as detected manifests — propose_updates would
        // return empty and the operator would see "1 manifest, 0
        // proposals" with no explanation (mortar dogfood: empty root
        // `package-lock.json` short-circuited polyglot traversal AND
        // looked like a successful scan). Polyglot detection still
        // discovers the real `ui/package.json` separately.
        if package_json_present && let Some(flavor) = detect_flavor(repo) {
            found.push(Manifest {
                path: PathBuf::from(flavor.lockfile_name()),
                kind: ManifestKind::NpmLockfile,
                metadata: BTreeMap::new(),
            });
        }
        Ok(found)
    }

    fn propose_updates(
        &self,
        manifests: &[Manifest],
        repo: &Path,
        ctx: &EcosystemContext,
    ) -> Result<Vec<Proposal>> {
        let has_package_json = manifests
            .iter()
            .any(|m| matches!(m.kind, ManifestKind::PackageJson));
        if !has_package_json {
            return Ok(Vec::new());
        }
        let Some(flavor) = detect_flavor(repo) else {
            return Ok(Vec::new());
        };
        let manifest_paths: Vec<PathBuf> = manifests
            .iter()
            .filter(|m| {
                matches!(
                    m.kind,
                    ManifestKind::PackageJson | ManifestKind::NpmLockfile
                )
            })
            .map(|m| m.path.clone())
            .collect();
        let mut proposals = run_npm_proposer(flavor, repo, &manifest_paths)?;
        tag_proposals_with_cohorts(&mut proposals);
        widen_cohort_tiers(&mut proposals);
        annotate_proposals_with_overrides(&mut proposals, repo);
        Ok(filter_ignored_packages(proposals, &ctx.ignored_subjects))
    }

    fn gate_workflows(&self, _proposal: &Proposal, repo: &Path) -> Result<Vec<PathBuf>> {
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

    fn affected_consumers(&self, proposal: &Proposal, tree: &Path) -> Result<Vec<ConsumerId>> {
        resolve_npm_consumers(proposal, tree)
    }

    fn apply_proposal(&self, proposal: &Proposal, tree_path: &Path) -> Result<()> {
        let Some(flavor) = detect_flavor(tree_path) else {
            return Err(Error::other(format!(
                "no npm/pnpm lockfile found in `{}`; cannot apply bump",
                tree_path.display()
            )));
        };
        apply_npm_proposal(flavor, proposal, tree_path)
    }

    fn copy_back(&self, _proposal: &Proposal, sandbox: &Path, host: &Path) -> Result<Vec<PathBuf>> {
        copy_back_npm_sandbox(sandbox, host)
    }

    fn copy_back_merged(
        &self,
        _proposals: &[&Proposal],
        sandbox: &Path,
        host: &Path,
    ) -> Result<Vec<PathBuf>> {
        // For npm, copy-back is bulk-by-design (the whole package.json
        // and lockfile pair). Each per-proposal copy_back would just
        // re-ship the same bytes, so the merged path collapses to ONE
        // bulk copy from the merged sandbox to host.
        copy_back_npm_sandbox(sandbox, host)
    }

    fn pr_body_fragment(&self, proposal: &Proposal, outcome: &ValidationOutcome) -> String {
        format!(
            "- **{pkg}**: `{from}` → `{to}` ({classification})",
            pkg = proposal.subject,
            from = proposal.from,
            to = proposal.to,
            classification = outcome.classification.as_str(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // parse_npm_outdated_output
    // -------------------------------------------------------------------------

    #[test]
    fn parse_outdated_handles_typical_npm_json() {
        let stdout = r#"{
            "lodash": {
                "current": "4.17.20",
                "wanted":  "4.17.21",
                "latest":  "4.17.21",
                "dependent": "my-app"
            },
            "react": {
                "current": "17.0.0",
                "wanted":  "17.0.2",
                "latest":  "18.3.1",
                "dependent": "my-app"
            }
        }"#;
        let rows = parse_npm_outdated_output(stdout).unwrap();
        assert_eq!(rows.len(), 2);
        // Sorted by name → lodash, react.
        assert_eq!(rows[0].name, "lodash");
        assert_eq!(rows[0].current.as_deref(), Some("4.17.20"));
        assert_eq!(rows[0].wanted, "4.17.21");
        assert_eq!(rows[0].latest, "4.17.21");
        assert_eq!(rows[1].name, "react");
        assert_eq!(rows[1].current.as_deref(), Some("17.0.0"));
    }

    #[test]
    fn parse_outdated_handles_empty_object() {
        let rows = parse_npm_outdated_output("{}").unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn parse_outdated_handles_empty_string() {
        let rows = parse_npm_outdated_output("").unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn parse_outdated_handles_missing_current() {
        // Package declared but not installed — `current` is absent.
        let stdout = r#"{"chalk":{"wanted":"4.1.2","latest":"5.3.0"}}"#;
        let rows = parse_npm_outdated_output(stdout).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].current, None);
    }

    #[test]
    fn yarn_lock_is_berry_detects_metadata_header() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        // yarn berry shape — has `__metadata:` block at top.
        std::fs::write(
            repo.join("yarn.lock"),
            "# This file is generated by running \"yarn install\" inside your project.\n\
             # Manual changes might be lost - proceed with caution!\n\
             \n\
             __metadata:\n  version: 9\n  cacheKey: 10\n\n\
             \"@angular/compiler@npm:21.2.13\":\n  version: 21.2.13\n",
        )
        .unwrap();
        assert!(yarn_lock_is_berry(repo));
    }

    #[test]
    fn yarn_lock_is_berry_returns_false_for_yarn1() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        // yarn1 shape — no `__metadata:` block.
        std::fs::write(
            repo.join("yarn.lock"),
            "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n\
             # yarn lockfile v1\n\n\
             ansi-styles@^4.1.0:\n  version \"4.3.0\"\n",
        )
        .unwrap();
        assert!(!yarn_lock_is_berry(repo));
    }

    #[test]
    fn yarn_lock_is_berry_returns_false_when_file_absent() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!yarn_lock_is_berry(tmp.path()));
    }

    // -------------------------------------------------------------------------
    // yarn berry proposer — descriptor + lockfile parser + flavor routing.
    // -------------------------------------------------------------------------

    #[test]
    fn detect_flavor_returns_yarn_berry_when_metadata_present() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        std::fs::write(repo.join("package.json"), "{}").unwrap();
        std::fs::write(
            repo.join("yarn.lock"),
            "__metadata:\n  version: 9\n\n\"x@npm:^1\":\n  version: 1.0.0\n",
        )
        .unwrap();
        assert_eq!(detect_flavor(repo), Some(NpmFlavor::YarnBerry));
    }

    #[test]
    fn detect_flavor_returns_yarn1_when_no_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        std::fs::write(repo.join("package.json"), "{}").unwrap();
        std::fs::write(
            repo.join("yarn.lock"),
            "# yarn lockfile v1\n\nx@^1.0.0:\n  version \"1.0.0\"\n",
        )
        .unwrap();
        assert_eq!(detect_flavor(repo), Some(NpmFlavor::Yarn));
    }

    #[test]
    fn parse_berry_descriptor_name_handles_unscoped_packages() {
        assert_eq!(
            parse_berry_descriptor_name("lodash@npm:^4.17.21"),
            Some("lodash".into())
        );
        assert_eq!(
            parse_berry_descriptor_name("\"lodash@npm:^4.17.21\""),
            Some("lodash".into())
        );
    }

    #[test]
    fn parse_berry_descriptor_name_handles_scoped_packages() {
        assert_eq!(
            parse_berry_descriptor_name("@types/node@npm:^20.10.0"),
            Some("@types/node".into())
        );
        assert_eq!(
            parse_berry_descriptor_name("\"@angular/compiler@npm:21.2.13\""),
            Some("@angular/compiler".into())
        );
    }

    #[test]
    fn parse_berry_descriptor_name_handles_workspace_protocol() {
        assert_eq!(
            parse_berry_descriptor_name("my-pkg@workspace:^"),
            Some("my-pkg".into())
        );
    }

    #[test]
    fn parse_berry_lockfile_extracts_subject_to_version_map() {
        let lockfile = "__metadata:\n  version: 9\n  cacheKey: 10\n\n\
                        \"lodash@npm:^4.17.21\":\n  version: 4.17.21\n  resolution: \"lodash@npm:4.17.21\"\n\n\
                        \"@types/node@npm:^20.10.0\":\n  version: 20.10.5\n  resolution: \"@types/node@npm:20.10.5\"\n";
        let map = parse_berry_lockfile(lockfile).unwrap();
        assert_eq!(map.get("lodash").map(String::as_str), Some("4.17.21"));
        assert_eq!(map.get("@types/node").map(String::as_str), Some("20.10.5"));
    }

    #[test]
    fn parse_berry_lockfile_skips_metadata_block() {
        let lockfile = "__metadata:\n  version: 9\n\n\"x@npm:^1\":\n  version: 1.0.0\n";
        let map = parse_berry_lockfile(lockfile).unwrap();
        assert!(!map.contains_key("__metadata"));
        assert_eq!(map.get("x").map(String::as_str), Some("1.0.0"));
    }

    #[test]
    fn parse_berry_lockfile_handles_comma_separated_descriptors() {
        // Multiple descriptors for the same resolution share an entry.
        // Both should yield the same version.
        let lockfile = "\"lodash@npm:^4.17.21, lodash@npm:^4.17.20\":\n  version: 4.17.21\n";
        let map = parse_berry_lockfile(lockfile).unwrap();
        assert_eq!(map.get("lodash").map(String::as_str), Some("4.17.21"));
    }

    #[test]
    fn parse_berry_lockfile_skips_entries_without_version() {
        // Workspace-protocol entries often have a `linkType:` and a
        // `version` field, but defensive: if `version` is missing, skip.
        let lockfile = "\"odd-one@workspace:packages/odd\":\n  resolution: \"odd-one@workspace:packages/odd\"\n";
        let map = parse_berry_lockfile(lockfile).unwrap();
        assert!(!map.contains_key("odd-one"));
    }

    #[test]
    fn parse_berry_lockfile_returns_empty_for_garbage() {
        // Malformed YAML returns an error, but the parser surfaces it
        // via Result rather than panicking. The proposer routes
        // through Err and aborts the scan_root.
        let map = parse_berry_lockfile("__metadata:\n  version: 9\n");
        assert!(map.is_ok());
    }

    #[test]
    fn propose_berry_updates_returns_empty_when_no_direct_deps() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        std::fs::write(repo.join("package.json"), "{}").unwrap();
        std::fs::write(repo.join("yarn.lock"), "__metadata:\n  version: 9\n").unwrap();
        let proposals = propose_berry_updates(repo, &[]).unwrap();
        assert!(proposals.is_empty());
    }

    #[test]
    fn collect_direct_deps_with_constraints_records_constraint_strings() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        std::fs::write(
            repo.join("package.json"),
            r#"{"dependencies":{"lodash":"^4.17.21"},"devDependencies":{"@types/node":"~20.10.0"}}"#,
        )
        .unwrap();
        let deps = collect_direct_deps_with_constraints(repo).unwrap();
        assert_eq!(deps.get("lodash").map(String::as_str), Some("^4.17.21"));
        assert_eq!(
            deps.get("@types/node").map(String::as_str),
            Some("~20.10.0")
        );
    }

    #[test]
    fn parse_outdated_skips_file_link_workspace_deps() {
        // pnpm outdated -r emits entries for `file:` / `workspace:` deps
        // with no `latest` (and/or a path-shaped `wanted`). These can't
        // be bumped against a registry, so the parser drops them.
        // Captured shape: real `pnpm outdated -r` against vite's
        // `@vitejs/test-aliased-module` entry.
        let stdout = r#"{
            "regular": {"current":"1.0.0","wanted":"1.0.1","latest":"1.0.1"},
            "@vitejs/test-aliased-module": {
                "wanted": "@vitejs/test-aliased-module@file:playground/alias/dir/module",
                "isDeprecated": false,
                "dependencyType": "dependencies"
            },
            "internal-pkg": {
                "wanted": "workspace:^",
                "isDeprecated": false
            }
        }"#;
        let rows = parse_npm_outdated_output(stdout).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "regular");
    }

    #[test]
    fn parse_outdated_collapses_workspace_per_consumer_arrays() {
        // npm 7+ workspaces emit ONE array per dep, with one entry per
        // consumer. The (current, wanted, latest) tuple is identical
        // across entries because npm hoists deps. Parser must accept
        // the array shape and emit exactly one row per dep.
        let stdout = r#"{
            "lodash": [
                {"current":"4.17.20","wanted":"4.17.20","latest":"4.18.1","dependent":"alpha"},
                {"current":"4.17.20","wanted":"4.17.20","latest":"4.18.1","dependent":"beta"}
            ],
            "chalk": [
                {"current":"4.1.0","wanted":"4.1.0","latest":"5.3.0","dependent":"alpha"}
            ]
        }"#;
        let rows = parse_npm_outdated_output(stdout).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "chalk");
        assert_eq!(rows[0].current.as_deref(), Some("4.1.0"));
        assert_eq!(rows[0].latest, "5.3.0");
        assert_eq!(rows[1].name, "lodash");
        assert_eq!(rows[1].current.as_deref(), Some("4.17.20"));
        assert_eq!(rows[1].latest, "4.18.1");
    }

    // -------------------------------------------------------------------------
    // yarn1 NDJSON parser
    // -------------------------------------------------------------------------

    #[test]
    fn parse_yarn1_outdated_extracts_table_rows() {
        // Real-ish shape from `yarn outdated --json` (yarn 1.22).
        let stdout = r#"{"type":"info","data":"Color legend : ..."}
{"type":"table","data":{"head":["Package","Current","Wanted","Latest","Package Type","URL"],"body":[["lodash","4.17.20","4.17.21","4.18.1","dependencies","https://lodash.com/"],["axios","1.6.0","1.6.7","1.16.1","dependencies","https://axios-http.com/"]]}}"#;
        let rows = parse_yarn1_outdated_output(stdout).unwrap();
        assert_eq!(rows.len(), 2);
        // Sorted by name → axios first.
        assert_eq!(rows[0].name, "axios");
        assert_eq!(rows[0].current.as_deref(), Some("1.6.0"));
        assert_eq!(rows[0].wanted, "1.6.7");
        assert_eq!(rows[0].latest, "1.16.1");
        assert_eq!(rows[1].name, "lodash");
    }

    #[test]
    fn parse_yarn1_outdated_returns_empty_when_no_table_line() {
        // yarn emits an info preamble even when nothing is outdated.
        let stdout = r#"{"type":"info","data":"Use \"yarn outdated --help\" for more"}"#;
        let rows = parse_yarn1_outdated_output(stdout).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn parse_yarn1_outdated_handles_empty_string() {
        assert!(parse_yarn1_outdated_output("").unwrap().is_empty());
    }

    #[test]
    fn parse_yarn1_outdated_ignores_garbage_lines() {
        // Mixed valid + invalid lines — invalid skipped, valid kept.
        let stdout = "not json\n{\"type\":\"table\",\"data\":{\"head\":[],\"body\":[[\"a\",\"1.0\",\"1.0\",\"2.0\",\"dependencies\",\"\"]]}}\n";
        let rows = parse_yarn1_outdated_output(stdout).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "a");
    }

    // -------------------------------------------------------------------------
    // build_npm_proposals
    // -------------------------------------------------------------------------

    #[test]
    fn build_proposals_tier_maps_correctly() {
        let rows = vec![
            NpmOutdatedRow {
                name: "lodash".into(),
                current: Some("4.17.20".into()),
                wanted: "4.17.21".into(),
                latest: "4.17.21".into(),
            },
            NpmOutdatedRow {
                name: "react".into(),
                current: Some("17.0.0".into()),
                wanted: "17.0.2".into(),
                latest: "18.3.1".into(),
            },
            NpmOutdatedRow {
                name: "chalk".into(),
                current: Some("4.1.2".into()),
                wanted: "4.1.2".into(),
                latest: "5.3.0".into(),
            },
        ];
        let proposals = build_npm_proposals(&rows, &[PathBuf::from("package.json")]);
        assert_eq!(proposals.len(), 3);
        let by_name: BTreeMap<&str, &Proposal> =
            proposals.iter().map(|p| (p.subject.as_str(), p)).collect();
        // lodash: wanted == latest → LockfileOnly.
        assert_eq!(by_name["lodash"].bump_tier, BumpTier::LockfileOnly);
        // react: wanted (17.0.2) != latest (18.3.1), cross-major → Breaking.
        assert_eq!(by_name["react"].bump_tier, BumpTier::Breaking);
        // chalk: wanted (4.1.2) != latest (5.3.0), cross-major → Breaking.
        assert_eq!(by_name["chalk"].bump_tier, BumpTier::Breaking);
    }

    #[test]
    fn build_proposals_skips_rows_where_current_equals_latest() {
        // npm outdated without node_modules sometimes lists packages
        // whose lockfile already matches latest. The proposer must
        // drop those so the report doesn't show "5.2.9 -> 5.2.9".
        let rows = vec![NpmOutdatedRow {
            name: "@fontsource/inter".into(),
            current: Some("5.2.8".into()),
            wanted: "5.2.8".into(),
            latest: "5.2.8".into(),
        }];
        let proposals = build_npm_proposals(&rows, &[]);
        assert!(proposals.is_empty());
    }

    #[test]
    fn build_proposals_skips_rows_without_current_version() {
        let rows = vec![NpmOutdatedRow {
            name: "chalk".into(),
            current: None,
            wanted: "4.1.2".into(),
            latest: "5.3.0".into(),
        }];
        let proposals = build_npm_proposals(&rows, &[]);
        assert!(proposals.is_empty());
    }

    // -------------------------------------------------------------------------
    // classify_npm_bump — same caret-compat-group rules as cargo
    // -------------------------------------------------------------------------

    #[test]
    fn classify_npm_same_major_is_compatible() {
        assert_eq!(classify_npm_bump("1.0.0", "1.5.0"), BumpTier::Compatible);
        assert_eq!(classify_npm_bump("17.0.0", "17.0.2"), BumpTier::Compatible);
    }

    #[test]
    fn classify_npm_cross_major_is_breaking() {
        assert_eq!(classify_npm_bump("17.0.0", "18.0.0"), BumpTier::Breaking);
        assert_eq!(classify_npm_bump("0.8.0", "1.0.0"), BumpTier::Breaking);
    }

    #[test]
    fn classify_npm_zero_dot_x_groups_by_minor() {
        assert_eq!(classify_npm_bump("0.18.1", "0.18.7"), BumpTier::Compatible);
        assert_eq!(classify_npm_bump("0.18.1", "0.20.0"), BumpTier::Breaking);
    }

    // -------------------------------------------------------------------------
    // explain_npm_bump — structured rationale for --explain.
    // -------------------------------------------------------------------------

    #[test]
    fn explain_npm_same_major_1_plus_returns_compatible() {
        let exp = explain_npm_bump("1.0.0", "1.5.0");
        assert_eq!(exp.decision, "compatible");
        assert_eq!(exp.rule, "npm:caret-major-1-plus");
    }

    #[test]
    fn explain_npm_cross_major_returns_breaking() {
        let exp = explain_npm_bump("1.5.0", "2.0.0");
        assert_eq!(exp.decision, "breaking");
        assert_eq!(exp.rule, "npm:caret-major-crossed");
    }

    #[test]
    fn explain_npm_cross_minor_in_0_x_returns_breaking() {
        let exp = explain_npm_bump("0.18.1", "0.20.0");
        assert_eq!(exp.decision, "breaking");
        assert_eq!(exp.rule, "npm:caret-0-x-minor-crossed");
    }

    #[test]
    fn explain_npm_unparseable_returns_breaking() {
        let exp = explain_npm_bump("not-a-version", "1.0.0");
        assert_eq!(exp.decision, "breaking");
        assert_eq!(exp.rule, "npm:unparseable-semver");
    }

    #[test]
    fn explain_npm_lockfile_only_carries_constraint() {
        let exp = explain_npm_lockfile_only_bump("4.17.20", "4.17.21", Some("^4.17.0"));
        assert_eq!(exp.decision, "lockfile-only");
        assert_eq!(exp.rule, "npm:lockfile-within-constraint");
        assert_eq!(
            exp.inputs.get("constraint").map(String::as_str),
            Some("^4.17.0")
        );
    }

    // -------------------------------------------------------------------------
    // preserve_constraint_prefix
    // -------------------------------------------------------------------------

    #[test]
    fn preserve_prefix_keeps_caret() {
        assert_eq!(preserve_constraint_prefix("^1.0.0", "1.5.2"), "^1.5.2");
    }

    #[test]
    fn preserve_prefix_keeps_tilde() {
        assert_eq!(preserve_constraint_prefix("~1.0.0", "1.5.2"), "~1.5.2");
    }

    #[test]
    fn preserve_prefix_keeps_exact_equality() {
        assert_eq!(preserve_constraint_prefix("=1.0.0", "1.5.2"), "=1.5.2");
    }

    #[test]
    fn preserve_prefix_adds_caret_to_bare_version() {
        // npm install --save defaults to caret-prefixed when adding a
        // dep that previously had a bare version. Mirror that here.
        assert_eq!(preserve_constraint_prefix("1.0.0", "1.5.2"), "^1.5.2");
    }

    #[test]
    fn preserve_prefix_opaque_for_unknown_shapes() {
        // file:, git+ssh://, npm tag references, etc. — replace verbatim.
        assert_eq!(
            preserve_constraint_prefix("file:../local", "1.5.2"),
            "1.5.2",
        );
    }

    // -------------------------------------------------------------------------
    // npm alias syntax: `<local-key>: "npm:<target-pkg>@<version-spec>"`.
    // npm's `outdated --json` keys by the LOCAL alias name, so the proposer
    // emits proposal.subject = local key (e.g. "my-lodash"). The editor
    // finds the entry correctly, but `preserve_constraint_prefix` pre-fix
    // fell into the catch-all "replace verbatim" branch and wiped the
    // entire `npm:lodash@` alias prefix — turning
    //   "my-lodash": "npm:lodash@4.17.21"
    // into
    //   "my-lodash": "4.17.22"
    // which breaks package resolution (npm would now try to fetch a
    // registry package literally named `my-lodash`).
    //
    // Surfaces post-cargo-renamed-dep dogfood (2026-05-18): same class of
    // aliased-dep bug as cargo's `package = "..."` syntax, different shape
    // (cargo missed the lookup; npm finds it but corrupts the value).
    // -------------------------------------------------------------------------

    #[test]
    fn preserve_prefix_handles_npm_alias_bare_inner_version() {
        // Bare inner version follows npm's --save convention: gain a caret
        // on update. Same rule the top-level bare-version path applies.
        assert_eq!(
            preserve_constraint_prefix("npm:lodash@4.17.21", "4.17.22"),
            "npm:lodash@^4.17.22",
        );
    }

    #[test]
    fn preserve_prefix_handles_npm_alias_caret_inner() {
        assert_eq!(
            preserve_constraint_prefix("npm:lodash@^4.17.21", "4.17.22"),
            "npm:lodash@^4.17.22",
        );
    }

    #[test]
    fn preserve_prefix_handles_npm_alias_tilde_inner() {
        assert_eq!(
            preserve_constraint_prefix("npm:lodash@~4.17.21", "4.17.22"),
            "npm:lodash@~4.17.22",
        );
    }

    #[test]
    fn preserve_prefix_handles_npm_alias_with_scoped_target() {
        // `@scope/pkg` introduces a leading `@` that is NOT the version
        // separator; the version `@` is the LAST one.
        assert_eq!(
            preserve_constraint_prefix("npm:@types/lodash@^4.17.21", "4.17.22"),
            "npm:@types/lodash@^4.17.22",
        );
    }

    // -------------------------------------------------------------------------
    // try_edit_package_json
    // -------------------------------------------------------------------------

    #[test]
    fn editor_widens_dependencies_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg = tmp.path().join("package.json");
        std::fs::write(
            &pkg,
            r#"{
  "name": "sample",
  "version": "0.1.0",
  "dependencies": {
    "lodash": "^4.17.20"
  }
}
"#,
        )
        .unwrap();
        let edited = try_edit_package_json(&pkg, "lodash", "4.17.21").unwrap();
        assert!(edited);
        let after = std::fs::read_to_string(&pkg).unwrap();
        assert!(after.contains(r#""lodash": "^4.17.21""#), "got:\n{after}");
        // Trailing newline preserved (npm convention).
        assert!(after.ends_with('\n'));
    }

    #[test]
    fn editor_widens_dev_dependencies_when_main_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg = tmp.path().join("package.json");
        std::fs::write(
            &pkg,
            r#"{"name":"sample","devDependencies":{"jest":"^28.0.0"}}"#,
        )
        .unwrap();
        let edited = try_edit_package_json(&pkg, "jest", "29.7.0").unwrap();
        assert!(edited);
        let after = std::fs::read_to_string(&pkg).unwrap();
        assert!(after.contains(r#""jest": "^29.7.0""#));
    }

    #[test]
    fn editor_returns_false_when_dep_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg = tmp.path().join("package.json");
        std::fs::write(
            &pkg,
            r#"{"name":"sample","dependencies":{"lodash":"^4.0.0"}}"#,
        )
        .unwrap();
        let edited = try_edit_package_json(&pkg, "missing-pkg", "1.0.0").unwrap();
        assert!(!edited);
    }

    // -------------------------------------------------------------------------
    // resolve_install_version — alias-aware LockfileOnly install spec.
    //
    // Same npm-alias root cause as the editor bug, different code path.
    // `run_install_pinned` builds `<name>@<version>` and shells out to
    // `npm install`. For a LockfileOnly bump on an aliased dep, passing
    // bare `name="my-lodash" version="4.17.22"` produces
    //   npm install my-lodash@4.17.22
    // which fails because `my-lodash` isn't a registry package — it's a
    // local alias for `lodash`. The resolver re-emits the alias so the
    // install spec becomes `my-lodash@npm:lodash@4.17.22`.
    // -------------------------------------------------------------------------

    #[test]
    fn resolve_install_passes_through_bare_version_for_unaliased_dep() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"name":"sample","dependencies":{"lodash":"^4.17.20"}}"#,
        )
        .unwrap();
        let v = resolve_install_version(tmp.path(), "lodash", "4.17.22").unwrap();
        assert_eq!(v, "4.17.22");
    }

    #[test]
    fn resolve_install_reconstructs_alias_spec_for_aliased_dep() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"name":"sample","dependencies":{"my-lodash":"npm:lodash@^4.17.21"}}"#,
        )
        .unwrap();
        let v = resolve_install_version(tmp.path(), "my-lodash", "4.17.22").unwrap();
        assert_eq!(v, "npm:lodash@4.17.22");
    }

    #[test]
    fn resolve_install_handles_scoped_alias_target() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"name":"sample","dependencies":{"local":"npm:@scope/pkg@^1.0.0"}}"#,
        )
        .unwrap();
        let v = resolve_install_version(tmp.path(), "local", "1.0.1").unwrap();
        assert_eq!(v, "npm:@scope/pkg@1.0.1");
    }

    #[test]
    fn resolve_install_finds_alias_under_dev_dependencies() {
        // The resolver scans all four dep-name fields, not just `dependencies`.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"name":"sample","devDependencies":{"my-jest":"npm:jest@^29.0.0"}}"#,
        )
        .unwrap();
        let v = resolve_install_version(tmp.path(), "my-jest", "29.7.0").unwrap();
        assert_eq!(v, "npm:jest@29.7.0");
    }

    #[test]
    fn editor_preserves_npm_alias_prefix_on_widen() {
        // End-to-end: package.json has an aliased entry; editor must bump
        // the inner version and preserve the `npm:<target>@` prefix
        // verbatim. Pre-fix the value was rewritten to a bare version,
        // silently breaking npm's package resolution.
        let tmp = tempfile::tempdir().unwrap();
        let pkg = tmp.path().join("package.json");
        std::fs::write(
            &pkg,
            r#"{
  "name": "sample",
  "dependencies": {
    "my-lodash": "npm:lodash@^4.17.21"
  }
}
"#,
        )
        .unwrap();
        let edited = try_edit_package_json(&pkg, "my-lodash", "4.17.22").unwrap();
        assert!(edited);
        let after = std::fs::read_to_string(&pkg).unwrap();
        assert!(
            after.contains(r#""my-lodash": "npm:lodash@^4.17.22""#),
            "alias prefix must be preserved, inner version bumped; got:\n{after}",
        );
        // Negative check: a bare-version write would have looked like
        // `"my-lodash": "^4.17.22"`. Make sure that didn't happen.
        assert!(
            !after.contains(r#""my-lodash": "^4.17.22""#),
            "alias prefix was wiped — bug regression; got:\n{after}",
        );
    }

    // -------------------------------------------------------------------------
    // detect_flavor + detect_manifests
    // -------------------------------------------------------------------------

    #[test]
    fn detect_flavor_recognizes_each_lockfile() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        assert!(detect_flavor(root).is_none());
        std::fs::write(root.join("package-lock.json"), "{}").unwrap();
        assert_eq!(detect_flavor(root), Some(NpmFlavor::Npm));
        std::fs::remove_file(root.join("package-lock.json")).unwrap();
        std::fs::write(root.join("pnpm-lock.yaml"), "lockfileVersion: 6.0\n").unwrap();
        assert_eq!(detect_flavor(root), Some(NpmFlavor::Pnpm));
        std::fs::remove_file(root.join("pnpm-lock.yaml")).unwrap();
        std::fs::write(root.join("yarn.lock"), "# yarn lockfile v1\n").unwrap();
        assert_eq!(detect_flavor(root), Some(NpmFlavor::Yarn));
    }

    #[test]
    fn detect_manifests_finds_package_json_and_lockfile() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("package.json"), r#"{"name":"x"}"#).unwrap();
        std::fs::write(root.join("package-lock.json"), "{}").unwrap();
        let eco = NpmEcosystem;
        let manifests = eco.detect_manifests(root).unwrap();
        assert_eq!(manifests.len(), 2);
        assert!(
            manifests
                .iter()
                .any(|m| matches!(m.kind, ManifestKind::PackageJson))
        );
        assert!(
            manifests
                .iter()
                .any(|m| matches!(m.kind, ManifestKind::NpmLockfile))
        );
    }

    // -------------------------------------------------------------------------
    // collect_direct_dep_names + filter
    // -------------------------------------------------------------------------

    #[test]
    fn read_lockfile_versions_parses_v3_packages_map() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": { "name": "root", "version": "0.1.0" },
                    "node_modules/lodash": { "version": "4.17.20" },
                    "node_modules/react": { "version": "17.0.0" },
                    "node_modules/foo/node_modules/lodash": { "version": "3.0.0" }
                }
            }"#,
        )
        .unwrap();
        let map = read_lockfile_versions(tmp.path()).unwrap();
        assert_eq!(map.get("lodash"), Some(&"4.17.20".to_string()));
        assert_eq!(map.get("react"), Some(&"17.0.0".to_string()));
        // Nested duplicate must be ignored — top-level only.
        assert_ne!(map.get("lodash"), Some(&"3.0.0".to_string()));
    }

    #[test]
    fn read_lockfile_versions_returns_empty_when_lockfile_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let map = read_lockfile_versions(tmp.path()).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn collect_direct_dep_names_reads_root_package_json() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{
                "dependencies": { "lodash": "^4.0.0" },
                "devDependencies": { "jest": "^28.0.0" }
            }"#,
        )
        .unwrap();
        let names = collect_direct_dep_names(tmp.path()).unwrap();
        let names: Vec<&String> = names.iter().collect();
        assert_eq!(names, vec![&"jest".to_string(), &"lodash".to_string()]);
    }

    #[test]
    fn filter_to_direct_deps_drops_transitive_entries() {
        let proposals = vec![sample_proposal("lodash"), sample_proposal("@types/node")];
        let direct: BTreeSet<String> = std::iter::once("lodash".to_string()).collect();
        let kept = filter_to_direct_deps(proposals, &direct);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].subject, "lodash");
    }

    #[test]
    fn filter_ignored_packages_drops_matching_subject() {
        let proposals = vec![sample_proposal("typescript"), sample_proposal("lodash")];
        let kept = filter_ignored_packages(proposals, &["typescript".to_string()]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].subject, "lodash");
    }

    #[test]
    fn filter_ignored_packages_handles_scoped_subjects() {
        // `@angular/core` and `@angular/common` differ — only the named
        // one is dropped. Scoped npm packages are subject-matched
        // byte-for-byte (no glob expansion).
        let proposals = vec![
            sample_proposal("@angular/core"),
            sample_proposal("@angular/common"),
        ];
        let kept = filter_ignored_packages(proposals, &["@angular/core".to_string()]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].subject, "@angular/common");
    }

    #[test]
    fn filter_ignored_packages_empty_list_is_identity() {
        let proposals = vec![sample_proposal("lodash"), sample_proposal("typescript")];
        let before = proposals.len();
        let kept = filter_ignored_packages(proposals, &[]);
        assert_eq!(kept.len(), before);
    }

    #[test]
    fn find_peer_dep_consumers_finds_flat_packages_declaring_subject_as_peer() {
        let tmp = tempfile::tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        std::fs::create_dir_all(nm.join("lucide-angular")).unwrap();
        std::fs::write(
            nm.join("lucide-angular").join("package.json"),
            r#"{
                "name": "lucide-angular",
                "version": "0.577.0",
                "peerDependencies": {
                    "@angular/common": "13.x - 21.x",
                    "@angular/core": "13.x - 21.x"
                }
            }"#,
        )
        .unwrap();
        std::fs::create_dir_all(nm.join("lodash")).unwrap();
        std::fs::write(
            nm.join("lodash").join("package.json"),
            r#"{"name": "lodash", "version": "4.17.21"}"#,
        )
        .unwrap();
        let consumers = find_peer_dep_consumers(tmp.path(), "@angular/core");
        assert_eq!(consumers, vec!["lucide-angular"]);
    }

    #[test]
    fn find_peer_dep_consumers_walks_scoped_packages() {
        let tmp = tempfile::tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        std::fs::create_dir_all(nm.join("@wildmason").join("aegis")).unwrap();
        std::fs::write(
            nm.join("@wildmason").join("aegis").join("package.json"),
            r#"{
                "name": "@wildmason/aegis",
                "version": "1.5.4",
                "peerDependencies": { "@angular/cdk": ">=21" }
            }"#,
        )
        .unwrap();
        let consumers = find_peer_dep_consumers(tmp.path(), "@angular/cdk");
        assert_eq!(consumers, vec!["@wildmason/aegis"]);
    }

    #[test]
    fn find_peer_dep_consumers_skips_dot_dirs_and_non_peer_declarations() {
        let tmp = tempfile::tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        // pnpm-style virtual store — skipped because it starts with `.`
        std::fs::create_dir_all(nm.join(".pnpm").join("foo")).unwrap();
        std::fs::write(
            nm.join(".pnpm").join("foo").join("package.json"),
            r#"{"name": "foo", "peerDependencies": {"@angular/core": "^21"}}"#,
        )
        .unwrap();
        // Real package that declares it as `dependencies` (not peer) — skipped
        std::fs::create_dir_all(nm.join("normal-dep")).unwrap();
        std::fs::write(
            nm.join("normal-dep").join("package.json"),
            r#"{"name": "normal-dep", "dependencies": {"@angular/core": "^21"}}"#,
        )
        .unwrap();
        let consumers = find_peer_dep_consumers(tmp.path(), "@angular/core");
        assert!(consumers.is_empty(), "got: {consumers:?}");
    }

    #[test]
    fn find_peer_dep_consumers_handles_missing_node_modules_gracefully() {
        // No node_modules dir → empty result, no crash.
        let tmp = tempfile::tempdir().unwrap();
        let consumers = find_peer_dep_consumers(tmp.path(), "@angular/core");
        assert!(consumers.is_empty());
    }

    #[test]
    fn find_peer_dep_consumers_walks_pnpm_virtual_store() {
        // pnpm layout: node_modules/.pnpm/<pkg>@<ver>/node_modules/<pkg>/package.json
        let tmp = tempfile::tempdir().unwrap();
        let virt = tmp
            .path()
            .join("node_modules")
            .join(".pnpm")
            .join("@wildmason+aegis@1.5.4_@angular+core@21.0.0")
            .join("node_modules")
            .join("@wildmason")
            .join("aegis");
        std::fs::create_dir_all(&virt).unwrap();
        std::fs::write(
            virt.join("package.json"),
            r#"{
                "name": "@wildmason/aegis",
                "version": "1.5.4",
                "peerDependencies": { "@angular/core": ">=21" }
            }"#,
        )
        .unwrap();
        // Also add an unscoped entry to confirm the unscoped path
        // through walk_flat_node_modules works inside the virtual
        // store too.
        let unscoped = tmp
            .path()
            .join("node_modules")
            .join(".pnpm")
            .join("lucide-angular@0.577.0_@angular+core@21.0.0")
            .join("node_modules")
            .join("lucide-angular");
        std::fs::create_dir_all(&unscoped).unwrap();
        std::fs::write(
            unscoped.join("package.json"),
            r#"{
                "name": "lucide-angular",
                "version": "0.577.0",
                "peerDependencies": { "@angular/core": "13.x - 21.x" }
            }"#,
        )
        .unwrap();
        let consumers = find_peer_dep_consumers(tmp.path(), "@angular/core");
        assert_eq!(consumers, vec!["@wildmason/aegis", "lucide-angular"]);
    }

    #[test]
    fn find_peer_dep_consumers_dedupes_across_virtual_store_versions() {
        // Same package at two different peer-resolution suffixes in
        // .pnpm — both declare the subject as a peer. The result
        // should report the package name once, not twice.
        let tmp = tempfile::tempdir().unwrap();
        for suffix in [
            "@wildmason+aegis@1.5.4_@angular+core@21.0.0",
            "@wildmason+aegis@1.5.4_@angular+core@22.0.0",
        ] {
            let pkg = tmp
                .path()
                .join("node_modules")
                .join(".pnpm")
                .join(suffix)
                .join("node_modules")
                .join("@wildmason")
                .join("aegis");
            std::fs::create_dir_all(&pkg).unwrap();
            std::fs::write(
                pkg.join("package.json"),
                r#"{
                    "name": "@wildmason/aegis",
                    "version": "1.5.4",
                    "peerDependencies": { "@angular/core": ">=21" }
                }"#,
            )
            .unwrap();
        }
        let consumers = find_peer_dep_consumers(tmp.path(), "@angular/core");
        assert_eq!(consumers, vec!["@wildmason/aegis"]);
    }

    #[test]
    fn find_peer_dep_consumers_combines_flat_and_virtual_store() {
        // A pnpm-style hybrid: top-level symlinks/installs at
        // node_modules/foo/ AND the real installs in .pnpm/. Both
        // should be searched, results combined and deduped.
        let tmp = tempfile::tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        // Flat: top-level direct dep
        std::fs::create_dir_all(nm.join("lucide-angular")).unwrap();
        std::fs::write(
            nm.join("lucide-angular").join("package.json"),
            r#"{"name":"lucide-angular","peerDependencies":{"@angular/core":">=21"}}"#,
        )
        .unwrap();
        // Virtual store: transitive consumer not hoisted to top
        let virt = nm
            .join(".pnpm")
            .join("@ngrx+store@21.0.0_@angular+core@21.0.0")
            .join("node_modules")
            .join("@ngrx")
            .join("store");
        std::fs::create_dir_all(&virt).unwrap();
        std::fs::write(
            virt.join("package.json"),
            r#"{"name":"@ngrx/store","peerDependencies":{"@angular/core":">=21"}}"#,
        )
        .unwrap();
        let consumers = find_peer_dep_consumers(tmp.path(), "@angular/core");
        assert_eq!(consumers, vec!["@ngrx/store", "lucide-angular"]);
    }

    #[test]
    fn find_peer_dep_consumers_walks_yarn_berry_unplugged() {
        // yarn berry layout: .yarn/unplugged/<pkg>-npm-<ver>-<hash>/
        //   node_modules/<pkg>/package.json
        let tmp = tempfile::tempdir().unwrap();
        let unplugged_pkg = tmp
            .path()
            .join(".yarn")
            .join("unplugged")
            .join("@wildmason-aegis-npm-1.5.4-a1b2c3d4")
            .join("node_modules")
            .join("@wildmason")
            .join("aegis");
        std::fs::create_dir_all(&unplugged_pkg).unwrap();
        std::fs::write(
            unplugged_pkg.join("package.json"),
            r#"{
                "name": "@wildmason/aegis",
                "version": "1.5.4",
                "peerDependencies": { "@angular/core": ">=21" }
            }"#,
        )
        .unwrap();
        let consumers = find_peer_dep_consumers(tmp.path(), "@angular/core");
        assert_eq!(consumers, vec!["@wildmason/aegis"]);
    }

    #[test]
    fn find_peer_dep_consumers_walks_yarn_berry_pnp_data_json() {
        // yarn berry PnP runtime data — the authoritative source
        // even when packages remain zipped in .yarn/cache/.
        let tmp = tempfile::tempdir().unwrap();
        let pnp_data = serde_json::json!({
            "__info": ["yarn 4.0.0 pnp data"],
            "packageRegistryData": [
                // Top-level workspace (name=null) — must be skipped.
                [null, [
                    [null, {
                        "packageLocation": "./",
                        "packageDependencies": [["@angular/core", "npm:21.0.0"]],
                        "linkType": "SOFT"
                    }]
                ]],
                // @wildmason/aegis declares @angular/core as a peer.
                ["@wildmason/aegis", [
                    ["npm:1.5.4", {
                        "packageLocation": "./.yarn/cache/@wildmason-aegis-npm-1.5.4-a1b2c3.zip/node_modules/@wildmason/aegis/",
                        "packageDependencies": [["@angular/core", "npm:21.0.0"]],
                        "packagePeers": ["@angular/core", "@angular/common"],
                        "linkType": "HARD"
                    }]
                ]],
                // lucide-angular ALSO declares @angular/core as a peer.
                ["lucide-angular", [
                    ["npm:0.577.0", {
                        "packageLocation": "./.yarn/cache/lucide-angular-npm-0.577.0-d4e5f6.zip/node_modules/lucide-angular/",
                        "packageDependencies": [["@angular/core", "npm:21.0.0"]],
                        "packagePeers": ["@angular/core"],
                        "linkType": "HARD"
                    }]
                ]],
                // typescript does NOT declare @angular/core as a peer.
                ["typescript", [
                    ["npm:5.9.3", {
                        "packageLocation": "./.yarn/cache/typescript-npm-5.9.3-aabbcc.zip/node_modules/typescript/",
                        "packageDependencies": [],
                        "packagePeers": [],
                        "linkType": "HARD"
                    }]
                ]]
            ]
        });
        std::fs::write(
            tmp.path().join(".pnp.data.json"),
            serde_json::to_string(&pnp_data).unwrap(),
        )
        .unwrap();
        let consumers = find_peer_dep_consumers(tmp.path(), "@angular/core");
        assert_eq!(consumers, vec!["@wildmason/aegis", "lucide-angular"]);
    }

    #[test]
    fn find_peer_dep_consumers_yarn_berry_pnp_data_skips_self_consumption() {
        // @angular/core itself shouldn't appear as a consumer of
        // @angular/core even if it (hypothetically) listed itself
        // in packagePeers (defensive against malformed input).
        let tmp = tempfile::tempdir().unwrap();
        let pnp_data = serde_json::json!({
            "packageRegistryData": [
                ["@angular/core", [
                    ["npm:21.0.0", {
                        "packagePeers": ["@angular/core"]
                    }]
                ]]
            ]
        });
        std::fs::write(
            tmp.path().join(".pnp.data.json"),
            serde_json::to_string(&pnp_data).unwrap(),
        )
        .unwrap();
        let consumers = find_peer_dep_consumers(tmp.path(), "@angular/core");
        assert!(consumers.is_empty(), "got: {consumers:?}");
    }

    #[test]
    fn find_peer_dep_consumers_yarn_berry_pnp_data_handles_malformed_gracefully() {
        // Invalid JSON, missing fields, wrong types — all must be
        // swallowed without crashing the proposer.
        let tmp = tempfile::tempdir().unwrap();
        // Missing packageRegistryData.
        std::fs::write(tmp.path().join(".pnp.data.json"), r#"{"__info":["x"]}"#).unwrap();
        let consumers = find_peer_dep_consumers(tmp.path(), "@angular/core");
        assert!(consumers.is_empty());
        // Malformed JSON.
        std::fs::write(tmp.path().join(".pnp.data.json"), "not json at all").unwrap();
        let consumers = find_peer_dep_consumers(tmp.path(), "@angular/core");
        assert!(consumers.is_empty());
        // packageRegistryData is the wrong shape.
        std::fs::write(
            tmp.path().join(".pnp.data.json"),
            r#"{"packageRegistryData": "not an array"}"#,
        )
        .unwrap();
        let consumers = find_peer_dep_consumers(tmp.path(), "@angular/core");
        assert!(consumers.is_empty());
    }

    #[test]
    fn find_peer_dep_consumers_combines_yarn_berry_layouts() {
        // A yarn berry project with BOTH unplugged AND pnp data.
        // Different packages contribute through different paths;
        // results union and dedupe.
        let tmp = tempfile::tempdir().unwrap();
        // Unplugged: @wildmason/aegis
        let unplugged_pkg = tmp
            .path()
            .join(".yarn")
            .join("unplugged")
            .join("@wildmason-aegis-npm-1.5.4-a1b2c3")
            .join("node_modules")
            .join("@wildmason")
            .join("aegis");
        std::fs::create_dir_all(&unplugged_pkg).unwrap();
        std::fs::write(
            unplugged_pkg.join("package.json"),
            r#"{"name":"@wildmason/aegis","peerDependencies":{"@angular/core":">=21"}}"#,
        )
        .unwrap();
        // PnP data: @ngrx/store (zipped only) + @wildmason/aegis (same as
        // unplugged — verifies dedupe across paths).
        let pnp_data = serde_json::json!({
            "packageRegistryData": [
                ["@wildmason/aegis", [
                    ["npm:1.5.4", { "packagePeers": ["@angular/core"] }]
                ]],
                ["@ngrx/store", [
                    ["npm:21.0.0", { "packagePeers": ["@angular/core"] }]
                ]]
            ]
        });
        std::fs::write(
            tmp.path().join(".pnp.data.json"),
            serde_json::to_string(&pnp_data).unwrap(),
        )
        .unwrap();
        let consumers = find_peer_dep_consumers(tmp.path(), "@angular/core");
        assert_eq!(consumers, vec!["@ngrx/store", "@wildmason/aegis"]);
    }

    #[test]
    fn find_peer_dep_consumers_ignores_pnpm_entries_without_inner_node_modules() {
        // Some pnpm temp/cache entries inside .pnpm/ don't have the
        // expected node_modules/ middle layer. They must be skipped
        // gracefully — no crash, no false positives.
        let tmp = tempfile::tempdir().unwrap();
        let stray = tmp.path().join("node_modules").join(".pnpm").join("stray");
        std::fs::create_dir_all(&stray).unwrap();
        std::fs::write(
            stray.join("package.json"),
            r#"{"name":"stray","peerDependencies":{"@angular/core":">=21"}}"#,
        )
        .unwrap();
        let consumers = find_peer_dep_consumers(tmp.path(), "@angular/core");
        assert!(consumers.is_empty(), "got: {consumers:?}");
    }

    #[test]
    fn widen_cohort_tiers_promotes_compatible_member_to_breaking_when_lockstep_partner_is_breaking()
    {
        let mut breaking = sample_proposal("@angular/core");
        breaking.bump_tier = BumpTier::Breaking;
        breaking.cohort = Some("angular-framework".into());
        let mut compatible = sample_proposal("@angular/common");
        compatible.bump_tier = BumpTier::Compatible;
        compatible.cohort = Some("angular-framework".into());
        let mut proposals = vec![breaking, compatible];

        widen_cohort_tiers(&mut proposals);

        let common = proposals
            .iter()
            .find(|p| p.subject == "@angular/common")
            .unwrap();
        let core = proposals
            .iter()
            .find(|p| p.subject == "@angular/core")
            .unwrap();
        assert_eq!(
            common.bump_tier,
            BumpTier::Breaking,
            "@angular/common should be widened to Breaking to lockstep with @angular/core"
        );
        assert_eq!(
            core.bump_tier,
            BumpTier::Breaking,
            "@angular/core retains its original Breaking tier (no downgrade)"
        );
        assert!(
            common
                .notes
                .iter()
                .any(|n| n.contains("cohort-lockstep") && n.contains("compatible to breaking")),
            "widened proposal should record a cohort-lockstep note; got: {:?}",
            common.notes
        );
        assert!(
            !core.notes.iter().any(|n| n.contains("cohort-lockstep")),
            "unwidened (already-at-max) members must not get a widening note; got: {:?}",
            core.notes
        );
    }

    #[test]
    fn widen_cohort_tiers_skips_single_member_cohorts() {
        // Only one @angular/core proposal in the run — nothing to
        // lockstep with, so no widening note even though it's
        // tagged with a cohort.
        let mut alone = sample_proposal("@angular/core");
        alone.bump_tier = BumpTier::Compatible;
        alone.cohort = Some("angular-framework".into());
        let mut proposals = vec![alone];

        widen_cohort_tiers(&mut proposals);

        let core = &proposals[0];
        assert_eq!(core.bump_tier, BumpTier::Compatible);
        assert!(
            !core.notes.iter().any(|n| n.contains("cohort-lockstep")),
            "single-member cohort must not trigger a widening note; got: {:?}",
            core.notes
        );
    }

    #[test]
    fn widen_cohort_tiers_promotes_lockfile_only_to_compatible_when_partner_is_compatible() {
        // The dominant tier in a 2-member cohort is Compatible —
        // the LockfileOnly member widens to Compatible, but the
        // Compatible member is unchanged.
        let mut lf = sample_proposal("@angular/core");
        lf.bump_tier = BumpTier::LockfileOnly;
        lf.cohort = Some("angular-framework".into());
        let mut compat = sample_proposal("@angular/common");
        compat.bump_tier = BumpTier::Compatible;
        compat.cohort = Some("angular-framework".into());
        let mut proposals = vec![lf, compat];

        widen_cohort_tiers(&mut proposals);

        let core = proposals
            .iter()
            .find(|p| p.subject == "@angular/core")
            .unwrap();
        assert_eq!(core.bump_tier, BumpTier::Compatible);
    }

    #[test]
    fn widen_cohort_tiers_isolates_separate_cohorts() {
        // Two independent cohorts in the same run. Widening must
        // only happen within a cohort — the lodash proposal (no
        // cohort) is left alone, and the @tiptap/* breaking bump
        // does NOT propagate to @angular/*.
        let mut angular_a = sample_proposal("@angular/core");
        angular_a.bump_tier = BumpTier::LockfileOnly;
        angular_a.cohort = Some("angular-framework".into());
        let mut angular_b = sample_proposal("@angular/common");
        angular_b.bump_tier = BumpTier::LockfileOnly;
        angular_b.cohort = Some("angular-framework".into());
        let mut tiptap_a = sample_proposal("@tiptap/core");
        tiptap_a.bump_tier = BumpTier::Breaking;
        tiptap_a.cohort = Some("tiptap".into());
        let mut tiptap_b = sample_proposal("@tiptap/starter-kit");
        tiptap_b.bump_tier = BumpTier::Compatible;
        tiptap_b.cohort = Some("tiptap".into());
        let mut lodash = sample_proposal("lodash");
        lodash.bump_tier = BumpTier::Compatible;
        let mut proposals = vec![angular_a, angular_b, tiptap_a, tiptap_b, lodash];

        widen_cohort_tiers(&mut proposals);

        let by_subject: std::collections::BTreeMap<_, _> = proposals
            .iter()
            .map(|p| (p.subject.as_str(), p.bump_tier))
            .collect();
        // Angular cohort: both stay LockfileOnly (no member above
        // that tier).
        assert_eq!(
            by_subject.get("@angular/core").copied(),
            Some(BumpTier::LockfileOnly)
        );
        assert_eq!(
            by_subject.get("@angular/common").copied(),
            Some(BumpTier::LockfileOnly)
        );
        // Tiptap cohort: the Compatible member widens to Breaking.
        assert_eq!(
            by_subject.get("@tiptap/starter-kit").copied(),
            Some(BumpTier::Breaking)
        );
        assert_eq!(
            by_subject.get("@tiptap/core").copied(),
            Some(BumpTier::Breaking)
        );
        // Cohort-free proposal: untouched.
        assert_eq!(
            by_subject.get("lodash").copied(),
            Some(BumpTier::Compatible)
        );
    }

    #[test]
    fn widen_cohort_tiers_is_idempotent() {
        // Running widening twice must produce the same proposal
        // set — no duplicate notes, no further mutations.
        let mut breaking = sample_proposal("@angular/core");
        breaking.bump_tier = BumpTier::Breaking;
        breaking.cohort = Some("angular-framework".into());
        let mut compatible = sample_proposal("@angular/common");
        compatible.bump_tier = BumpTier::Compatible;
        compatible.cohort = Some("angular-framework".into());
        let mut proposals = vec![breaking, compatible];

        widen_cohort_tiers(&mut proposals);
        let notes_after_first = proposals
            .iter()
            .find(|p| p.subject == "@angular/common")
            .unwrap()
            .notes
            .clone();
        widen_cohort_tiers(&mut proposals);
        let notes_after_second = &proposals
            .iter()
            .find(|p| p.subject == "@angular/common")
            .unwrap()
            .notes;
        assert_eq!(
            &notes_after_first, notes_after_second,
            "second pass must not append duplicate widening notes"
        );
    }

    #[test]
    fn tag_proposals_with_cohorts_assigns_angular_framework_cohort() {
        let mut proposals = vec![
            sample_proposal("@angular/core"),
            sample_proposal("@angular/common"),
            sample_proposal("@angular/cdk"),
            sample_proposal("lodash"),
        ];
        tag_proposals_with_cohorts(&mut proposals);
        let by_subject: std::collections::BTreeMap<_, _> = proposals
            .iter()
            .map(|p| (p.subject.as_str(), p.cohort.as_deref()))
            .collect();
        assert_eq!(
            by_subject.get("@angular/core").copied().flatten(),
            Some("angular-framework")
        );
        assert_eq!(
            by_subject.get("@angular/common").copied().flatten(),
            Some("angular-framework")
        );
        assert_eq!(
            by_subject.get("@angular/cdk").copied().flatten(),
            Some("angular-components")
        );
        assert_eq!(by_subject.get("lodash").copied().flatten(), None);
    }

    #[test]
    fn annotate_proposals_with_overrides_marks_pinned_packages() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{
                "name": "demo",
                "dependencies": { "lodash": "^4.17.0", "axios": "^1.6.0" },
                "overrides": { "lodash": "4.17.21" }
            }"#,
        )
        .unwrap();
        let mut proposals = vec![sample_proposal("lodash"), sample_proposal("axios")];
        annotate_proposals_with_overrides(&mut proposals, tmp.path());
        let lodash = proposals.iter().find(|p| p.subject == "lodash").unwrap();
        let axios = proposals.iter().find(|p| p.subject == "axios").unwrap();
        assert!(
            lodash
                .notes
                .iter()
                .any(|n| n.contains("override-pinned to 4.17.21")),
            "lodash should be annotated; notes: {:?}",
            lodash.notes
        );
        assert!(
            axios.notes.is_empty(),
            "axios should NOT be annotated; notes: {:?}",
            axios.notes
        );
    }

    #[test]
    fn annotate_proposals_picks_up_pnpm_overrides() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{
                "name": "demo",
                "pnpm": { "overrides": { "lodash": "4.17.21" } }
            }"#,
        )
        .unwrap();
        let mut proposals = vec![sample_proposal("lodash")];
        annotate_proposals_with_overrides(&mut proposals, tmp.path());
        assert!(
            proposals[0]
                .notes
                .iter()
                .any(|n| n.contains("override-pinned"))
        );
    }

    #[test]
    fn annotate_proposals_picks_up_yarn_resolutions() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{
                "name": "demo",
                "resolutions": { "lodash": "4.17.21" }
            }"#,
        )
        .unwrap();
        let mut proposals = vec![sample_proposal("lodash")];
        annotate_proposals_with_overrides(&mut proposals, tmp.path());
        assert!(
            proposals[0]
                .notes
                .iter()
                .any(|n| n.contains("override-pinned"))
        );
    }

    #[test]
    fn override_key_to_package_name_handles_path_form() {
        // npm's `"foo > bar"` syntax means "pin `bar` when reached
        // via `foo`." The right-most segment is the pinned package.
        assert_eq!(override_key_to_package_name("foo > bar"), "bar");
        assert_eq!(override_key_to_package_name("a > b > c"), "c");
        assert_eq!(override_key_to_package_name("lodash"), "lodash");
        assert_eq!(
            override_key_to_package_name("@angular/core"),
            "@angular/core"
        );
    }

    #[test]
    fn annotate_proposals_handles_missing_package_json_gracefully() {
        // A scan with no manifest must not crash; the proposals
        // come back unannotated.
        let tmp = tempfile::tempdir().unwrap();
        let mut proposals = vec![sample_proposal("lodash")];
        annotate_proposals_with_overrides(&mut proposals, tmp.path());
        assert!(proposals[0].notes.is_empty());
    }

    #[test]
    fn build_npm_proposals_id_disambiguates_by_source_version() {
        // Two `npm outdated` rows for the same package at different
        // currently-installed versions must produce distinct proposal
        // IDs so a downstream apply-pr branch-per-proposal flow doesn't
        // collide. Same shape as the cargo multi-version transitive
        // case that surfaced in helm/mortar dogfood.
        let manifest_paths = vec![PathBuf::from("package.json")];
        let row_a = NpmOutdatedRow {
            name: "left-pad".into(),
            current: Some("1.0.0".into()),
            wanted: "1.0.0".into(),
            latest: "1.3.0".into(),
        };
        let row_b = NpmOutdatedRow {
            name: "left-pad".into(),
            current: Some("1.1.0".into()),
            wanted: "1.1.0".into(),
            latest: "1.3.0".into(),
        };
        let p_a = build_npm_proposals(&[row_a], &manifest_paths);
        let p_b = build_npm_proposals(&[row_b], &manifest_paths);
        assert_eq!(p_a.len(), 1);
        assert_eq!(p_b.len(), 1);
        assert_ne!(
            p_a[0].id, p_b[0].id,
            "different `from` versions must produce distinct proposal IDs"
        );
        assert!(
            p_a[0].id.contains("1-0-0") && p_a[0].id.contains("to-1-3-0"),
            "expected from-1-0-0 + to-1-3-0 segments: id={}",
            p_a[0].id
        );
    }

    fn sample_proposal(name: &str) -> Proposal {
        Proposal {
            id: format!("npm-{name}-test"),
            ecosystem: EcosystemName::Npm.as_str().into(),
            kind: ProposalKind::Version,
            subject: name.into(),
            from: "1.0.0".into(),
            to: "1.5.0".into(),
            initial_classification: Classification::Exact,
            manifest_paths: vec![],
            notes: vec![],
            bump_tier: BumpTier::Compatible,
            affected_consumers: Vec::new(),
            explanation: None,
            cohort: None,
        }
    }

    // -------------------------------------------------------------------------
    // Workspace member discovery (npm/yarn `workspaces`, pnpm-workspace.yaml,
    // glob expansion).
    // -------------------------------------------------------------------------

    fn proposal_for_subject(subject: &str) -> Proposal {
        Proposal {
            id: format!("npm-{subject}-test"),
            ecosystem: EcosystemName::Npm.as_str().into(),
            kind: ProposalKind::Version,
            subject: subject.into(),
            from: "1.0.0".into(),
            to: "1.5.0".into(),
            initial_classification: Classification::Exact,
            manifest_paths: vec![],
            notes: vec![],
            bump_tier: BumpTier::Compatible,
            affected_consumers: Vec::new(),
            explanation: None,
            cohort: None,
        }
    }

    fn write_pkg(path: &Path, json: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, json).unwrap();
    }

    #[test]
    fn detect_workspace_members_returns_empty_for_single_project() {
        let tmp = tempfile::tempdir().unwrap();
        write_pkg(
            &tmp.path().join("package.json"),
            r#"{"name":"single","version":"1.0.0"}"#,
        );
        let members = detect_workspace_members(tmp.path()).unwrap();
        assert!(
            members.is_empty(),
            "no workspaces field → no members: {members:?}"
        );
    }

    #[test]
    fn detect_workspace_members_reads_literal_workspaces_array() {
        let tmp = tempfile::tempdir().unwrap();
        write_pkg(
            &tmp.path().join("package.json"),
            r#"{
                "name":"root",
                "workspaces":["packages/foo","packages/bar"]
            }"#,
        );
        write_pkg(
            &tmp.path().join("packages/foo/package.json"),
            r#"{"name":"@scope/foo","version":"1.0.0"}"#,
        );
        write_pkg(
            &tmp.path().join("packages/bar/package.json"),
            r#"{"name":"@scope/bar","version":"1.0.0"}"#,
        );
        let members = detect_workspace_members(tmp.path()).unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].name, "@scope/bar");
        assert_eq!(members[1].name, "@scope/foo");
        assert_eq!(
            members[0].relative_path,
            PathBuf::from("packages").join("bar")
        );
    }

    #[test]
    fn detect_workspace_members_reads_object_form_with_packages_key() {
        let tmp = tempfile::tempdir().unwrap();
        write_pkg(
            &tmp.path().join("package.json"),
            r#"{
                "name":"root",
                "workspaces":{"packages":["apps/web","apps/api"]}
            }"#,
        );
        write_pkg(
            &tmp.path().join("apps/web/package.json"),
            r#"{"name":"web"}"#,
        );
        write_pkg(
            &tmp.path().join("apps/api/package.json"),
            r#"{"name":"api"}"#,
        );
        let members = detect_workspace_members(tmp.path()).unwrap();
        let names: Vec<&str> = members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["api", "web"]);
    }

    #[test]
    fn detect_workspace_members_expands_glob_patterns() {
        let tmp = tempfile::tempdir().unwrap();
        write_pkg(
            &tmp.path().join("package.json"),
            r#"{"name":"root","workspaces":["packages/*"]}"#,
        );
        for name in ["alpha", "beta", "gamma"] {
            write_pkg(
                &tmp.path().join("packages").join(name).join("package.json"),
                &format!(r#"{{"name":"{name}"}}"#),
            );
        }
        // A non-package directory mixed in must NOT be reported.
        std::fs::create_dir_all(tmp.path().join("packages/scripts")).unwrap();
        let members = detect_workspace_members(tmp.path()).unwrap();
        let names: Vec<&str> = members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn detect_workspace_members_reads_pnpm_workspace_yaml() {
        let tmp = tempfile::tempdir().unwrap();
        // pnpm doesn't use `workspaces` in package.json — only the YAML.
        write_pkg(&tmp.path().join("package.json"), r#"{"name":"root"}"#);
        std::fs::write(
            tmp.path().join("pnpm-workspace.yaml"),
            "packages:\n  - 'libs/*'\n  - apps/dashboard\n",
        )
        .unwrap();
        for name in ["a", "b"] {
            write_pkg(
                &tmp.path().join("libs").join(name).join("package.json"),
                &format!(r#"{{"name":"@libs/{name}"}}"#),
            );
        }
        write_pkg(
            &tmp.path().join("apps/dashboard/package.json"),
            r#"{"name":"dashboard"}"#,
        );
        let members = detect_workspace_members(tmp.path()).unwrap();
        let names: Vec<&str> = members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["dashboard", "@libs/a", "@libs/b"]);
    }

    #[test]
    fn detect_workspace_members_honors_negation_patterns() {
        // pnpm supports `!packages/private` to exclude from a positive
        // glob match. After positive expansion + negation subtraction,
        // only the non-negated members should remain.
        let tmp = tempfile::tempdir().unwrap();
        write_pkg(&tmp.path().join("package.json"), r#"{"name":"root"}"#);
        std::fs::write(
            tmp.path().join("pnpm-workspace.yaml"),
            "packages:\n  - 'packages/*'\n  - '!packages/private'\n",
        )
        .unwrap();
        for name in ["public", "private"] {
            write_pkg(
                &tmp.path().join("packages").join(name).join("package.json"),
                &format!(r#"{{"name":"{name}"}}"#),
            );
        }
        let members = detect_workspace_members(tmp.path()).unwrap();
        let names: Vec<&str> = members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["public"], "negation should exclude private");
    }

    #[test]
    fn detect_workspace_members_honors_glob_negation_patterns() {
        // Negation works with globs too: `!packages/private-*` should
        // drop every match of that glob even though the positive
        // `packages/*` would otherwise include them.
        let tmp = tempfile::tempdir().unwrap();
        write_pkg(&tmp.path().join("package.json"), r#"{"name":"root"}"#);
        std::fs::write(
            tmp.path().join("pnpm-workspace.yaml"),
            "packages:\n  - 'packages/*'\n  - '!packages/private-*'\n",
        )
        .unwrap();
        for name in ["public", "private-foo", "private-bar", "shared"] {
            write_pkg(
                &tmp.path().join("packages").join(name).join("package.json"),
                &format!(r#"{{"name":"{name}"}}"#),
            );
        }
        let members = detect_workspace_members(tmp.path()).unwrap();
        let names: Vec<&str> = members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["public", "shared"]);
    }

    #[test]
    fn detect_workspace_members_skips_directories_without_package_json() {
        let tmp = tempfile::tempdir().unwrap();
        write_pkg(
            &tmp.path().join("package.json"),
            r#"{"name":"root","workspaces":["packages/*"]}"#,
        );
        std::fs::create_dir_all(tmp.path().join("packages/empty")).unwrap();
        write_pkg(
            &tmp.path().join("packages/real/package.json"),
            r#"{"name":"real"}"#,
        );
        let members = detect_workspace_members(tmp.path()).unwrap();
        let names: Vec<&str> = members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["real"]);
    }

    // -------------------------------------------------------------------------
    // affected_consumers (Resolver — plan §C.3.5 for npm/yarn/pnpm)
    // -------------------------------------------------------------------------

    fn make_workspace(tmp: &tempfile::TempDir, deps_per_member: &[(&str, &str, &str)]) {
        // `deps_per_member` is (member_dir, member_name, dep_block_json).
        // Root declares packages/* as workspaces.
        write_pkg(
            &tmp.path().join("package.json"),
            r#"{"name":"root","workspaces":["packages/*"]}"#,
        );
        for (dir, name, dep_block) in deps_per_member {
            write_pkg(
                &tmp.path().join("packages").join(dir).join("package.json"),
                &format!(r#"{{"name":"{name}",{dep_block}}}"#),
            );
        }
    }

    #[test]
    fn affected_consumers_lists_members_that_directly_declare_dep() {
        let tmp = tempfile::tempdir().unwrap();
        make_workspace(
            &tmp,
            &[
                ("a", "@scope/a", r#""dependencies":{"lodash":"^4.0.0"}"#),
                ("b", "@scope/b", r#""dependencies":{"axios":"^1.0.0"}"#),
                ("c", "@scope/c", r#""dependencies":{"lodash":"^4.0.0"}"#),
            ],
        );
        let eco = NpmEcosystem;
        let consumers = eco
            .affected_consumers(&proposal_for_subject("lodash"), tmp.path())
            .unwrap();
        assert_eq!(consumers, vec!["@scope/a", "@scope/c"]);
    }

    #[test]
    fn affected_consumers_returns_empty_when_no_member_consumes_dep() {
        let tmp = tempfile::tempdir().unwrap();
        make_workspace(
            &tmp,
            &[("a", "@scope/a", r#""dependencies":{"axios":"^1.0.0"}"#)],
        );
        let eco = NpmEcosystem;
        let consumers = eco
            .affected_consumers(&proposal_for_subject("nowhere-pkg"), tmp.path())
            .unwrap();
        assert!(consumers.is_empty());
    }

    #[test]
    fn affected_consumers_excludes_self_when_target_is_workspace_member() {
        // A workspace member named `lodash` is the bumped package, not
        // its own consumer — matches cargo's affected_consumers semantics.
        let tmp = tempfile::tempdir().unwrap();
        make_workspace(
            &tmp,
            &[
                ("a", "@scope/a", r#""dependencies":{"lodash":"^4.0.0"}"#),
                ("b", "lodash", r#""version":"1.0.0""#),
            ],
        );
        let eco = NpmEcosystem;
        let consumers = eco
            .affected_consumers(&proposal_for_subject("lodash"), tmp.path())
            .unwrap();
        assert_eq!(consumers, vec!["@scope/a"]);
    }

    #[test]
    fn affected_consumers_walks_dev_peer_optional_deps() {
        let tmp = tempfile::tempdir().unwrap();
        make_workspace(
            &tmp,
            &[
                ("a", "@scope/a", r#""devDependencies":{"jest":"^29.0.0"}"#),
                ("b", "@scope/b", r#""peerDependencies":{"jest":"^29.0.0"}"#),
                (
                    "c",
                    "@scope/c",
                    r#""optionalDependencies":{"jest":"^29.0.0"}"#,
                ),
                ("d", "@scope/d", r#""dependencies":{"axios":"^1.0.0"}"#),
            ],
        );
        let eco = NpmEcosystem;
        let consumers = eco
            .affected_consumers(&proposal_for_subject("jest"), tmp.path())
            .unwrap();
        assert_eq!(
            consumers,
            vec!["@scope/a", "@scope/b", "@scope/c"],
            "every dep-shaped declaration counts"
        );
    }

    // -------------------------------------------------------------------------
    // update_package_json_constraint — workspace + glob integration
    // -------------------------------------------------------------------------

    #[test]
    fn update_constraint_widens_every_glob_resolved_member() {
        let tmp = tempfile::tempdir().unwrap();
        write_pkg(
            &tmp.path().join("package.json"),
            r#"{"name":"root","workspaces":["packages/*"],"dependencies":{"lodash":"^4.17.0"}}"#,
        );
        for name in ["alpha", "beta"] {
            write_pkg(
                &tmp.path().join("packages").join(name).join("package.json"),
                &format!(r#"{{"name":"{name}","dependencies":{{"lodash":"^4.17.0"}}}}"#),
            );
        }
        let modified = update_package_json_constraint(tmp.path(), "lodash", "4.18.1").unwrap();
        let mut expected = vec![
            PathBuf::from("package.json"),
            PathBuf::from("packages").join("alpha").join("package.json"),
            PathBuf::from("packages").join("beta").join("package.json"),
        ];
        expected.sort();
        assert_eq!(modified, expected);
        for path in &expected {
            let text = std::fs::read_to_string(tmp.path().join(path)).unwrap();
            assert!(
                text.contains("\"^4.18.1\""),
                "every package.json should have the widened constraint: {path:?}"
            );
        }
    }

    #[test]
    fn update_constraint_skips_members_without_the_dep() {
        let tmp = tempfile::tempdir().unwrap();
        write_pkg(
            &tmp.path().join("package.json"),
            r#"{"name":"root","workspaces":["packages/*"]}"#,
        );
        write_pkg(
            &tmp.path().join("packages/has/package.json"),
            r#"{"name":"has","dependencies":{"lodash":"^4.17.0"}}"#,
        );
        write_pkg(
            &tmp.path().join("packages/missing/package.json"),
            r#"{"name":"missing","dependencies":{"axios":"^1.0.0"}}"#,
        );
        let modified = update_package_json_constraint(tmp.path(), "lodash", "4.18.1").unwrap();
        assert_eq!(
            modified,
            vec![PathBuf::from("packages").join("has").join("package.json")]
        );
    }
}
