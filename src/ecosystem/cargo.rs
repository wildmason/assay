//! Cargo ecosystem.
//!
//! Detects `Cargo.toml` + `Cargo.lock` files in a repo (workspace root and
//! per-crate manifests), runs `cargo update --dry-run --workspace` to
//! enumerate available bumps, and cross-checks the stdout parser against a
//! direct lockfile diff to defend against cargo stdout format drift.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::model::{
    Classification, Manifest, ManifestKind, Proposal, ProposalKind, ValidationOutcome,
};

use super::{DependencyEcosystem, EcosystemContext, EcosystemName};

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
        _ctx: &EcosystemContext,
    ) -> Result<Vec<Proposal>> {
        // A Cargo workspace produces one resolver invocation per scan, not
        // per-manifest. If no lockfile was detected, there's nothing to bump.
        let has_lock = manifests
            .iter()
            .any(|m| matches!(m.kind, ManifestKind::CargoLock));
        if !has_lock {
            return Ok(Vec::new());
        }
        run_cargo_proposer(repo, manifests)
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

    fn apply_proposal(&self, _proposal: &Proposal, tree_path: &Path) -> Result<()> {
        apply_cargo_update_to_tree(tree_path)
    }

    fn copy_back(&self, _proposal: &Proposal, sandbox: &Path, host: &Path) -> Result<Vec<PathBuf>> {
        let sandbox_lock = sandbox.join("Cargo.lock");
        if !sandbox_lock.is_file() {
            return Err(Error::other(format!(
                "Cargo.lock missing from sandbox at `{}`; cannot copy back",
                sandbox.display()
            )));
        }
        let host_lock = host.join("Cargo.lock");
        std::fs::copy(&sandbox_lock, &host_lock).map_err(|source| Error::Io {
            path: host_lock,
            source,
        })?;
        Ok(vec![PathBuf::from("Cargo.lock")])
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

/// Parser for `cargo update --dry-run` stdout. Each "Updating X v$OLD -> v$NEW"
/// line maps to one `CargoUpdateLine`.
///
/// Public for unit tests; callers should use `propose_from_cargo_dry_run`
/// which also cross-checks against the lockfile diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoUpdateLine {
    pub crate_name: String,
    pub from: String,
    pub to: String,
}

/// Parses cargo update stdout. Recognized line shapes (cargo 1.85+):
///
/// ```text
/// Updating crates.io index
///       Updating serde v1.0.200 -> v1.0.215
///       Adding  foo v1.0.0
///     Removing bar v0.1.0
/// ```
///
/// Only `Updating` lines that contain ` -> v` produce a `CargoUpdateLine`.
/// Adding/Removing/index-update lines are ignored — those don't represent
/// version bumps of an existing dep, which is the only kind we propose.
pub fn parse_cargo_update_output(stdout: &str) -> Vec<CargoUpdateLine> {
    let mut out = Vec::new();
    for raw in stdout.lines() {
        let line = raw.trim_start();
        let rest = match line.strip_prefix("Updating ") {
            Some(rest) => rest,
            None => continue,
        };
        // Filter out the "Updating crates.io index" header line and any
        // bare-registry update lines that lack a version arrow.
        if !rest.contains(" -> v") {
            continue;
        }
        // Expected shape: "<crate> v<old> -> v<new>"
        let Some((crate_part, version_part)) = rest.split_once(" v") else {
            continue;
        };
        let crate_name = crate_part.trim().to_string();
        if crate_name.is_empty() {
            continue;
        }
        let Some((from, to_with_v)) = version_part.split_once(" -> v") else {
            continue;
        };
        let from = from.trim().to_string();
        let to = to_with_v.trim().to_string();
        if from.is_empty() || to.is_empty() {
            continue;
        }
        out.push(CargoUpdateLine {
            crate_name,
            from,
            to,
        });
    }
    out
}

/// Diff two `Cargo.lock` contents (TOML) into a list of version changes.
/// Used to cross-check the stdout parser; if the two disagree we abort
/// loudly because either cargo's stdout format drifted or our parser has
/// a bug.
pub fn diff_lockfiles(before: &str, after: &str) -> Result<Vec<CargoUpdateLine>> {
    let before_versions = lockfile_versions(before)?;
    let after_versions = lockfile_versions(after)?;
    let mut out = Vec::new();
    for (name, from) in &before_versions {
        if let Some(to) = after_versions.get(name)
            && to != from
        {
            out.push(CargoUpdateLine {
                crate_name: name.clone(),
                from: from.clone(),
                to: to.clone(),
            });
        }
    }
    out.sort_by(|a, b| a.crate_name.cmp(&b.crate_name));
    Ok(out)
}

fn lockfile_versions(toml_text: &str) -> Result<BTreeMap<String, String>> {
    let parsed: toml::Value =
        toml_text
            .parse()
            .map_err(|e: toml::de::Error| Error::CargoUpdate {
                message: format!("Cargo.lock parse error: {e}"),
            })?;
    let mut out = BTreeMap::new();
    let Some(packages) = parsed.get("package").and_then(|v| v.as_array()) else {
        return Ok(out);
    };
    for pkg in packages {
        let Some(table) = pkg.as_table() else {
            continue;
        };
        let Some(name) = table.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(version) = table.get("version").and_then(|v| v.as_str()) else {
            continue;
        };
        // Note: cargo allows multiple package entries with the same name at
        // different versions (e.g. transitive dup). We key by name only,
        // which means same-name-different-version edge cases collapse —
        // acceptable for v1 (these are rare in practice and the workflow
        // run will catch any genuine breakage).
        out.insert(name.to_string(), version.to_string());
    }
    Ok(out)
}

/// High-level Cargo proposer: takes cargo's stdout and the before/after
/// lockfile contents, cross-checks them, and returns one `Proposal` per
/// version change. Aborts via `Error::CargoParserMismatch` if the parser
/// and lockfile diff disagree about the set of changes.
pub fn propose_from_cargo_dry_run(
    stdout: &str,
    lock_before: &str,
    lock_after: &str,
    manifest_paths: &[PathBuf],
) -> Result<Vec<Proposal>> {
    let parsed = parse_cargo_update_output(stdout);
    let diffed = diff_lockfiles(lock_before, lock_after)?;
    cross_check(&parsed, &diffed)?;
    let mut proposals = Vec::new();
    for line in &diffed {
        let id = format!(
            "cargo-{}-{}",
            sanitize_id_segment(&line.crate_name),
            sanitize_id_segment(&line.to),
        );
        proposals.push(Proposal {
            id,
            ecosystem: EcosystemName::Cargo.as_str().to_string(),
            kind: ProposalKind::Version,
            subject: line.crate_name.clone(),
            from: line.from.clone(),
            to: line.to.clone(),
            initial_classification: Classification::Exact,
            manifest_paths: manifest_paths.to_vec(),
            notes: Vec::new(),
        });
    }
    Ok(proposals)
}

fn cross_check(parsed: &[CargoUpdateLine], diffed: &[CargoUpdateLine]) -> Result<()> {
    let parsed_set: BTreeMap<&str, (&str, &str)> = parsed
        .iter()
        .map(|line| {
            (
                line.crate_name.as_str(),
                (line.from.as_str(), line.to.as_str()),
            )
        })
        .collect();
    let diffed_set: BTreeMap<&str, (&str, &str)> = diffed
        .iter()
        .map(|line| {
            (
                line.crate_name.as_str(),
                (line.from.as_str(), line.to.as_str()),
            )
        })
        .collect();
    if parsed_set == diffed_set {
        return Ok(());
    }
    let only_parsed: Vec<_> = parsed_set
        .keys()
        .filter(|k| !diffed_set.contains_key(*k))
        .copied()
        .collect();
    let only_diffed: Vec<_> = diffed_set
        .keys()
        .filter(|k| !parsed_set.contains_key(*k))
        .copied()
        .collect();
    let mismatched: Vec<_> = parsed_set
        .iter()
        .filter_map(|(name, parsed_pair)| {
            diffed_set
                .get(name)
                .filter(|diffed_pair| diffed_pair != &parsed_pair)
                .map(|_| *name)
        })
        .collect();
    Err(Error::CargoParserMismatch {
        message: format!(
            "stdout vs lockfile disagreement; only-stdout: {only_parsed:?}, only-lockfile: {only_diffed:?}, mismatched-versions: {mismatched:?}"
        ),
    })
}

/// Apply cargo bumps to a working tree by running `cargo update --workspace`
/// in place. Idempotent: invoking it again on an already-up-to-date tree
/// produces a no-op. The Applier is called once per `Proposal` so cargo
/// gets invoked multiple times for an N-bump scan; the second through Nth
/// invocations are fast because the lockfile is already at the desired
/// state.
pub fn apply_cargo_update_to_tree(tree_path: &Path) -> Result<()> {
    let manifest_path = tree_path.join("Cargo.toml");
    if !manifest_path.is_file() {
        return Err(Error::InvalidManifest {
            path: manifest_path,
            message: "Cargo.toml not found in working tree".into(),
        });
    }
    let manifest_str = manifest_path
        .to_str()
        .ok_or_else(|| Error::other("Cargo.toml path is not valid UTF-8"))?;
    let output = std::process::Command::new("cargo")
        .args(["update", "--workspace", "--manifest-path", manifest_str])
        .env("CARGO_TERM_COLOR", "never")
        .output()
        .map_err(|source| Error::Io {
            path: tree_path.to_path_buf(),
            source,
        })?;
    if !output.status.success() {
        return Err(Error::CargoUpdate {
            message: format!(
                "cargo update (apply) exited non-zero: stderr=\n{}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        });
    }
    Ok(())
}

/// Invoke `cargo update --dry-run --workspace` against a tempdir clone of
/// `repo` and parse the result into proposals.
///
/// Implementation detail: we clone with `git clone --local --no-hardlinks`
/// to get a writable working copy that does NOT share git objects via the
/// `alternates` mechanism (which would leak the alternates pointer back
/// into anything that archived the tempdir). When the source repo isn't a
/// git checkout, we fall back to copying just the manifest files.
fn run_cargo_proposer(repo: &Path, manifests: &[Manifest]) -> Result<Vec<Proposal>> {
    let tmp = tempfile::Builder::new()
        .prefix("assay-cargo-")
        .tempdir()
        .map_err(|source| Error::Io {
            path: repo.to_path_buf(),
            source,
        })?;
    let clone_root = tmp.path();
    materialize_cargo_workspace(repo, clone_root)?;

    let manifest_path = clone_root.join("Cargo.toml");
    let lock_path = clone_root.join("Cargo.lock");
    let lock_before = std::fs::read_to_string(&lock_path).map_err(|source| Error::Io {
        path: lock_path.clone(),
        source,
    })?;

    let dry_run_output = run_cargo_command(
        clone_root,
        &[
            "update",
            "--dry-run",
            "--workspace",
            "--manifest-path",
            manifest_path
                .to_str()
                .ok_or_else(|| Error::other("Cargo.toml path is not valid UTF-8"))?,
        ],
    )?;
    let stdout = dry_run_output.stdout.clone();

    // Cargo emits its diagnostics on stderr; if it failed, surface that.
    if !dry_run_output.success {
        return Err(Error::CargoUpdate {
            message: format!(
                "cargo update --dry-run exited non-zero: stderr=\n{}\nstdout=\n{}",
                dry_run_output.stderr.trim(),
                stdout.trim()
            ),
        });
    }

    // For the cross-check we need an *actual* lockfile diff. Re-run cargo
    // update without --dry-run inside the same tempdir clone. The host
    // tree is never mutated because we operate on a copy.
    let apply_output = run_cargo_command(
        clone_root,
        &[
            "update",
            "--workspace",
            "--manifest-path",
            manifest_path.to_str().expect("validated above"),
        ],
    )?;
    if !apply_output.success {
        return Err(Error::CargoUpdate {
            message: format!(
                "cargo update (non-dry-run, in tempdir) exited non-zero: stderr=\n{}",
                apply_output.stderr.trim()
            ),
        });
    }
    let lock_after = std::fs::read_to_string(&lock_path).map_err(|source| Error::Io {
        path: lock_path.clone(),
        source,
    })?;

    // Manifest paths to record on each proposal — workspace-relative paths
    // taken from the detected manifest list.
    let manifest_paths: Vec<PathBuf> = manifests
        .iter()
        .filter(|m| matches!(m.kind, ManifestKind::CargoLock | ManifestKind::CargoToml))
        .map(|m| m.path.clone())
        .collect();

    propose_from_cargo_dry_run(&stdout, &lock_before, &lock_after, &manifest_paths)
}

#[derive(Debug)]
struct CargoCommandOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

fn run_cargo_command(cwd: &Path, args: &[&str]) -> Result<CargoCommandOutput> {
    let output = std::process::Command::new("cargo")
        .args(args)
        .current_dir(cwd)
        // Suppress color codes — cargo defaults to coloring when stdout is
        // a TTY but our parent stdout may be a TTY when this runs.
        .env("CARGO_TERM_COLOR", "never")
        .output()
        .map_err(|source| Error::Io {
            path: cwd.to_path_buf(),
            source,
        })?;
    Ok(CargoCommandOutput {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// Materialize the relevant subset of `repo` into `dest` so cargo can
/// resolve the workspace. Prefers `git clone --local --no-hardlinks` for
/// fidelity; falls back to a manifest-only copy when the repo isn't a git
/// checkout.
fn materialize_cargo_workspace(repo: &Path, dest: &Path) -> Result<()> {
    let is_git = repo.join(".git").exists();
    if is_git {
        let output = std::process::Command::new("git")
            .arg("clone")
            .arg("--local")
            .arg("--no-hardlinks")
            .arg("--quiet")
            .arg(repo)
            .arg(dest)
            .output()
            .map_err(|source| Error::Io {
                path: repo.to_path_buf(),
                source,
            })?;
        if !output.status.success() {
            return Err(Error::other(format!(
                "git clone --local failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    } else {
        copy_manifest_tree(repo, dest)
    }
}

fn copy_manifest_tree(src: &Path, dest: &Path) -> Result<()> {
    for entry in std::fs::read_dir(src).map_err(|source| Error::Io {
        path: src.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| Error::Io {
            path: src.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let file_name = entry.file_name();
        let target = dest.join(&file_name);
        if path.is_dir() {
            // Skip target/, .git/, node_modules/, .assay/, and other
            // build outputs. Cargo only needs source manifests + src/.
            let name = file_name.to_string_lossy();
            if matches!(
                name.as_ref(),
                "target" | ".git" | "node_modules" | ".assay" | "target-codex" | "research"
            ) {
                continue;
            }
            std::fs::create_dir_all(&target).map_err(|source| Error::Io {
                path: target.clone(),
                source,
            })?;
            copy_manifest_tree(&path, &target)?;
        } else {
            std::fs::copy(&path, &target).map_err(|source| Error::Io {
                path: target.clone(),
                source,
            })?;
        }
    }
    Ok(())
}

/// Replace any character outside `[a-z0-9-]` with `-`. Used to build
/// branch-safe proposal IDs (e.g. `cargo-foo-bar-1-0-0`).
fn sanitize_id_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut last_was_dash = false;
    for ch in value.chars().flat_map(|c| c.to_lowercase()) {
        let safe = if ch.is_ascii_alphanumeric() { ch } else { '-' };
        if safe == '-' {
            if !last_was_dash {
                out.push(safe);
            }
            last_was_dash = true;
        } else {
            out.push(safe);
            last_was_dash = false;
        }
    }
    out.trim_matches('-').to_string()
}

/// Resolve which workspace members consume the bumped crate. Returns
/// sorted, deduped names of members that reach a package matching
/// `proposal.subject` via the cargo dependency graph.
///
/// Returns an empty `Vec` when the bumped crate isn't in the dep graph
/// at all (e.g. the workspace doesn't consume it after all). Failures
/// (`cargo metadata` errors, missing Cargo.toml) propagate.
///
/// This is the Resolver stage from plan §C.3.5: per-proposal
/// workspace-member dep-graph filtering so the Reporter can produce
/// per-consumer rows for only members that actually use the bumped
/// crate. The plan's pipeline runs the Resolver after Applier (so the
/// post-apply `Cargo.lock` is what's resolved), but for the trait-method
/// surface we just run against whatever tree is passed in.
fn resolve_cargo_consumers(
    proposal: &Proposal,
    tree: &Path,
) -> Result<Vec<crate::model::ConsumerId>> {
    use cargo_metadata::MetadataCommand;

    let manifest_path = tree.join("Cargo.toml");
    if !manifest_path.is_file() {
        return Err(Error::InvalidManifest {
            path: manifest_path,
            message: "Cargo.toml not found in tree (cargo metadata cannot resolve)".into(),
        });
    }

    let metadata = MetadataCommand::new()
        .manifest_path(&manifest_path)
        .exec()
        .map_err(|e| Error::other(format!("cargo metadata failed: {e}")))?;

    Ok(find_workspace_consumers_in_metadata(
        &metadata,
        &proposal.subject,
    ))
}

/// Pure graph-walk helper: given parsed `cargo metadata` output and a
/// target crate name, return the names of workspace members that reach
/// the target through any transitive dependency edge.
///
/// Split out from `resolve_cargo_consumers` so the graph-walking logic
/// can be exercised against real `cargo metadata` output from synthetic
/// workspace fixtures without intermediating constructors.
fn find_workspace_consumers_in_metadata(
    metadata: &cargo_metadata::Metadata,
    target_name: &str,
) -> Vec<crate::model::ConsumerId> {
    use std::collections::{HashMap, HashSet};

    // Collect every PackageId whose name matches the target. Multiple
    // versions of the same crate produce multiple matching IDs — any one
    // suffices for reachability.
    let target_ids: HashSet<&cargo_metadata::PackageId> = metadata
        .packages
        .iter()
        .filter(|p| p.name == target_name)
        .map(|p| &p.id)
        .collect();

    if target_ids.is_empty() {
        return Vec::new();
    }

    let Some(resolve) = &metadata.resolve else {
        return Vec::new();
    };

    // Build adjacency: PackageId -> resolved dep PackageIds.
    let dep_graph: HashMap<&cargo_metadata::PackageId, &[cargo_metadata::PackageId]> = resolve
        .nodes
        .iter()
        .map(|n| (&n.id, n.dependencies.as_slice()))
        .collect();

    // For each workspace member, BFS to determine if any target is
    // reachable. The set of reachable nodes from each member is small in
    // practice; we don't memoize across members for v1 simplicity.
    let mut consumers: Vec<crate::model::ConsumerId> = Vec::new();
    for member_id in &metadata.workspace_members {
        // A crate doesn't consume itself — if a workspace member IS the
        // bumped target, skip it. The Reporter renders the bumped crate
        // as the proposal row; consumers are the OTHER members affected.
        if target_ids.contains(member_id) {
            continue;
        }
        if can_reach_any(member_id, &target_ids, &dep_graph)
            && let Some(pkg) = metadata.packages.iter().find(|p| &p.id == member_id)
        {
            consumers.push(pkg.name.clone());
        }
    }
    consumers.sort();
    consumers.dedup();
    consumers
}

fn can_reach_any(
    start: &cargo_metadata::PackageId,
    targets: &std::collections::HashSet<&cargo_metadata::PackageId>,
    graph: &std::collections::HashMap<&cargo_metadata::PackageId, &[cargo_metadata::PackageId]>,
) -> bool {
    use std::collections::HashSet;

    let mut visited: HashSet<&cargo_metadata::PackageId> = HashSet::new();
    let mut queue: Vec<&cargo_metadata::PackageId> = vec![start];
    while let Some(pid) = queue.pop() {
        if !visited.insert(pid) {
            continue;
        }
        if targets.contains(pid) {
            return true;
        }
        if let Some(deps) = graph.get(pid) {
            for d in deps.iter() {
                queue.push(d);
            }
        }
    }
    false
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
}
