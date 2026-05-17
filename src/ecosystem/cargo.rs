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
    BumpTier, Classification, Manifest, ManifestKind, Proposal, ProposalKind, ValidationOutcome,
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

    fn apply_proposal(&self, proposal: &Proposal, tree_path: &Path) -> Result<()> {
        apply_cargo_proposal(proposal, tree_path)
    }

    fn copy_back(&self, proposal: &Proposal, sandbox: &Path, host: &Path) -> Result<Vec<PathBuf>> {
        copy_back_cargo_proposal(proposal, sandbox, host)
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

/// Parser for `cargo update --dry-run --verbose` stdout's `Unchanged X vOLD
/// (available: vNEW[, requires Rust X.Y.Z])` lines.
///
/// These lines surface the gap between *what cargo bumped* (in-range,
/// lockfile-only) and *what's actually published* (constraint or MSRV
/// blocked). They are the input to the `Compatible` / `Breaking` proposal
/// tiers — assay reports them but doesn't auto-apply since bumping
/// requires editing the manifest's constraint, not just the lockfile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoUnchangedLine {
    pub crate_name: String,
    /// Version currently resolved in the lockfile.
    pub from: String,
    /// Highest version cargo could see in the registry.
    pub to: String,
    /// `Some("X.Y.Z")` when cargo flagged the target as MSRV-blocked.
    /// Not a hard veto — assay still proposes the bump but attaches the
    /// note so the operator knows an MSRV change is part of the cost.
    pub requires_rust: Option<String>,
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

/// Parses `Unchanged X vOLD (available: vNEW[, requires Rust X.Y.Z])`
/// lines emitted by `cargo update --dry-run --verbose`. Lines without
/// the `(available: vNEW...)` clause (e.g. `Unchanged X vOLD (requires
/// Rust X.Y.Z)`) are silently skipped — they mean cargo *would* bump
/// but the published version itself is MSRV-blocked, not actionable as
/// a bump proposal.
pub fn parse_cargo_unchanged_output(stdout: &str) -> Vec<CargoUnchangedLine> {
    let mut out = Vec::new();
    for raw in stdout.lines() {
        let line = raw.trim_start();
        let rest = match line.strip_prefix("Unchanged ") {
            Some(rest) => rest,
            None => continue,
        };
        // "<crate> v<from> (<parens>)" — the version prefix is what
        // separates crate name from the rest.
        let Some((crate_part, version_part)) = rest.split_once(" v") else {
            continue;
        };
        let crate_name = crate_part.trim().to_string();
        if crate_name.is_empty() {
            continue;
        }
        // From-version followed by " (...)". When the parenthetical is
        // missing the line carries no actionable bump.
        let Some((from_part, paren_part)) = version_part.split_once(" (") else {
            continue;
        };
        let from = from_part.trim().to_string();
        if from.is_empty() {
            continue;
        }
        let Some(inner) = paren_part.strip_suffix(')') else {
            continue;
        };
        let Some(after_avail) = inner.strip_prefix("available: v") else {
            // Parenthetical is something else ("requires Rust X.Y.Z" alone,
            // or some future variant). No actionable target version.
            continue;
        };
        // Optional "<vNEW>, requires Rust X.Y.Z" suffix split.
        let (to_str, requires_rust) = match after_avail.split_once(", requires Rust ") {
            Some((to, rust)) => (to.trim(), Some(rust.trim().to_string())),
            None => (after_avail.trim(), None),
        };
        let to = to_str.to_string();
        if to.is_empty() {
            continue;
        }
        out.push(CargoUnchangedLine {
            crate_name,
            from,
            to,
            requires_rust,
        });
    }
    out
}

/// Classify an `Unchanged X vFROM (available: vTO)` bump by impact tier,
/// using Cargo's compatibility groups (which are subtler than plain semver).
///
/// Compatibility groups per the [Cargo reference][1]:
/// - `major >= 1`: compatible within the same major (`^1.x.y`).
/// - `0.y.z` (minor >= 1): compatible within the same minor (`^0.y.z`).
/// - `0.0.z`: every patch is its own group — *no* `to` other than the same
///   `from` is compatible.
///
/// Returns [`BumpTier::Compatible`] when `from` and `to` live in the same
/// group (i.e. only a manifest-constraint pin keeps cargo from bumping
/// — non-breaking by Cargo's contract), [`BumpTier::Breaking`] otherwise.
/// Defensively returns `Breaking` for unparseable versions so the operator
/// gets a chance to look rather than silently skipping the upgrade.
///
/// [1]: https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#caret-requirements
pub fn classify_unchanged_bump(from: &str, to: &str) -> BumpTier {
    let Ok(from_v) = semver::Version::parse(from) else {
        return BumpTier::Breaking;
    };
    let Ok(to_v) = semver::Version::parse(to) else {
        return BumpTier::Breaking;
    };
    if compat_group(&from_v) == compat_group(&to_v) {
        BumpTier::Compatible
    } else {
        BumpTier::Breaking
    }
}

/// Cargo's caret-compatibility group key. Two versions are caret-compatible
/// iff their group keys are equal. See [`classify_unchanged_bump`].
fn compat_group(v: &semver::Version) -> (u64, u64, u64) {
    match (v.major, v.minor) {
        (0, 0) => (0, 0, v.patch),
        (0, _) => (0, v.minor, 0),
        _ => (v.major, 0, 0),
    }
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
            bump_tier: BumpTier::LockfileOnly,
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

/// Apply a Cargo proposal to a working tree. Tier-aware:
///
/// - [`BumpTier::LockfileOnly`] runs `cargo update --workspace` in place
///   (the in-range bump cargo already detected as available).
/// - [`BumpTier::Compatible`] / [`BumpTier::Breaking`] widen each
///   workspace Cargo.toml's constraint on the subject crate to the
///   proposal's `to` version, then run `cargo update --workspace` so
///   the lockfile picks up the now-permitted version. Aborts loudly
///   if no manifest in the workspace carries a constraint to widen —
///   the proposer must not surface bumps the applier can't reach.
pub fn apply_cargo_proposal(proposal: &Proposal, tree_path: &Path) -> Result<()> {
    if !matches!(proposal.bump_tier, BumpTier::LockfileOnly) {
        let modified =
            crate::ecosystem::cargo_manifest_editor::apply_constraint_widening_to_workspace(
                tree_path,
                &proposal.subject,
                &proposal.to,
            )?;
        if modified.is_empty() {
            return Err(Error::other(format!(
                "expected to widen the constraint for `{}` in {} workspace but no manifest carried a matching dep entry",
                proposal.subject,
                tree_path.display(),
            )));
        }
    }
    apply_cargo_update_to_tree(tree_path)
}

/// Copy validated changes from sandbox back to host. Always carries
/// Cargo.lock; for non-LockfileOnly tiers also ships any Cargo.toml
/// whose bytes differ between sandbox and host (the constraint widening
/// done by `apply_cargo_proposal` typically lands in one manifest, but
/// a workspace with the same dep declared in multiple members may have
/// touched several).
pub fn copy_back_cargo_proposal(
    proposal: &Proposal,
    sandbox: &Path,
    host: &Path,
) -> Result<Vec<PathBuf>> {
    let mut copied: Vec<PathBuf> = Vec::new();

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
    copied.push(PathBuf::from("Cargo.lock"));

    if !matches!(proposal.bump_tier, BumpTier::LockfileOnly) {
        let manifests = crate::ecosystem::cargo_manifest_editor::list_workspace_manifests(sandbox)?;
        for sb_manifest in manifests {
            let rel = sb_manifest
                .strip_prefix(sandbox)
                .unwrap_or(&sb_manifest)
                .to_path_buf();
            if !sb_manifest.is_file() {
                continue;
            }
            let host_manifest = host.join(&rel);
            let sb_bytes = std::fs::read(&sb_manifest).map_err(|source| Error::Io {
                path: sb_manifest.clone(),
                source,
            })?;
            let host_bytes = std::fs::read(&host_manifest).unwrap_or_default();
            if sb_bytes == host_bytes {
                continue;
            }
            std::fs::copy(&sb_manifest, &host_manifest).map_err(|source| Error::Io {
                path: host_manifest,
                source,
            })?;
            copied.push(rel);
        }
        copied.sort();
        // Dedup just in case (Cargo.lock first, manifests after).
        copied.dedup();
    }

    Ok(copied)
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

/// Invoke `cargo update --dry-run --workspace` against the host repo's
/// own manifest and parse the result into proposals.
///
/// **Why direct, not cloned to a tempdir.** An earlier design cloned the
/// repo into `tempfile::TempDir` and ran cargo there for write isolation.
/// That breaks on any project with **out-of-tree path deps** — e.g.
/// `wildmason-license = { path = "../../licensing/crate" }` in a Tauri
/// project's `src-tauri/Cargo.toml`. Once cloned, the relative path
/// resolves into a non-existent location and cargo refuses to even
/// enumerate the dep graph.
///
/// `--dry-run` is non-mutating to the lockfile by design, so running on
/// the host is safe. Cargo's user-level registry cache
/// (`~/.cargo/registry`) gets refreshed as a side effect, which is
/// behavior the operator already expects from any cargo invocation.
///
/// **Lockfile cross-check trade-off.** The earlier design ran a second
/// `cargo update` (non-dry-run) in the tempdir to produce a real
/// lockfile diff, then cross-checked it against the parsed stdout —
/// catching parser drift if cargo's stdout format ever changed. Without
/// a tempdir, we can't run the mutating side without touching the host.
/// We accept the parser-only path for v1; [`propose_from_cargo_dry_run`]
/// keeps the cross-check available for callers that *do* have an
/// after-lockfile to compare.
fn run_cargo_proposer(repo: &Path, manifests: &[Manifest]) -> Result<Vec<Proposal>> {
    let manifest_path = repo.join("Cargo.toml");
    let manifest_str = manifest_path
        .to_str()
        .ok_or_else(|| Error::other("Cargo.toml path is not valid UTF-8"))?;
    // `--verbose` is what surfaces the `Unchanged X v$OLD (available: v$NEW)`
    // lines we need for the Compatible / Breaking tiers. Without it, cargo
    // prints only a `note: pass --verbose to see N unchanged…` hint and the
    // 100+ constraint-pinned upgrade opportunities stay invisible.
    let dry_run_output = run_cargo_command(
        repo,
        &[
            "update",
            "--dry-run",
            "--workspace",
            "--verbose",
            "--manifest-path",
            manifest_str,
        ],
    )?;
    if !dry_run_output.success {
        return Err(Error::CargoUpdate {
            message: format!(
                "cargo update --dry-run exited non-zero: stderr=\n{}\nstdout=\n{}",
                dry_run_output.stderr.trim(),
                dry_run_output.stdout.trim()
            ),
        });
    }

    let manifest_paths: Vec<PathBuf> = manifests
        .iter()
        .filter(|m| matches!(m.kind, ManifestKind::CargoLock | ManifestKind::CargoToml))
        .map(|m| m.path.clone())
        .collect();

    // Cargo emits all human-readable progress (Updating / Unchanged /
    // Locking lines) to STDERR, with stdout reserved for the JSON
    // resolver output that `--message-format=json` would produce. We
    // run without `--message-format=json`, so the text we want is on
    // stderr. Earlier code paths read stdout alone and quietly returned
    // zero proposals on real repos; the synthetic test fixtures fed
    // stdout directly and so never caught the mismatch. Concatenating
    // both streams here is robust regardless of which cargo version is
    // installed.
    let combined = format!("{}\n{}", dry_run_output.stdout, dry_run_output.stderr);
    let mut proposals = propose_from_cargo_stdout(&combined, &manifest_paths)?;

    // Unchanged-line proposals get filtered against the set of *direct*
    // workspace dependencies. cargo's verbose output also lists
    // transitive deps that are "behind latest", but those have no
    // constraint entry in this workspace's manifests — they'd be
    // bumped by widening the parent direct dep. Surfacing them as
    // proposals here would create fake actionable items the applier
    // would (correctly) refuse with "expected to widen the constraint
    // for X but no manifest carried a matching dep entry".
    let unchanged = propose_unchanged_from_cargo_stdout(&combined, &manifest_paths);
    let direct = collect_direct_dep_names(repo)?;
    proposals.extend(filter_to_direct_deps(unchanged, &direct));
    Ok(proposals)
}

/// Returns the set of *direct* (declared in some workspace member's
/// Cargo.toml) dependency names. Used to drop transitive-only entries
/// from the Unchanged-line tier proposals — the constraint editor can
/// only widen entries that actually appear in a manifest.
fn collect_direct_dep_names(repo: &Path) -> Result<std::collections::BTreeSet<String>> {
    use cargo_metadata::MetadataCommand;
    let manifest_path = repo.join("Cargo.toml");
    if !manifest_path.is_file() {
        return Ok(std::collections::BTreeSet::new());
    }
    let metadata = MetadataCommand::new()
        .manifest_path(&manifest_path)
        .no_deps()
        .exec()
        .map_err(|e| {
            Error::other(format!(
                "cargo metadata (for direct-dep filter) failed: {e}"
            ))
        })?;
    let mut names = std::collections::BTreeSet::new();
    for pkg in &metadata.packages {
        for dep in &pkg.dependencies {
            // `dep.name` is the source-of-truth package name even when
            // a member renames via `foo = { package = "actual", ... }`.
            names.insert(dep.name.clone());
        }
    }
    Ok(names)
}

/// Pure filter: keep only proposals whose `subject` (crate name) is in
/// `direct_names`. Split out so the proposer's transitive-dep filter
/// can be exercised against synthetic inputs without spinning up
/// cargo metadata.
fn filter_to_direct_deps(
    proposals: Vec<Proposal>,
    direct_names: &std::collections::BTreeSet<String>,
) -> Vec<Proposal> {
    proposals
        .into_iter()
        .filter(|p| direct_names.contains(&p.subject))
        .collect()
}

/// Build [`BumpTier::Compatible`] and [`BumpTier::Breaking`] proposals from
/// the `Unchanged X vFROM (available: vTO[, requires Rust X.Y.Z])` lines
/// emitted by `cargo update --dry-run --verbose`. Each line becomes a
/// report-only proposal — assay surfaces it but does NOT auto-apply,
/// because closing the gap requires editing Cargo.toml constraints,
/// not just regenerating the lockfile. (The constraint-edit applier
/// lands in a follow-up commit.)
///
/// `requires_rust` notes from cargo ride along in `notes` so the
/// operator sees the MSRV ask before deciding to merge.
pub fn propose_unchanged_from_cargo_stdout(
    stdout: &str,
    manifest_paths: &[PathBuf],
) -> Vec<Proposal> {
    let parsed = parse_cargo_unchanged_output(stdout);
    let mut proposals = Vec::with_capacity(parsed.len());
    for line in &parsed {
        let tier = classify_unchanged_bump(&line.from, &line.to);
        let id = format!(
            "cargo-{}-{}",
            sanitize_id_segment(&line.crate_name),
            sanitize_id_segment(&line.to),
        );
        let mut notes = Vec::new();
        if let Some(rust) = &line.requires_rust {
            notes.push(format!("requires Rust {rust}"));
        }
        proposals.push(Proposal {
            id,
            ecosystem: EcosystemName::Cargo.as_str().to_string(),
            kind: ProposalKind::Version,
            subject: line.crate_name.clone(),
            from: line.from.clone(),
            to: line.to.clone(),
            initial_classification: Classification::Exact,
            manifest_paths: manifest_paths.to_vec(),
            notes,
            bump_tier: tier,
        });
    }
    proposals
}

/// Build proposals from `cargo update --dry-run` stdout without the
/// lockfile-diff cross-check. Used by [`run_cargo_proposer`] which can't
/// generate an after-lockfile without a mutating cargo invocation.
pub fn propose_from_cargo_stdout(
    stdout: &str,
    manifest_paths: &[PathBuf],
) -> Result<Vec<Proposal>> {
    let parsed = parse_cargo_update_output(stdout);
    let mut proposals = Vec::new();
    for line in &parsed {
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
            bump_tier: BumpTier::LockfileOnly,
        });
    }
    Ok(proposals)
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
        assert_eq!(serde.id, "cargo-serde-1-0-215");
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
