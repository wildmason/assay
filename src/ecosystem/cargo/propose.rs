//! Proposer for the cargo ecosystem: turn `cargo update --dry-run` output
//! into [`Proposal`] objects.
//!
//! `run_cargo_proposer` shells out to cargo against the host repo's own
//! manifest (no tempdir clone — see the doc-comment on the function for
//! why); the per-line parsers in [`super::parse`] and the tier classifier
//! in [`super::classify`] turn raw stdout/stderr into typed proposals.
//! Output is filtered against per-ecosystem ignore lists and tagged with
//! cargo-family cohorts before returning.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::model::{BumpTier, Classification, Manifest, ManifestKind, Proposal, ProposalKind};

use super::super::EcosystemName;
use super::classify::classify_unchanged_bump;
use super::parse::{
    cross_check, diff_lockfiles, lockfile_versions, parse_cargo_unchanged_output,
    parse_cargo_update_output,
};

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
            "cargo-{}-{}-to-{}",
            sanitize_id_segment(&line.crate_name),
            sanitize_id_segment(&line.from),
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
            affected_consumers: Vec::new(),
            explanation: None,
            cohort: None,
        });
    }
    Ok(proposals)
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
pub(super) fn run_cargo_proposer(repo: &Path, manifests: &[Manifest]) -> Result<Vec<Proposal>> {
    // `--manifest-path Cargo.toml` is resolved against the subprocess
    // CWD (which we set to `repo` below). Passing `repo.join("Cargo.toml")`
    // here would double up the path when `repo` is itself relative —
    // e.g. polyglot Tauri scan_root `src-tauri/` + manifest-path
    // `src-tauri/Cargo.toml` = `src-tauri/src-tauri/Cargo.toml`, which
    // cargo correctly reports as nonexistent.
    let manifest_str = "Cargo.toml";
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

/// Filter out proposals whose `subject` (crate name) appears in the
/// per-ecosystem ignore list from `.assay.toml`'s
/// `[ecosystems.cargo] ignore = [...]`. Exact-match, mirroring the
/// GHA filter.
pub(crate) fn filter_ignored_crates(proposals: Vec<Proposal>, ignored: &[String]) -> Vec<Proposal> {
    if ignored.is_empty() {
        return proposals;
    }
    proposals
        .into_iter()
        .filter(|p| !ignored.iter().any(|i| i == &p.subject))
        .collect()
}

/// Set the `cohort` field on every cargo proposal whose subject
/// matches a known crate-family cohort definition. Pure annotation
/// pass — no proposals added, dropped, or rewritten; just tagged
/// so the reporter can group them under one heading and the
/// validator/applier treat them as atomic units. Stand-alone
/// crates (`anyhow`, `thiserror`, `regex`, …) keep `cohort: None`.
/// See [`super::super::cargo_cohorts::KNOWN_COHORTS`].
pub(crate) fn tag_proposals_with_cargo_cohorts(proposals: &mut [Proposal]) {
    for p in proposals.iter_mut() {
        if let Some(c) = super::super::cargo_cohorts::match_cohort(&p.subject) {
            p.cohort = Some(c.id.to_string());
        }
    }
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
pub(super) fn filter_to_direct_deps(
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
            "cargo-{}-{}-to-{}",
            sanitize_id_segment(&line.crate_name),
            sanitize_id_segment(&line.from),
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
            affected_consumers: Vec::new(),
            explanation: None,
            cohort: None,
        });
    }
    proposals
}

/// Build proposals from `cargo update --dry-run` stdout without the
/// lockfile-diff cross-check. Used by `run_cargo_proposer` which can't
/// generate an after-lockfile without a mutating cargo invocation.
pub fn propose_from_cargo_stdout(
    stdout: &str,
    manifest_paths: &[PathBuf],
) -> Result<Vec<Proposal>> {
    let parsed = parse_cargo_update_output(stdout);
    let mut proposals = Vec::new();
    for line in &parsed {
        let id = format!(
            "cargo-{}-{}-to-{}",
            sanitize_id_segment(&line.crate_name),
            sanitize_id_segment(&line.from),
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
            affected_consumers: Vec::new(),
            explanation: None,
            cohort: None,
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
/// Build a single synthetic [`Proposal`] for an operator-specified
/// `--dep <name>@<version>` upgrade.
///
/// Reads `Cargo.lock` at `repo` to discover the dep's currently-resolved
/// version (the proposal's `from`). When `name` isn't declared in the
/// lockfile (or the lockfile is absent), returns `Ok(None)` so the cli
/// can try the next ecosystem. When the lockfile already pins
/// `target_version`, also returns `Ok(None)` so the run exits cleanly
/// without a no-op proposal.
///
/// Tier classification reuses [`classify_unchanged_bump`] (Compatible
/// when from→to stays within the same caret group, Breaking otherwise).
/// The proposal bypasses LockfileOnly tier — even bumps that satisfy
/// the existing constraint route through the constraint-widening
/// applier, which is correct (idempotent widen to the same value) but
/// produces a manifest churn that the discovery proposer would have
/// avoided. Refining this is a follow-up; for v1 the goal is "make
/// `--dep` work end-to-end" and Compatible/Breaking is conservative-correct.
pub(super) fn synthesize_dep_proposal(
    name: &str,
    target_version: &str,
    manifests: &[Manifest],
    repo: &Path,
) -> Result<Option<Proposal>> {
    let lockfile_path = repo.join("Cargo.lock");
    let lockfile_text = match std::fs::read_to_string(&lockfile_path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(crate::error::Error::Io {
                path: lockfile_path,
                source: err,
            });
        }
    };
    let versions = lockfile_versions(&lockfile_text)?;
    let Some(current) = versions.get(name) else {
        return Ok(None);
    };
    if current == target_version {
        eprintln!(
            "[cargo] {name} already resolves to {target_version} in Cargo.lock; nothing to validate",
        );
        return Ok(None);
    }

    let manifest_paths: Vec<PathBuf> = manifests
        .iter()
        .filter(|m| {
            matches!(
                m.kind,
                crate::model::ManifestKind::CargoLock | crate::model::ManifestKind::CargoToml
            )
        })
        .map(|m| m.path.clone())
        .collect();
    let tier = classify_unchanged_bump(current, target_version);
    let id = format!(
        "cargo-{}-{}-to-{}",
        sanitize_id_segment(name),
        sanitize_id_segment(current),
        sanitize_id_segment(target_version),
    );
    Ok(Some(Proposal {
        id,
        ecosystem: EcosystemName::Cargo.as_str().to_string(),
        kind: ProposalKind::Version,
        subject: name.to_string(),
        from: current.clone(),
        to: target_version.to_string(),
        initial_classification: Classification::Exact,
        manifest_paths,
        notes: vec!["source:--dep (operator-specified target)".to_string()],
        bump_tier: tier,
        affected_consumers: Vec::new(),
        explanation: None,
        cohort: None,
    }))
}

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
