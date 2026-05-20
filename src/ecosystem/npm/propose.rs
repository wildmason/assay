//! High-level npm proposer + the cohort / overrides / ignore annotation
//! pipeline.
//!
//! `run_npm_proposer` chooses the path (npm/pnpm/yarn1 outdated subprocess
//! vs the per-dep berry walk in [`super::berry`]), turns each
//! [`super::outdated::NpmOutdatedRow`] into a [`Proposal`] via
//! `build_npm_proposals`, and filters down to direct deps so the
//! constraint-edit applier never sees a transitive entry it can't widen.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::model::{BumpTier, Classification, Manifest, Proposal, ProposalKind};
use crate::process_runner::{RunResult, run_with_timeout};

use super::super::EcosystemName;
use super::berry::{parse_berry_lockfile, propose_berry_updates};
use super::classify::classify_npm_bump;
use super::direct_deps::{collect_direct_dep_names, collect_direct_deps_with_constraints};
use super::flavor::{NpmFlavor, detect_flavor, map_npm_spawn_io, npm_binary_name};
use super::outdated::{
    NpmOutdatedRow, backfill_current_from_lockfile, parse_npm_outdated_output,
    parse_yarn1_outdated_output, read_lockfile_versions,
};

/// Builds proposals from parsed outdated rows. Tier mapping mirrors
/// cargo's: when the lockfile-wanted version equals the registry latest,
/// the bump only needs `npm update` (LockfileOnly). When it doesn't,
/// the constraint blocks the latest and tier classification falls back
/// to the caret-compat-group comparison between current and latest.
///
/// Rows with no `current` (package declared but never installed) are
/// skipped — we have no "from" to compare against.
pub(crate) fn build_npm_proposals(
    rows: &[NpmOutdatedRow],
    manifest_paths: &[PathBuf],
) -> Vec<Proposal> {
    let mut proposals = Vec::new();
    for row in rows {
        let Some(current) = row.current.as_deref() else {
            continue;
        };
        // When `npm outdated` runs without a populated node_modules it
        // includes every package, even ones where the lockfile already
        // matches the registry latest. Drop those — there's nothing to
        // bump.
        if current == row.latest {
            continue;
        }
        let tier = if row.wanted == row.latest {
            BumpTier::LockfileOnly
        } else {
            classify_npm_bump(current, &row.latest)
        };
        let id = format!(
            "npm-{}-{}-to-{}",
            sanitize_id_segment(&row.name),
            sanitize_id_segment(current),
            sanitize_id_segment(&row.latest),
        );
        proposals.push(Proposal {
            id,
            ecosystem: EcosystemName::Npm.as_str().to_string(),
            kind: ProposalKind::Version,
            subject: row.name.clone(),
            from: current.to_string(),
            to: row.latest.clone(),
            initial_classification: Classification::Exact,
            manifest_paths: manifest_paths.to_vec(),
            notes: Vec::new(),
            bump_tier: tier,
            affected_consumers: Vec::new(),
            explanation: None,
            cohort: None,
        });
    }
    proposals
}

/// Filter proposals down to direct deps declared in `package.json` (root
/// + any workspace members). Drops transitive entries that `npm
/// outdated` surfaces but the applier can't widen.
pub(crate) fn filter_to_direct_deps(
    proposals: Vec<Proposal>,
    direct: &BTreeSet<String>,
) -> Vec<Proposal> {
    proposals
        .into_iter()
        .filter(|p| direct.contains(&p.subject))
        .collect()
}

pub(super) fn run_npm_proposer(
    flavor: NpmFlavor,
    repo: &Path,
    manifest_paths: &[PathBuf],
) -> Result<Vec<Proposal>> {
    let bin = npm_binary_name(flavor);
    if bin.is_empty() {
        return Ok(Vec::new());
    }
    // Yarn berry has no built-in `outdated` and goes through a
    // dedicated proposer that walks direct deps + queries `yarn npm
    // info` per dep. Route here instead of falling through the
    // outdated-subprocess path below.
    if matches!(flavor, NpmFlavor::YarnBerry) {
        return propose_berry_updates(repo, manifest_paths);
    }
    let args: &[&str] = match flavor {
        // `npm outdated` from a workspace root enumerates workspace
        // member deps via npm 7+ flattening; no recursive flag needed.
        NpmFlavor::Npm => &["outdated", "--json"],
        // `pnpm outdated` from a workspace root reports ONLY the root
        // package's deps. `-r` (recursive) enumerates every workspace
        // member's outdated entries; without it, monorepos look empty.
        NpmFlavor::Pnpm => &["outdated", "-r", "--format=json"],
        // Yarn 1 has no `-r` analogue and doesn't ship native
        // workspaces in the same shape; yarn 1's `outdated --json`
        // surfaces the project's flat dep set.
        NpmFlavor::Yarn => &["outdated", "--json"],
        // Routed above.
        NpmFlavor::YarnBerry => unreachable!("YarnBerry handled by propose_berry_updates"),
    };

    let mut cmd = std::process::Command::new(bin);
    cmd.args(args).current_dir(repo);
    let run = run_with_timeout(cmd, std::time::Duration::from_secs(120))
        .map_err(|source| map_npm_spawn_io(source, bin, flavor, repo))?;
    let RunResult::Completed { status, stdout, .. } = run else {
        return Err(Error::other(format!(
            "{bin} outdated timed out against `{}`",
            repo.display()
        )));
    };
    // npm outdated exits non-zero when packages are outdated; we ignore
    // the exit code and rely on parsing.
    let _ = status;
    let stdout_str = String::from_utf8_lossy(&stdout);

    let mut rows = match flavor {
        NpmFlavor::Yarn => parse_yarn1_outdated_output(&stdout_str)?,
        NpmFlavor::YarnBerry => {
            unreachable!("YarnBerry routed through propose_berry_updates")
        }
        _ => parse_npm_outdated_output(&stdout_str)?,
    };
    // When `node_modules` isn't materialized, `npm outdated` omits the
    // `current` field. Fall back to the package-lock.json's resolved
    // version so assay can still surface proposals without forcing the
    // operator to run `npm install` first. (yarn1 typically reports
    // `current` directly, but the backfill is a no-op for already-set
    // rows.)
    if matches!(flavor, NpmFlavor::Npm) {
        backfill_current_from_lockfile(repo, &mut rows)?;
    }
    let proposals = build_npm_proposals(&rows, manifest_paths);
    let direct = collect_direct_dep_names(repo)?;
    Ok(filter_to_direct_deps(proposals, &direct))
}

/// Set the `cohort` field on every proposal whose subject matches a
/// known framework cohort definition. Pure annotation pass — no
/// proposals are added, dropped, or rewritten; just tagged so the
/// reporter can group them under one heading and the validator/
/// applier can treat them as atomic units. Stand-alone packages
/// (`lodash`, `typescript`, `vite`, `@types/*`, etc.) keep
/// `cohort: None`. See [`crate::ecosystem::npm_cohorts::KNOWN_COHORTS`].
pub(crate) fn tag_proposals_with_cohorts(proposals: &mut [Proposal]) {
    for p in proposals.iter_mut() {
        if let Some(c) = super::super::npm_cohorts::match_cohort(&p.subject) {
            p.cohort = Some(c.id.to_string());
        }
    }
}

/// Re-export so existing npm pipeline callers keep their shorter
/// import path. Real implementation lives in the shared
/// `ecosystem::cohort_pipeline` module since cargo now needs the
/// same widening logic.
pub(crate) use super::super::cohort_pipeline::widen_cohort_tiers;

/// Read the project's override declarations (npm `overrides`,
/// pnpm.overrides, yarn `resolutions`) from `package.json` and
/// attach a `note: "override-pinned to <version>"` to every proposal
/// whose subject is governed by an override. The proposal is NOT
/// dropped — the user still wants to see what the registry has —
/// but the note flags that adopting the proposal would conflict
/// with the existing pin.
///
/// Best-effort: a missing or malformed `package.json` produces no
/// annotations. Nested override paths (e.g. `"foo > bar"` meaning
/// "only when foo depends on bar") are flattened conservatively —
/// the bare package name on the LHS is treated as the override key
/// because that's what assay's exact-match against `Proposal.subject`
/// can act on.
pub(crate) fn annotate_proposals_with_overrides(proposals: &mut [Proposal], repo: &Path) {
    let overrides = match read_package_overrides(repo) {
        Some(m) if !m.is_empty() => m,
        _ => return,
    };
    for p in proposals.iter_mut() {
        if let Some(pin) = overrides.get(&p.subject) {
            p.notes.push(format!(
                "override-pinned to {pin}; adopting this bump would conflict"
            ));
        }
    }
}

/// Parse `package.json` for npm `overrides`, pnpm `pnpm.overrides`,
/// and yarn `resolutions` blocks. Returns a flat map from package
/// name → pinned spec. Returns `None` when the file is absent or
/// can't be parsed (the propose flow is best-effort; an unreadable
/// manifest just means no annotations).
fn read_package_overrides(repo: &Path) -> Option<std::collections::BTreeMap<String, String>> {
    use std::collections::BTreeMap;

    let path = repo.join("package.json");
    let text = std::fs::read_to_string(&path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    if let Some(obj) = json.get("overrides").and_then(|v| v.as_object()) {
        flatten_overrides(obj, &mut out);
    }
    if let Some(obj) = json
        .get("pnpm")
        .and_then(|p| p.get("overrides"))
        .and_then(|v| v.as_object())
    {
        flatten_overrides(obj, &mut out);
    }
    if let Some(obj) = json.get("resolutions").and_then(|v| v.as_object()) {
        flatten_overrides(obj, &mut out);
    }
    Some(out)
}

/// Flatten an npm/pnpm/yarn override block into `name -> spec`.
///
/// Three shapes are recognized:
///
/// - `"lodash": "1.0.0"` → `lodash` pinned to `1.0.0`.
/// - `"lodash": { "..": "1.0.0" }` → pnpm conditional override; the
///   `..` key means "regardless of parent" so this also pins
///   `lodash` to `1.0.0`. Other parent-keyed forms (e.g.
///   `"react": "18.0.0"` nested under `lodash`) are recorded with
///   the nested package name (`react`) as the pin target — that's
///   the npm semantic of "when X is a transitive of Y, force Y to
///   version Z."
/// - `"foo > bar": "1.0.0"` → npm path-key override; the
///   right-most segment (`bar`) is the package being pinned.
fn flatten_overrides(
    obj: &serde_json::Map<String, serde_json::Value>,
    out: &mut std::collections::BTreeMap<String, String>,
) {
    for (key, value) in obj {
        let pkg_name = override_key_to_package_name(key);
        match value {
            serde_json::Value::String(s) => {
                out.insert(pkg_name.to_string(), s.clone());
            }
            serde_json::Value::Object(nested) => {
                if let Some(serde_json::Value::String(s)) = nested.get("..") {
                    out.insert(pkg_name.to_string(), s.clone());
                }
                // Nested non-".." entries describe parent-scoped
                // pins; the inner key is the package being pinned.
                for (inner_key, inner_value) in nested {
                    if inner_key == ".." {
                        continue;
                    }
                    if let serde_json::Value::String(s) = inner_value {
                        let inner_pkg = override_key_to_package_name(inner_key);
                        out.insert(inner_pkg.to_string(), s.clone());
                    }
                }
            }
            _ => {}
        }
    }
}

/// Resolve an npm/pnpm/yarn override-key into a bare package name.
/// Keys like `"lodash"` → `lodash`; `"foo > bar"` (npm path form)
/// → `bar` (the right-most segment is the pinned package); empty or
/// malformed keys fall through to the original string so the caller
/// sees them in the receipt for debugging.
pub(super) fn override_key_to_package_name(key: &str) -> &str {
    if let Some((_, tail)) = key.rsplit_once('>') {
        return tail.trim();
    }
    key.trim()
}

/// Drop proposals whose `subject` exactly matches an entry in the
/// per-ecosystem ignore list. Mirrors `filter_ignored_crates`
/// ([`crate::ecosystem::cargo`]) and `filter_ignored_actions`
/// ([`crate::ecosystem::github_actions`]) so `--ignore npm:<name>`
/// behaves the same way across ecosystems. Scoped subjects like
/// `@angular/core` work because the comparison is byte-for-byte.
pub(crate) fn filter_ignored_packages(
    proposals: Vec<Proposal>,
    ignored: &[String],
) -> Vec<Proposal> {
    if ignored.is_empty() {
        return proposals;
    }
    proposals
        .into_iter()
        .filter(|p| !ignored.iter().any(|i| i == &p.subject))
        .collect()
}

/// Build a single synthetic [`Proposal`] for an operator-specified
/// `--dep <name>@<version>` upgrade across npm/pnpm/yarn1/yarn berry.
///
/// Looks up `name`'s currently-resolved version from the flavor-appropriate
/// lockfile (`package-lock.json` / `pnpm-lock.yaml` / `yarn.lock` flavor-
/// or berry-format). When that fails (lockfile absent or the dep isn't
/// pinned), falls back to the declared constraint string from
/// `package.json` (`^4.17.0` → `4.17.0`) — sufficient for proposal
/// generation but loses any version-narrowing the lockfile would have
/// provided. Returns `Ok(None)` when the dep isn't declared anywhere.
///
/// Tier classification reuses [`classify_npm_bump`]; LockfileOnly is
/// suppressed (see [`super::super::cargo::propose::synthesize_dep_proposal`]
/// for the same rationale — conservative-correct for v1, refinement is
/// a follow-up).
pub(super) fn synthesize_dep_proposal(
    name: &str,
    target_version: &str,
    manifests: &[Manifest],
    repo: &Path,
) -> Result<Option<Proposal>> {
    let Some(flavor) = detect_flavor(repo) else {
        // No lockfile means this project isn't actually npm-shaped at
        // this scan_root — bail without producing a proposal so the
        // cli can move on to the next ecosystem.
        return Ok(None);
    };
    let current = match resolve_current_version(name, flavor, repo)? {
        Some(v) => v,
        None => return Ok(None),
    };
    if current == target_version {
        eprintln!(
            "[npm] {name} already resolves to {target_version} in {}; nothing to validate",
            flavor.lockfile_name(),
        );
        return Ok(None);
    }

    let manifest_paths: Vec<PathBuf> = manifests
        .iter()
        .filter(|m| {
            matches!(
                m.kind,
                crate::model::ManifestKind::PackageJson | crate::model::ManifestKind::NpmLockfile
            )
        })
        .map(|m| m.path.clone())
        .collect();
    let tier = classify_npm_bump(&current, target_version);
    let id = format!(
        "npm-{}-{}-to-{}",
        sanitize_id_segment(name),
        sanitize_id_segment(&current),
        sanitize_id_segment(target_version),
    );
    Ok(Some(Proposal {
        id,
        ecosystem: EcosystemName::Npm.as_str().to_string(),
        kind: ProposalKind::Version,
        subject: name.to_string(),
        from: current,
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

/// Best-effort resolve of `name`'s currently-installed version under
/// `repo`, scoped to the detected lockfile flavor.
///
/// Order of preference: flavor-native lockfile parse, then the
/// declared constraint string from `package.json` with caret/tilde
/// stripped. Returns `Ok(None)` when neither source mentions `name`.
fn resolve_current_version(name: &str, flavor: NpmFlavor, repo: &Path) -> Result<Option<String>> {
    match flavor {
        NpmFlavor::Npm => {
            let lockfile = read_lockfile_versions(repo)?;
            if let Some(v) = lockfile.get(name) {
                return Ok(Some(v.clone()));
            }
        }
        NpmFlavor::YarnBerry => {
            let path = repo.join("yarn.lock");
            if let Ok(text) = std::fs::read_to_string(&path) {
                let installed = parse_berry_lockfile(&text)?;
                if let Some(v) = installed.get(name) {
                    return Ok(Some(v.clone()));
                }
            }
        }
        NpmFlavor::Pnpm => {
            // pnpm-lock.yaml's importer.dependencies.<name>.version
            // field carries the resolved version. Best-effort parse —
            // missing fields fall through to the package.json
            // constraint-stripping path below.
            if let Some(v) = read_pnpm_lockfile_version(name, repo)? {
                return Ok(Some(v));
            }
        }
        NpmFlavor::Yarn => {
            // yarn1's yarn.lock uses a custom format that's
            // fiddly to parse without a real parser. The
            // constraint-stripped fallback below covers the
            // common case; precise yarn1 lockfile reading is a
            // follow-up.
        }
    }
    // Fallback: read the declared constraint from package.json (root +
    // workspace members) and strip caret/tilde/etc to get a bare version.
    let declared = collect_direct_deps_with_constraints(repo)?;
    if let Some(spec) = declared.get(name) {
        return Ok(Some(strip_constraint_prefix(spec).to_string()));
    }
    Ok(None)
}

fn read_pnpm_lockfile_version(name: &str, repo: &Path) -> Result<Option<String>> {
    let path = repo.join("pnpm-lock.yaml");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(None);
    };
    let value: serde_yml::Value = match serde_yml::from_str(&text) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    // pnpm-lock.yaml v6+ shape:
    //   importers:
    //     <importer>:
    //       dependencies:
    //         <name>:
    //           specifier: ...
    //           version: <resolved>
    let Some(importers) = value.get("importers").and_then(|v| v.as_mapping()) else {
        return Ok(None);
    };
    for (_, importer) in importers {
        let Some(importer_map) = importer.as_mapping() else {
            continue;
        };
        for dep_field in ["dependencies", "devDependencies", "peerDependencies"] {
            let Some(deps) = importer_map
                .get(serde_yml::Value::String(dep_field.into()))
                .and_then(|v| v.as_mapping())
            else {
                continue;
            };
            let Some(entry) = deps.get(serde_yml::Value::String(name.into())) else {
                continue;
            };
            let Some(version) = entry
                .as_mapping()
                .and_then(|m| m.get(serde_yml::Value::String("version".into())))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            // pnpm sometimes appends `(peers...)` to the version
            // string. Strip everything after the first `(` to keep
            // the bare semver.
            let bare = version.split('(').next().unwrap_or(version).trim();
            if !bare.is_empty() {
                return Ok(Some(bare.to_string()));
            }
        }
    }
    Ok(None)
}

/// Strip caret/tilde/equals/operator prefixes from a constraint string,
/// returning the bare version inside. Multi-req ranges (`">=1, <2"`)
/// and tags / git refs are returned verbatim — the caller treats them
/// as the literal `from` and lets the classifier handle the awkwardness.
fn strip_constraint_prefix(spec: &str) -> &str {
    let trimmed = spec.trim();
    if let Some(rest) = trimmed.strip_prefix('^') {
        return rest;
    }
    if let Some(rest) = trimmed.strip_prefix('~') {
        return rest;
    }
    if let Some(rest) = trimmed.strip_prefix('=') {
        return rest;
    }
    if let Some(rest) = trimmed.strip_prefix(">=") {
        return rest;
    }
    if let Some(rest) = trimmed.strip_prefix("<=") {
        return rest;
    }
    if let Some(rest) = trimmed.strip_prefix('>') {
        return rest;
    }
    if let Some(rest) = trimmed.strip_prefix('<') {
        return rest;
    }
    trimmed
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
