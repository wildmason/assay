//! Parsers for `cargo update --dry-run [--verbose]` output and lockfile
//! diffs.
//!
//! `parse_cargo_update_output` and `parse_cargo_unchanged_output` consume
//! cargo's human-readable stdout/stderr; `diff_lockfiles` consumes the
//! `Cargo.lock` TOML before/after a cargo invocation. The two paths are
//! cross-checked in `cross_check` (see [`super::propose::propose_from_cargo_dry_run`])
//! to defend against cargo stdout format drift.

use std::collections::BTreeMap;

use crate::error::{Error, Result};

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

pub(super) fn lockfile_versions(toml_text: &str) -> Result<BTreeMap<String, String>> {
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

/// Cross-check that the stdout parser and lockfile diff agree on the
/// set of changes. If they disagree (different crates, different
/// versions), returns [`Error::CargoParserMismatch`] so the caller can
/// abort the run loudly rather than silently shipping the wrong proposals.
pub(super) fn cross_check(parsed: &[CargoUpdateLine], diffed: &[CargoUpdateLine]) -> Result<()> {
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
