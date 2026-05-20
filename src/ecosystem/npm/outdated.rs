//! `npm outdated --json` / `pnpm outdated --format=json` /
//! `yarn outdated --json` parsers, plus `package-lock.json` reader used to
//! backfill `current` when `npm outdated` runs against an un-installed tree.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::error::{Error, Result};

/// Single entry from `npm outdated --json` / `pnpm outdated --format=json`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct OutdatedEntry {
    /// Resolved version in the lockfile. May be absent when the package
    /// is in `package.json` but hasn't been installed yet.
    #[serde(default)]
    current: Option<String>,
    /// Highest version that satisfies the current constraint. Absent
    /// when pnpm reports a `file:` / `link:` / `workspace:` dep — those
    /// have no registry-side "wanted" to bump to and are skipped by
    /// the proposer.
    #[serde(default)]
    wanted: Option<String>,
    /// Most recent publish on the registry. Absent for the same
    /// non-registry dep flavors as `wanted` above.
    #[serde(default)]
    latest: Option<String>,
}

/// One JSON value per dep emitted by `npm outdated --json`.
///
/// In a flat (single-project) project the shape is one [`OutdatedEntry`]
/// per dep. In a workspace project (npm 7+ workspaces) it's an **array**
/// of entries — one per consuming member — so the same dep can appear
/// multiple times with the same (current, wanted, latest) tuple but
/// different `dependent` values. The first entry suffices for proposal
/// generation because npm hoists workspace deps to the root
/// `node_modules`, so every consumer sees the same resolved version.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum OutdatedValue {
    Single(OutdatedEntry),
    PerConsumer(Vec<OutdatedEntry>),
}

/// Parsed proposal-ready entry combining the dep name with its versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NpmOutdatedRow {
    pub name: String,
    pub current: Option<String>,
    pub wanted: String,
    pub latest: String,
}

/// Parses the JSON object emitted by `npm outdated --json` /
/// `pnpm outdated --format=json`. Returns rows sorted by name so
/// downstream proposal IDs are deterministic across runs.
///
/// Empty input (no outdated packages, both reporters emit `{}` and exit
/// non-zero from npm — but with `--json` the body is still well-formed
/// JSON) parses to an empty Vec.
///
/// Handles both the flat (single-project) shape `{ "lodash": {...} }`
/// and the workspace shape `{ "lodash": [ {...}, {...} ] }` that npm 7+
/// emits when the project has workspaces. Per-consumer arrays are
/// collapsed to one row per dep using the first entry — assay treats
/// the bump as a single workspace-level event; per-member dep
/// declarations are surfaced via `affected_consumers` downstream.
pub(crate) fn parse_npm_outdated_output(stdout: &str) -> Result<Vec<NpmOutdatedRow>> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let parsed: BTreeMap<String, OutdatedValue> = serde_json::from_str(trimmed)
        .map_err(|e| Error::other(format!("npm outdated JSON: {e}")))?;
    let mut rows: Vec<NpmOutdatedRow> = Vec::new();
    for (name, value) in parsed {
        let entry = match value {
            OutdatedValue::Single(e) => e,
            OutdatedValue::PerConsumer(entries) => match entries.into_iter().next() {
                Some(e) => e,
                None => continue,
            },
        };
        // Skip non-registry deps (`file:`, `link:`, `workspace:`) — pnpm
        // -r emits these with `wanted` or `latest` absent (or a path-shaped
        // `wanted`), and there's no registry-side version to bump to.
        let (Some(wanted), Some(latest)) = (entry.wanted, entry.latest) else {
            continue;
        };
        rows.push(NpmOutdatedRow {
            name,
            current: entry.current,
            wanted,
            latest,
        });
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(rows)
}

/// Parse yarn1's `yarn outdated --json` output (newline-delimited JSON).
///
/// Yarn 1 wraps the actual data in a table envelope:
///
/// ```text
/// {"type":"info","data":"Color legend : ..."}
/// {"type":"table","data":{"head":["Package","Current","Wanted","Latest","Package Type","URL"],
///   "body":[["lodash","4.17.20","4.17.21","4.18.1","dependencies","https://lodash.com/"]]}}
/// ```
///
/// Each `body` row carries `[name, current, wanted, latest, package_type,
/// url]`. We pick the first `type: "table"` line and emit one row per
/// body entry.
///
/// Returns an empty Vec when the stream contains no `table` line (yarn
/// emits `{"type":"info",...}` even when nothing is outdated).
pub(crate) fn parse_yarn1_outdated_output(stdout: &str) -> Result<Vec<NpmOutdatedRow>> {
    let mut rows: Vec<NpmOutdatedRow> = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue;
        };
        let kind = value.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if kind != "table" {
            continue;
        }
        let Some(data) = value.get("data") else {
            continue;
        };
        let Some(body) = data.get("body").and_then(|v| v.as_array()) else {
            continue;
        };
        for entry in body {
            let Some(cells) = entry.as_array() else {
                continue;
            };
            if cells.len() < 4 {
                continue;
            }
            let Some(name) = cells.first().and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(current) = cells.get(1).and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(wanted) = cells.get(2).and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(latest) = cells.get(3).and_then(|v| v.as_str()) else {
                continue;
            };
            rows.push(NpmOutdatedRow {
                name: name.to_string(),
                current: Some(current.to_string()),
                wanted: wanted.to_string(),
                latest: latest.to_string(),
            });
        }
        // Stop after the first table — yarn1 emits only one.
        break;
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(rows)
}

/// Read each `node_modules/<name>` entry from a `package-lock.json` v3
/// `packages` map. Returns a `name -> version` lookup for use when
/// `npm outdated` omits the `current` field (no installed
/// node_modules).
pub(crate) fn read_lockfile_versions(repo: &Path) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let lockfile = repo.join("package-lock.json");
    if !lockfile.is_file() {
        return Ok(out);
    }
    let text = std::fs::read_to_string(&lockfile).map_err(|source| Error::Io {
        path: lockfile.clone(),
        source,
    })?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| Error::other(format!("package-lock.json parse: {e}")))?;
    // Modern lockfile shape (v2/v3): `packages` map keyed by
    // `"node_modules/<name>"`. Nested deps may have keys like
    // `"node_modules/a/node_modules/b"` — those are transitive copies
    // and we want the *top-level* resolution. The simplest pick: take
    // the first occurrence of each `<name>`. v1 lockfiles use a
    // `dependencies` tree which we skip — modern projects (npm 7+)
    // produce v2/v3 by default.
    if let Some(packages) = value.get("packages").and_then(|v| v.as_object()) {
        for (key, entry) in packages {
            let Some(rest) = key.strip_prefix("node_modules/") else {
                continue;
            };
            // Skip nested deps; only top-level `node_modules/<name>`.
            if rest.contains("/node_modules/") {
                continue;
            }
            let Some(version) = entry.get("version").and_then(|v| v.as_str()) else {
                continue;
            };
            out.entry(rest.to_string())
                .or_insert_with(|| version.to_string());
        }
    }
    Ok(out)
}

pub(super) fn backfill_current_from_lockfile(
    repo: &Path,
    rows: &mut [NpmOutdatedRow],
) -> Result<()> {
    let needs_backfill = rows.iter().any(|r| r.current.is_none());
    if !needs_backfill {
        return Ok(());
    }
    let lockfile = read_lockfile_versions(repo)?;
    for row in rows.iter_mut() {
        if row.current.is_none()
            && let Some(v) = lockfile.get(&row.name)
        {
            row.current = Some(v.clone());
        }
    }
    Ok(())
}
