//! Yarn Berry (yarn ≥ 2) specific paths.
//!
//! Berry core has no built-in `outdated` command, so the proposer walks
//! direct deps from package.json and queries `yarn npm info <pkg> --json`
//! per dep. We try corepack first (works on every modern Node) and fall
//! back to direct `yarn` for environments where corepack isn't installed
//! but the on-PATH `yarn` is already a berry-capable shim.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::model::Proposal;
use crate::process_runner::{RunResult, run_with_timeout};

use super::direct_deps::collect_direct_deps_with_constraints;
use super::flavor::{NpmFlavor, npm_binary_name};
use super::outdated::NpmOutdatedRow;
use super::propose::build_npm_proposals;

/// Parse a yarn berry `yarn.lock` file (YAML format with descriptor
/// blocks) and return a `subject -> installed_version` map.
///
/// Berry yarn.lock entries look like:
/// ```yaml
/// "lodash@npm:^4.17.21":
///   version: 4.17.21
///   resolution: "lodash@npm:4.17.21"
/// ```
/// Multiple descriptors may share a block via comma-separation. The
/// `__metadata:` header is skipped. Entries with no top-level `version`
/// field (e.g. workspace-protocol entries) are skipped — we can't
/// compare against a "current" version for them.
pub(crate) fn parse_berry_lockfile(text: &str) -> Result<BTreeMap<String, String>> {
    let value: serde_yml::Value = serde_yml::from_str(text)
        .map_err(|e| Error::other(format!("yarn.lock (berry) parse: {e}")))?;
    let mut out = BTreeMap::new();
    let Some(top) = value.as_mapping() else {
        return Ok(out);
    };
    for (key, val) in top {
        let Some(descriptor_blob) = key.as_str() else {
            continue;
        };
        if descriptor_blob == "__metadata" {
            continue;
        }
        let Some(version) = val
            .as_mapping()
            .and_then(|m| m.get(serde_yml::Value::String("version".into())))
            .and_then(|v| v.as_str())
        else {
            continue;
        };
        // The blob may carry multiple comma-separated descriptors
        // pointing at the same resolution. Yield one map entry per
        // distinct package name; if a name appears twice across
        // blobs (rare — same dep at two pinned versions) the last
        // wins, matching how berry itself surfaces the package.
        for descriptor in descriptor_blob.split(',').map(str::trim) {
            if descriptor.is_empty() {
                continue;
            }
            if let Some(name) = parse_berry_descriptor_name(descriptor) {
                out.insert(name, version.to_string());
            }
        }
    }
    Ok(out)
}

/// Extract just the package name from a berry descriptor.
///
/// Berry descriptors look like `<name>@<protocol>:<range>`, e.g.
/// `lodash@npm:^4.17.21` or `@types/node@npm:^20.10.0`. Scoped names
/// start with `@` and the relevant `@` separator is the SECOND `@`.
/// Workspace-protocol entries (`my-pkg@workspace:^`) parse the same
/// way; the caller decides whether to use them.
pub(super) fn parse_berry_descriptor_name(descriptor: &str) -> Option<String> {
    let trimmed = descriptor.trim().trim_matches('"');
    // Scoped names: find the second `@` (the one preceded by a
    // non-`@` char).
    if let Some(rest) = trimmed.strip_prefix('@') {
        let at = rest.find('@')?;
        Some(format!("@{}", &rest[..at]))
    } else {
        let at = trimmed.find('@')?;
        Some(trimmed[..at].to_string())
    }
}

/// Query `yarn npm info <pkg> --json` for `pkg`'s latest registry
/// version. Returns the version string from `dist-tags.latest`, or
/// `None` when the query fails, the package isn't on the registry,
/// or the response shape doesn't carry the expected fields.
///
/// Berry projects typically pin a specific yarn version via
/// `packageManager` in package.json and rely on
/// [corepack](https://nodejs.org/api/corepack.html) to dispatch the
/// `yarn` command to that version. The `yarn` binary on PATH may
/// itself be yarn1 (from a global `npm install -g yarn`) — that
/// binary rejects the berry-specific `yarn npm info` subcommand. To
/// support both shapes we try `corepack yarn ...` first (works on
/// every modern Node), then fall back to direct `yarn ...` for
/// environments where corepack isn't installed but the on-PATH
/// `yarn` is already a berry-capable shim.
///
/// Errors are NOT bubbled — a single registry hiccup shouldn't tank
/// the whole proposer run.
fn query_berry_latest_version(repo: &Path, pkg: &str) -> Option<String> {
    let yarn_bin = npm_binary_name(NpmFlavor::YarnBerry);
    // On Windows, npm-family binaries ship as `.cmd` shims around
    // node scripts; `Command::new` resolves only `.exe` automatically.
    // Same applies to corepack.
    let corepack_bin = if cfg!(windows) {
        "corepack.cmd"
    } else {
        "corepack"
    };
    let attempts: &[(&str, &[&str])] = &[
        // Corepack-mediated path. `corepack yarn ...` honours
        // package.json's `packageManager` field and reliably runs
        // berry even when the global `yarn` shim is yarn1.
        (corepack_bin, &["yarn", "npm", "info", pkg, "--json"]),
        // Direct path. Works when `yarn` itself is a berry binary
        // (e.g. when the project pins berry via `.yarn/releases/...`
        // and the shim PATH integration is set up correctly).
        (yarn_bin, &["npm", "info", pkg, "--json"]),
    ];
    for (bin, args) in attempts {
        let mut cmd = std::process::Command::new(bin);
        cmd.args(*args).current_dir(repo);
        let run = match run_with_timeout(cmd, std::time::Duration::from_secs(30)) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let RunResult::Completed { status, stdout, .. } = run else {
            continue;
        };
        if !status.success() {
            continue;
        }
        let text = String::from_utf8_lossy(&stdout);
        // berry's stdout may be a single JSON object or one-line-per-
        // package JSON streamed by `npm info`. Try whole-string parse
        // first, then fall back to the first parseable line.
        let trimmed = text.trim();
        let parsed = serde_json::from_str::<serde_json::Value>(trimmed)
            .ok()
            .or_else(|| {
                text.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .find_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            });
        let Some(value) = parsed else {
            continue;
        };
        if let Some(latest) = value
            .get("dist-tags")
            .and_then(|v| v.get("latest"))
            .and_then(|v| v.as_str())
        {
            return Some(latest.to_string());
        }
        if let Some(version) = value.get("version").and_then(|v| v.as_str()) {
            return Some(version.to_string());
        }
    }
    None
}

/// Yarn berry proposer — walks direct deps from package.json (root +
/// workspace members), queries `yarn npm info` for each, compares
/// against the berry yarn.lock's installed version, and emits one
/// proposal per (newer-version-available) dep.
///
/// Berry has no built-in `outdated` command in core (it was removed
/// in v2; a third-party plugin exists but isn't shipped by default),
/// so this per-dep walk is the canonical reliable path. Per-dep
/// registry queries are slow (N subprocesses per project) but
/// deterministic and don't require a plugin install.
pub(super) fn propose_berry_updates(repo: &Path, manifest_paths: &[PathBuf]) -> Result<Vec<Proposal>> {
    let direct = collect_direct_deps_with_constraints(repo)?;
    if direct.is_empty() {
        return Ok(Vec::new());
    }
    let lockfile_path = repo.join("yarn.lock");
    let installed = match std::fs::read_to_string(&lockfile_path) {
        Ok(text) => parse_berry_lockfile(&text)?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
        Err(err) => {
            return Err(Error::Io {
                path: lockfile_path,
                source: err,
            });
        }
    };
    let mut rows: Vec<NpmOutdatedRow> = Vec::new();
    let mut queried = 0usize;
    let mut succeeded = 0usize;
    for name in direct.keys() {
        queried += 1;
        let current = installed.get(name).cloned();
        let Some(latest) = query_berry_latest_version(repo, name) else {
            continue;
        };
        succeeded += 1;
        // Skip when no current version is known (dep declared but
        // never installed) or when the lockfile already matches the
        // latest registry version.
        let Some(current) = current else { continue };
        if current == latest {
            continue;
        }
        // Berry has no `wanted` signal (the in-constraint maximum
        // npm/pnpm both expose). Setting `wanted = current` forces
        // `build_npm_proposals` to route through
        // `classify_npm_bump` rather than collapsing every bump
        // to `LockfileOnly`. That keeps the tier classification
        // honest: an exact-pin constraint that doesn't satisfy
        // `latest` produces a Compatible/Breaking proposal that
        // requires manifest editing, while a caret-anchored
        // constraint that does satisfy `latest` will be re-tiered
        // to LockfileOnly by a future enhancement that inspects
        // the constraint string. For now we err on the side of
        // requiring the operator to review constraint edits.
        rows.push(NpmOutdatedRow {
            name: name.clone(),
            current: Some(current.clone()),
            wanted: current,
            latest,
        });
    }
    if queried > 0 && succeeded == 0 {
        eprintln!(
            "[npm:berry] queried {queried} direct dep(s) via `corepack yarn npm info` and `yarn npm info`; \
             neither pathway returned a usable registry response. Install corepack (or a berry-capable \
             yarn binary on PATH) so assay can resolve registry versions for this project.",
        );
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(build_npm_proposals(&rows, manifest_paths))
}
