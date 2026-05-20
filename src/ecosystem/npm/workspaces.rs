//! Workspace-member discovery (npm/yarn `workspaces`, pnpm-workspace.yaml)
//! and the npm-side `resolve_npm_consumers` that drives per-consumer
//! reporting in the Reporter.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::model::{ConsumerId, Proposal};

use super::peer_walk::{find_peer_dep_consumers, package_json_declares};

/// A workspace member discovered under `tree_path`.
///
/// `relative_path` is the workspace-relative directory holding the
/// member's `package.json`. `name` is whatever the member's
/// `package.json` declares (used as the [`ConsumerId`] in reports).
#[derive(Debug, Clone)]
pub(crate) struct WorkspaceMember {
    pub relative_path: PathBuf,
    pub name: String,
}

/// Discover npm/yarn/pnpm workspace members under `tree_path`.
///
/// Reads `workspaces` from the root `package.json` (either an array or
/// `{ packages: [...] }`) for npm/yarn, AND `packages:` from
/// `pnpm-workspace.yaml` for pnpm. Both sources are unioned — projects
/// rarely have both, but if they do we treat them as a combined set.
///
/// Glob patterns (`packages/*`, `apps/*-server`) are expanded relative
/// to `tree_path`. Each resolved directory is included only if it
/// contains a `package.json` with a parseable `name`. Members are
/// sorted by relative path and deduped.
///
/// Returns an empty Vec when no workspace declaration exists (the
/// single-project case).
pub(crate) fn detect_workspace_members(tree_path: &Path) -> Result<Vec<WorkspaceMember>> {
    // Canonicalize so `--repo .` works: the glob walker yields paths
    // relative to CWD, and a `Path::strip_prefix(".")` against an
    // already-relative match like `packages/alpha` fails. Resolving the
    // tree to absolute makes the prefix-strip consistent regardless of
    // how the operator invoked assay.
    let tree_path_owned = match std::path::absolute(tree_path) {
        Ok(p) => p,
        Err(_) => tree_path.to_path_buf(),
    };
    let tree_path = tree_path_owned.as_path();
    let mut patterns: BTreeSet<String> = BTreeSet::new();
    let root_pkg = tree_path.join("package.json");
    if let Ok(text) = std::fs::read_to_string(&root_pkg)
        && let Ok(root_value) = serde_json::from_str::<serde_json::Value>(&text)
        && let Some(ws) = root_value.get("workspaces")
    {
        let entries: Vec<String> = if let Some(arr) = ws.as_array() {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        } else if let Some(obj) = ws.as_object() {
            obj.get("packages")
                .and_then(|p| p.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        patterns.extend(entries);
    }
    let pnpm_ws = tree_path.join("pnpm-workspace.yaml");
    if let Ok(text) = std::fs::read_to_string(&pnpm_ws)
        && let Ok(value) = serde_yml::from_str::<serde_yml::Value>(&text)
        && let Some(packages) = value.get("packages").and_then(|p| p.as_sequence())
    {
        for entry in packages {
            if let Some(s) = entry.as_str() {
                patterns.insert(s.to_string());
            }
        }
    }

    // Split positive patterns from negation patterns. pnpm honors
    // `!packages/private` as an exclusion against the resolved member
    // set. Negations apply AFTER positive expansion; subtraction matches
    // by exact path or glob.
    let (positive_patterns, negation_patterns): (Vec<&String>, Vec<&String>) =
        patterns.iter().partition(|p| !p.starts_with('!'));
    let mut resolved_dirs: BTreeSet<PathBuf> = BTreeSet::new();
    for pattern in &positive_patterns {
        if pattern.contains('*') || pattern.contains('?') || pattern.contains('[') {
            let absolute_pattern = tree_path.join(pattern);
            let pattern_str = match absolute_pattern.to_str() {
                Some(s) => s,
                None => continue,
            };
            // The `glob` crate's pattern parser interprets `\` as an
            // escape character on every platform, so Windows-style
            // backslash separators (`C:\repo\packages\*`) produce zero
            // matches. Normalize to forward slashes — `Path::strip_prefix`
            // still works on the matched results because Rust's std
            // accepts both separators on Windows.
            let normalized = pattern_str.replace('\\', "/");
            if let Ok(walker) = glob::glob(&normalized) {
                for entry in walker.flatten() {
                    if entry.is_dir()
                        && entry.join("package.json").is_file()
                        && let Ok(rel) = entry.strip_prefix(tree_path)
                    {
                        resolved_dirs.insert(rel.to_path_buf());
                    }
                }
            }
        } else {
            let candidate = tree_path.join(pattern);
            if candidate.is_dir() && candidate.join("package.json").is_file() {
                resolved_dirs.insert(PathBuf::from(pattern.as_str()));
            }
        }
    }

    // Apply negation: drop any resolved dir that matches a `!<pattern>`
    // entry (literal path or glob). pnpm's spec says negations win
    // regardless of declaration order.
    for negation in &negation_patterns {
        let pattern_body = &negation[1..]; // strip the leading `!`
        if pattern_body.contains('*') || pattern_body.contains('?') || pattern_body.contains('[') {
            let absolute_pattern = tree_path.join(pattern_body);
            let Some(pattern_str) = absolute_pattern.to_str() else {
                continue;
            };
            let normalized = pattern_str.replace('\\', "/");
            if let Ok(walker) = glob::glob(&normalized) {
                for entry in walker.flatten() {
                    if let Ok(rel) = entry.strip_prefix(tree_path) {
                        resolved_dirs.remove(rel);
                    }
                }
            }
        } else {
            resolved_dirs.remove(Path::new(pattern_body));
        }
    }

    let mut out: Vec<WorkspaceMember> = Vec::new();
    for rel in resolved_dirs {
        let pkg_path = tree_path.join(&rel).join("package.json");
        let Ok(text) = std::fs::read_to_string(&pkg_path) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        let Some(name) = value.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        out.push(WorkspaceMember {
            relative_path: rel,
            name: name.to_string(),
        });
    }
    out.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    Ok(out)
}

/// Return the workspace members that declare `proposal.subject` as a
/// direct dependency.
///
/// Mirrors cargo's `affected_consumers` semantics: a member is a
/// "consumer" if its `package.json`'s `dependencies` /
/// `devDependencies` / `peerDependencies` / `optionalDependencies`
/// lists the bumped package. Self-references are excluded (a member
/// whose own `name` matches `proposal.subject` is the bumped package,
/// not a consumer).
///
/// Returns an empty Vec when no workspace declaration exists or no
/// member declares the dep — the Reporter collapses to a flat single-
/// project view in that case.
pub(super) fn resolve_npm_consumers(proposal: &Proposal, tree: &Path) -> Result<Vec<ConsumerId>> {
    let mut consumers: Vec<ConsumerId> = Vec::new();
    for member in detect_workspace_members(tree)? {
        if member.name == proposal.subject {
            continue;
        }
        let pkg_path = tree.join(&member.relative_path).join("package.json");
        if package_json_declares(&pkg_path, &proposal.subject)? {
            consumers.push(member.name.clone());
        }
    }
    // Augment with peer-dep declarers from node_modules. For a
    // library that declares `peerDependencies: { "@angular/core":
    // ">=21" }`, an `@angular/core` bump may shift the minimum peer
    // range — that's the "blast radius" data the operator needs.
    // The dogfood (slate, aegis, wildmason.dev) flagged this as the
    // biggest npm `affected_consumers` gap. Failures are silent
    // (best-effort) — proposers don't crash because node_modules
    // happens to be partially installed.
    for peer in find_peer_dep_consumers(tree, &proposal.subject) {
        if peer == proposal.subject {
            continue;
        }
        if !consumers.iter().any(|c| c == &peer) {
            consumers.push(peer);
        }
    }
    consumers.sort();
    Ok(consumers)
}
