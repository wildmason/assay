//! Direct-dep discovery from `package.json` (root + workspace members).
//!
//! Used by the proposer to drop transitive entries (`npm outdated`
//! surfaces them, but the applier can't widen what isn't declared) and
//! by the berry proposer to know each dep's existing constraint string.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::error::{Error, Result};

use super::workspaces::detect_workspace_members;

/// Read every dep name declared in `package.json`'s `dependencies`,
/// `devDependencies`, `peerDependencies`, and `optionalDependencies`.
/// Workspace members are walked via
/// [`super::workspaces::detect_workspace_members`] so npm 7+ workspace
/// globs (`packages/*`) and pnpm-workspace.yaml entries are all expanded
/// before scanning for declared deps.
pub(crate) fn collect_direct_dep_names(repo: &Path) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    let root_pkg = repo.join("package.json");
    if root_pkg.is_file() {
        let root_text = std::fs::read_to_string(&root_pkg).map_err(|source| Error::Io {
            path: root_pkg.clone(),
            source,
        })?;
        let root_value: serde_json::Value = serde_json::from_str(&root_text)
            .map_err(|e| Error::other(format!("package.json parse: {e}")))?;
        extend_dep_names(&root_value, &mut names);
    }
    for member in detect_workspace_members(repo)? {
        let member_pkg = repo.join(&member.relative_path).join("package.json");
        if !member_pkg.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&member_pkg).map_err(|source| Error::Io {
            path: member_pkg.clone(),
            source,
        })?;
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
            extend_dep_names(&value, &mut names);
        }
    }
    Ok(names)
}

fn extend_dep_names(pkg: &serde_json::Value, names: &mut BTreeSet<String>) {
    for field in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        if let Some(obj) = pkg.get(field).and_then(|v| v.as_object()) {
            for key in obj.keys() {
                names.insert(key.clone());
            }
        }
    }
}

/// Like [`collect_direct_dep_names`], but pairs each name with its
/// declared constraint string from package.json. Used by the berry
/// proposer to know what range each direct dep is pinned to so the
/// applier can preserve operator-chosen prefixes. Workspace-member
/// deps merge into the result; later-walked members override earlier
/// ones on key collision (rare in practice — a workspace shouldn't
/// declare the same dep at two different constraints across members).
pub(crate) fn collect_direct_deps_with_constraints(
    repo: &Path,
) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let root_pkg = repo.join("package.json");
    if root_pkg.is_file() {
        let text = std::fs::read_to_string(&root_pkg).map_err(|source| Error::Io {
            path: root_pkg.clone(),
            source,
        })?;
        let value: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| Error::other(format!("package.json parse: {e}")))?;
        extend_dep_constraints(&value, &mut out);
    }
    for member in detect_workspace_members(repo)? {
        let member_pkg = repo.join(&member.relative_path).join("package.json");
        if !member_pkg.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&member_pkg).map_err(|source| Error::Io {
            path: member_pkg.clone(),
            source,
        })?;
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
            extend_dep_constraints(&value, &mut out);
        }
    }
    Ok(out)
}

fn extend_dep_constraints(pkg: &serde_json::Value, out: &mut BTreeMap<String, String>) {
    for field in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        if let Some(obj) = pkg.get(field).and_then(|v| v.as_object()) {
            for (key, value) in obj {
                if let Some(s) = value.as_str() {
                    out.insert(key.clone(), s.to_string());
                }
            }
        }
    }
}
