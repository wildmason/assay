//! Peer-dependency walker: surfaces every installed package whose
//! `peerDependencies` block references the proposed subject.
//!
//! Four install layouts get the same treatment so the answer is
//! consistent across npm, pnpm, yarn 1, and yarn berry:
//!
//! - **npm / yarn1 flat hoisted:** `node_modules/<pkg>/`
//! - **pnpm virtual store:** `node_modules/.pnpm/<id>/node_modules/<pkg>/`
//! - **yarn berry unplugged:** `.yarn/unplugged/<pkg>-npm-<ver>-<hash>/
//!   node_modules/<pkg>/`
//! - **yarn berry PnP runtime data:** `.pnp.data.json` `packagePeers`
//!   array on each registry entry
//!
//! Every walker is best-effort — IO / JSON errors are swallowed
//! because the consumer list is advisory: an incomplete or in-progress
//! install shouldn't fail the run.

use std::path::Path;

use crate::error::Result;

/// Walk the project's installed-dependency layout looking for
/// declarations of `subject` in any package's `peerDependencies`.
/// Returns the deduplicated list of package names that declare it.
/// Best-effort — IO and parse errors are swallowed since the
/// proposer should still ship results when the install tree is in
/// a half-baked state (`pnpm install` interrupted, `yarn install`
/// without `--immutable`, etc.).
///
/// Handles four layouts side-by-side; each project may use one or
/// more of them:
///
/// - **npm / yarn1 flat hoisted:** `node_modules/foo/package.json`
///   (plus the scoped variant `node_modules/@scope/foo/`).
/// - **pnpm virtual store:** `node_modules/.pnpm/<id>/node_modules/<pkg>/`.
///   pnpm-style monorepos (the dominant flavor in modern Wildmason
///   projects) put the real install under `.pnpm/`; the top-level
///   `node_modules/` is just symlinks to declared deps.
/// - **yarn berry unplugged:** `.yarn/unplugged/<pkg>-npm-<ver>-<hash>/
///   node_modules/<pkg>/package.json`. yarn 2+ ("Berry") in PnP
///   mode doesn't materialize `node_modules/` — packages either
///   stay zipped in `.yarn/cache/` (zero-installs) or get
///   "unplugged" into the directory tree. Unplugged hits the
///   subset that needs install scripts or has been explicitly
///   marked; the layout matches pnpm's enough to reuse the same
///   walker.
/// - **yarn berry PnP runtime data:** `.pnp.data.json`. Parsed
///   when present so we catch every registered package — not just
///   the unplugged subset. The `packagePeers` field on each
///   registry entry is yarn's authoritative list of peer-dep
///   subjects, so a direct check there beats walking zips.
///
/// Names are deduplicated globally: the same library can appear at
/// multiple versions or under multiple peer-resolution suffixes
/// and should still be reported once.
pub(super) fn find_peer_dep_consumers(tree: &Path, subject: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let node_modules = tree.join("node_modules");
    if node_modules.is_dir() {
        walk_flat_node_modules(&node_modules, subject, &mut out);
        let pnpm_store = node_modules.join(".pnpm");
        if pnpm_store.is_dir() {
            walk_pnpm_virtual_store(&pnpm_store, subject, &mut out);
        }
    }
    let yarn_unplugged = tree.join(".yarn").join("unplugged");
    if yarn_unplugged.is_dir() {
        walk_yarn_berry_unplugged(&yarn_unplugged, subject, &mut out);
    }
    let pnp_data = tree.join(".pnp.data.json");
    if pnp_data.is_file() {
        walk_yarn_berry_pnp_data(&pnp_data, subject, &mut out);
    }
    out.sort();
    out.dedup();
    out
}

/// Walk a flat `node_modules`-style directory looking for
/// `peerDependencies[subject]` declarations. Handles both unscoped
/// (`<root>/foo/`) and scoped (`<root>/@scope/foo/`) entries. Skips
/// dotted entries like `.bin`, `.cache`, and `.pnpm` (the virtual
/// store has its own walker). Pushes matches into `out` without
/// deduplication; the caller is responsible for sort+dedup.
fn walk_flat_node_modules(root: &Path, subject: &str, out: &mut Vec<String>) {
    let entries = match std::fs::read_dir(root) {
        Ok(iter) => iter,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = match entry.file_name().into_string() {
            Ok(s) => s,
            Err(_) => continue,
        };
        if name.starts_with('.') {
            continue;
        }
        if name.starts_with('@') {
            let scope_entries = match std::fs::read_dir(&path) {
                Ok(iter) => iter,
                Err(_) => continue,
            };
            for sub in scope_entries.flatten() {
                let sub_name = match sub.file_name().into_string() {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let full = format!("{name}/{sub_name}");
                check_peer_dep(&sub.path(), subject, &full, out);
            }
        } else {
            check_peer_dep(&path, subject, &name, out);
        }
    }
}

/// Walk pnpm's virtual store. Each entry under `.pnpm/` is named
/// `<pkg>@<ver>(_<peer-resolution>)?` (with scoped slashes escaped
/// to `+`) and contains a `node_modules/` directory holding the
/// hoisted install plus any peer-linked siblings. We delegate each
/// `<entry>/node_modules/` to [`walk_flat_node_modules`] — the
/// layout inside is structurally identical to a flat hoisted tree.
/// Best-effort on errors; partial pnpm installs do not crash the
/// proposer.
fn walk_pnpm_virtual_store(store: &Path, subject: &str, out: &mut Vec<String>) {
    let entries = match std::fs::read_dir(store) {
        Ok(iter) => iter,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let inner_nm = path.join("node_modules");
        if !inner_nm.is_dir() {
            continue;
        }
        walk_flat_node_modules(&inner_nm, subject, out);
    }
}

/// Walk yarn berry's unplugged directory. Each entry is named
/// `<pkg>-npm-<ver>-<hash>` (yarn's hash-stamped pkg dirname) and
/// contains `node_modules/<pkg>/package.json` — the same shape as
/// the pnpm virtual store, so we reuse [`walk_flat_node_modules`]
/// on the inner `node_modules/`. Best-effort on errors.
///
/// Note: `.yarn/unplugged/` only contains the SUBSET of packages
/// yarn has unzipped — packages with install scripts, native
/// bindings, or those explicitly marked `unplugged: true` in
/// `.yarnrc.yml`. For full coverage we also parse `.pnp.data.json`
/// when available (see [`walk_yarn_berry_pnp_data`]).
fn walk_yarn_berry_unplugged(unplugged: &Path, subject: &str, out: &mut Vec<String>) {
    let entries = match std::fs::read_dir(unplugged) {
        Ok(iter) => iter,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let inner_nm = path.join("node_modules");
        if !inner_nm.is_dir() {
            continue;
        }
        walk_flat_node_modules(&inner_nm, subject, out);
    }
}

/// Parse `.pnp.data.json` and find every registered package whose
/// `packagePeers` array contains `subject`. yarn berry writes this
/// file in PnP mode (default for yarn 3+) as a JSON-encoded
/// snapshot of the package registry. The relevant shape:
///
/// ```json
/// {
///   "packageRegistryData": [
///     ["@scope/pkg", [
///       ["npm:1.0.0", {
///         "packagePeers": ["@angular/core", "@angular/common"],
///         "packageDependencies": [...],
///         ...
///       }]
///     ]],
///     ...
///   ]
/// }
/// ```
///
/// The outer pair is `[name, [[version_locator, info], ...]]`.
/// `null` appears as the name slot for the top-level project
/// (workspace root) and is skipped. `packagePeers` is yarn's
/// authoritative list of peer-dep subjects for that resolution —
/// independent of whether the package is unplugged or still
/// zipped in `.yarn/cache/`.
///
/// Best-effort: a missing, unreadable, or malformed file
/// contributes no entries.
fn walk_yarn_berry_pnp_data(pnp_data: &Path, subject: &str, out: &mut Vec<String>) {
    let text = match std::fs::read_to_string(pnp_data) {
        Ok(t) => t,
        Err(_) => return,
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return;
    };
    let Some(registry) = value.get("packageRegistryData").and_then(|v| v.as_array()) else {
        return;
    };
    for entry in registry {
        let Some(pair) = entry.as_array() else {
            continue;
        };
        if pair.len() != 2 {
            continue;
        }
        // pair[0] is the package name (or null for the top-level
        // workspace). pair[1] is an array of [version_locator, info]
        // pairs — one per resolved version of this package.
        let Some(name) = pair[0].as_str() else {
            continue;
        };
        if name == subject {
            // The package itself is not a peer-dep consumer of
            // itself.
            continue;
        }
        let Some(versions) = pair[1].as_array() else {
            continue;
        };
        let mut declares_peer = false;
        for version_entry in versions {
            let Some(ve) = version_entry.as_array() else {
                continue;
            };
            if ve.len() != 2 {
                continue;
            }
            let Some(info) = ve[1].as_object() else {
                continue;
            };
            let Some(peers) = info.get("packagePeers").and_then(|v| v.as_array()) else {
                continue;
            };
            if peers.iter().any(|p| p.as_str() == Some(subject)) {
                declares_peer = true;
                break;
            }
        }
        if declares_peer {
            out.push(name.to_string());
        }
    }
}

/// Parse `<pkg_dir>/package.json` and append `pkg_name` to `out` if
/// the manifest declares `subject` in its `peerDependencies` block.
/// Silent on any IO / parse failure — peer-dep population is
/// advisory.
fn check_peer_dep(pkg_dir: &Path, subject: &str, pkg_name: &str, out: &mut Vec<String>) {
    let pkg_json = pkg_dir.join("package.json");
    let text = match std::fs::read_to_string(&pkg_json) {
        Ok(t) => t,
        Err(_) => return,
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return;
    };
    if let Some(obj) = value.get("peerDependencies").and_then(|v| v.as_object())
        && obj.contains_key(subject)
    {
        out.push(pkg_name.to_string());
    }
}

/// `true` when `pkg_path`'s manifest lists `name` under any of the
/// dependency-flavored fields. Used by the consumer resolver to
/// confirm an upstream `package.json` actually declares the
/// proposed subject before adding it to the affected list.
pub(super) fn package_json_declares(pkg_path: &Path, name: &str) -> Result<bool> {
    let text = match std::fs::read_to_string(pkg_path) {
        Ok(t) => t,
        Err(_) => return Ok(false),
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Ok(false);
    };
    for field in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        if let Some(obj) = value.get(field).and_then(|v| v.as_object())
            && obj.contains_key(name)
        {
            return Ok(true);
        }
    }
    Ok(false)
}
