//! Polyglot scan-root auto-detection for monorepo and Tauri layouts.
//!
//! When the operator hasn't declared `[project] roots = [...]` in
//! `.assay.toml`, we probe a small fixed set of conventional sub-
//! project locations (Tauri `src-tauri/`, Vite frontend `ui/`/`app/`,
//! pnpm-style `apps/<name>/` and `packages/<name>/`) and surface each
//! discovered scan root so subsequent ecosystem dispatch finds the
//! manifests that live under them.
//!
//! No new scan roots are introduced when the repo root already
//! carries the relevant ecosystem's manifest — a root Cargo workspace
//! already enumerates its members, a root `package.json` already
//! enumerates its workspaces, and double-listing would produce
//! duplicate proposals.

use std::path::{Path, PathBuf};

use super::paths::{same_path, strip_extended_length_prefix};

/// Append polyglot subdirectories (Tauri-style `src-tauri/`/`ui/`,
/// monorepo-style `apps/<name>/`/`packages/<name>/`) to `scan_roots`
/// when the repo root doesn't carry the relevant ecosystem's manifest
/// at top level. No-op when the user supplied `[project] roots = [...]`
/// in `.assay.toml` (explicit config wins). Each addition emits a
/// stderr breadcrumb so the operator can see what was auto-detected.
pub(super) fn augment_with_polyglot_subdirs(
    scan_roots: &mut Vec<PathBuf>,
    repo_root: &Path,
    config: &crate::config::AssayConfig,
) {
    if !config.project.roots.is_empty() {
        return;
    }
    for extra in detect_polyglot_subdirs(repo_root) {
        if !scan_roots.iter().any(|p| same_path(p, &extra)) {
            // Strip the `\\?\` extended-length prefix that may show
            // up after canonicalize on Windows. The path is correct
            // either way, but the prefix is noise in user-facing
            // breadcrumbs.
            let display = strip_extended_length_prefix(extra.clone());
            eprintln!(
                "[project] auto-detected polyglot scan root: `{}` \
                 (set [project] roots = [...] in .assay.toml to silence)",
                display.display()
            );
            scan_roots.push(extra);
        }
    }
}

/// Probe `repo_root` for sub-projects in conventional Tauri /
/// monorepo locations. Returns each subdirectory that carries a v1
/// ecosystem manifest the root does NOT already cover.
///
/// Per-ecosystem gating: a cargo workspace at root already enumerates
/// its members, so cargo subdirs are skipped. An npm root package.json
/// already enumerates its workspaces, so npm subdirs are skipped.
/// This prevents double-counting workspace members while still
/// catching Tauri layouts (`src-tauri/` Cargo + `ui/` npm with no
/// root manifest) and rust+frontend polyglots (root Cargo workspace
/// + `apps/web/` npm — ci-forge's shape).
///
/// Order is stable across runs.
pub(super) fn detect_polyglot_subdirs(repo_root: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let root_has_cargo = repo_root.join("Cargo.toml").is_file();
    let root_has_npm = repo_root.join("package.json").is_file();

    // src-tauri/ is the canonical Tauri backend directory; the literal
    // name is hard-coded by the Tauri CLI scaffold and shows up in
    // every Wildmason Tauri app (Bridge, Helm, Mortar, Crucible).
    let cargo_candidates = ["src-tauri"];
    // UI subfolder names — the small set of conventional choices
    // across the Tauri / Vue / Next.js + monorepo ecosystem. Order
    // matches encounter likelihood in Wildmason repos.
    let npm_candidates = ["ui", "frontend", "app", "web", "client"];

    if !root_has_cargo {
        for sub in cargo_candidates {
            let p = repo_root.join(sub);
            if p.join("Cargo.toml").is_file() {
                out.push(p);
            }
        }
    }
    if !root_has_npm {
        for sub in npm_candidates {
            let p = repo_root.join(sub);
            if p.join("package.json").is_file() {
                out.push(p);
            }
        }
        // Monorepo nested probe: `apps/<name>/package.json` and
        // `packages/<name>/package.json`. ci-forge's `apps/web/`
        // (rust workspace at root + Vite frontend nested 2 levels
        // deep) is unreachable from the 1-level scan above. Cargo is
        // omitted from this nested probe because a root workspace
        // already covers its members.
        for nest in ["apps", "packages"] {
            let nest_dir = repo_root.join(nest);
            if !nest_dir.is_dir() {
                continue;
            }
            let entries: Vec<_> = match std::fs::read_dir(&nest_dir) {
                Ok(iter) => iter.flatten().collect(),
                Err(_) => continue,
            };
            let mut nested: Vec<PathBuf> = entries
                .into_iter()
                .map(|e| e.path())
                .filter(|p| p.is_dir() && p.join("package.json").is_file())
                .collect();
            nested.sort();
            for p in nested {
                out.push(p);
            }
        }
    }
    out
}
