//! Per-ecosystem manifest-detection breadcrumbs for the text
//! reporter.
//!
//! Smaller than [`super::reporting`]: this surfaces the
//! "[<eco>] manifests detected: N" lines printed during the
//! discovery phase, plus the cargo-specific `Cargo.lock`-missing
//! warning that catches the silent-zero-proposals trap library
//! crates fall into.

use std::path::Path;

use crate::model::{Manifest, ManifestKind};

pub(super) fn report_text(name: &str, scan_root_rel: Option<&Path>, manifests: &[Manifest]) {
    // Suppress (ecosystem, scan_root) pairs with no manifests — they're
    // dominant in multi-root layouts (cargo in `ui`, npm in `src-tauri`,
    // etc.) and add noise without signal.
    if manifests.is_empty() {
        return;
    }
    match scan_root_rel {
        Some(rel) if !rel.as_os_str().is_empty() => {
            println!(
                "[{name}] {}: {} manifest(s)",
                rel.display(),
                manifests.len()
            );
        }
        _ => println!("[{name}] manifests detected: {}", manifests.len()),
    }
    for manifest in manifests {
        println!("  - {}", manifest.path.display());
    }
    if let Some(warning) = missing_cargo_lock_warning(name, manifests) {
        eprintln!("{warning}");
    }
}

/// Build the warning text shown when a Cargo workspace has `Cargo.toml`
/// but no `Cargo.lock`. Returns `None` when no warning is warranted.
///
/// The proposer compares the committed lockfile against the registry to
/// find available bumps — without one it cannot find any, and the run
/// silently reports "0 proposals." That mode of failure misleads the
/// user into thinking nothing needs upgrading; in reality the analyzer
/// just had no anchor to compare against. Library crates routinely
/// don't commit `Cargo.lock`, so this case is common in OSS targets.
pub(super) fn missing_cargo_lock_warning(name: &str, manifests: &[Manifest]) -> Option<String> {
    if name != "cargo" {
        return None;
    }
    let has_toml = manifests
        .iter()
        .any(|m| matches!(m.kind, ManifestKind::CargoToml));
    let has_lock = manifests
        .iter()
        .any(|m| matches!(m.kind, ManifestKind::CargoLock));
    if has_toml && !has_lock {
        Some(
            "[cargo] warning: Cargo.lock not found — assay needs a lockfile to detect upgrades. \
             Run `cargo generate-lockfile` once to materialize one (library crates typically \
             don't commit Cargo.lock; the file you generate stays untracked)."
                .to_string(),
        )
    } else {
        None
    }
}
