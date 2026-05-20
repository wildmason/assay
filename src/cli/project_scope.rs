//! Resolved scope for one `analyze` invocation.
//!
//! [`ProjectScope`] is the data carrier; [`ProjectScope::resolve`] is
//! the decision rule that turns `--project` / `--repo` + the
//! `.assay.toml` `[project]` section into `(artifact_root, scan_roots,
//! ecosystem_restriction)`. Polyglot auto-detection
//! ([`super::polyglot`]) plugs in here for the both `--project`-as-
//! directory case and the no-`--project` default.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

use super::args::{AnalyzeArgs, EcosystemSelector};
use super::paths::{anchor_artifact_root_at_git_root, same_path};
use super::polyglot::augment_with_polyglot_subdirs;

/// Resolved scope for one `analyze` invocation. Carries the artifact
/// root (where `.assay/` lives + where git operations anchor) plus the
/// list of scan roots (directories where ecosystems detect manifests).
///
/// **Single-root case** (no `--project`, no `[project] roots` in config):
/// `artifact_root` = `scan_roots[0]` = `args.repo`. Single element.
///
/// **`--project <path>`**: `artifact_root` and the sole scan root are
/// derived from the path. May restrict to one ecosystem when path is
/// a manifest file. Config `[project] roots` is ignored in this mode —
/// `--project` is the explicit "single sub-project" entry point.
///
/// **`[project] roots = [...]` in `.assay.toml`** (polyglot Tauri / mixed
/// repos): `artifact_root` = `args.repo`; `scan_roots` = `args.repo`
/// plus each config-declared root (deduplicated). The repo root stays
/// in scan_roots so root-level manifests (`.github/workflows/`) are
/// still discovered.
#[derive(Debug, Clone)]
pub(super) struct ProjectScope {
    /// Where `.assay/` is written and where git operations anchor.
    pub(super) artifact_root: PathBuf,
    /// Every directory to scan for ecosystem manifests. Always
    /// non-empty.
    pub(super) scan_roots: Vec<PathBuf>,
    pub(super) ecosystem_restriction: Option<EcosystemSelector>,
}

impl ProjectScope {
    pub(super) fn resolve(args: &AnalyzeArgs, config: &crate::config::AssayConfig) -> Result<Self> {
        if let Some(path) = args.project.as_deref() {
            if !path.exists() {
                return Err(Error::other(format!(
                    "--project path `{}` does not exist",
                    path.display()
                )));
            }
            if path.is_dir() {
                let (artifact_root, scan_root) = anchor_artifact_root_at_git_root(path);
                let mut scan_roots: Vec<PathBuf> = vec![scan_root.clone()];
                // Polyglot auto-detect ALSO applies when --project points
                // at a directory — without this, `assay analyze --project
                // mortar` (Tauri: src-tauri/ + ui/) misses every Cargo
                // and npm manifest because the root has neither at top
                // level. Pre-fix dogfood: 49/52 actionable proposals
                // (94%) silently dropped on mortar. Per-ecosystem gate
                // honored so a single-cargo / single-npm repo doesn't
                // also probe for subdirs (a root workspace covers its
                // members already).
                augment_with_polyglot_subdirs(&mut scan_roots, &scan_root, config);
                return Ok(ProjectScope {
                    artifact_root,
                    scan_roots,
                    ecosystem_restriction: None,
                });
            }
            let (eco, scan_root_initial) =
                infer_project_scope_from_manifest(path).ok_or_else(|| {
                    Error::other(format!(
                        "--project file `{}` is not a recognized manifest. \
                         Supported: Cargo.toml (cargo), .github/workflows/*.yml \
                         (github-actions).",
                        path.display()
                    ))
                })?;
            let (artifact_root, scan_root) = anchor_artifact_root_at_git_root(&scan_root_initial);
            return Ok(ProjectScope {
                artifact_root,
                scan_roots: vec![scan_root],
                ecosystem_restriction: Some(eco),
            });
        }
        // No --project: artifact root = --repo. scan_roots = repo + any
        // config-declared roots (resolved relative to repo). Repo root
        // is ALWAYS scanned so root-level manifests like
        // `.github/workflows/` aren't missed when the config lists
        // subdirectory roots.
        let artifact_root = args.repo.clone();
        let mut scan_roots: Vec<PathBuf> = vec![artifact_root.clone()];
        for cfg_root in &config.project.roots {
            let resolved = if cfg_root.is_absolute() {
                cfg_root.clone()
            } else {
                artifact_root.join(cfg_root)
            };
            if !scan_roots.iter().any(|p| same_path(p, &resolved)) {
                scan_roots.push(resolved);
            }
        }
        augment_with_polyglot_subdirs(&mut scan_roots, &artifact_root, config);
        Ok(ProjectScope {
            artifact_root,
            scan_roots,
            ecosystem_restriction: None,
        })
    }
}

/// Capture the reproducibility context (argv + tool version + host
/// OS/arch) at the top of every analyze run. Falls into the
/// receipt's `run_context` field so a downstream CI consumer can
/// scan one place for "what version on what machine". The dogfood
/// (ci-forge agent) flagged the absence of this top-level block as
/// the main missing piece for reproducibility audits.
pub(super) fn capture_run_context() -> crate::model::RunContext {
    let cli_args: Vec<String> = std::env::args().collect();
    let mut host = std::collections::BTreeMap::new();
    host.insert("os".to_string(), std::env::consts::OS.to_string());
    host.insert("arch".to_string(), std::env::consts::ARCH.to_string());
    crate::model::RunContext {
        cli_args,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        host,
    }
}

/// Decode `--project <path>` when the path points at a manifest file
/// rather than a directory. Returns the inferred ecosystem (so we can
/// restrict the run to that one) plus the directory to use as the
/// scan root.
pub(super) fn infer_project_scope_from_manifest(
    path: &Path,
) -> Option<(EcosystemSelector, PathBuf)> {
    let filename = path.file_name()?.to_str()?;
    if filename.eq_ignore_ascii_case("Cargo.toml") {
        let parent = path.parent()?.to_path_buf();
        return Some((EcosystemSelector::Cargo, parent));
    }
    if filename.eq_ignore_ascii_case("package.json") {
        let parent = path.parent()?.to_path_buf();
        return Some((EcosystemSelector::Npm, parent));
    }
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if matches!(ext.as_str(), "yml" | "yaml") {
        // Walk parents to find `.github` then take its parent as repo root.
        let mut cursor = path.parent();
        while let Some(dir) = cursor {
            if dir
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.eq_ignore_ascii_case(".github"))
            {
                return Some((
                    EcosystemSelector::GithubActions,
                    dir.parent()?.to_path_buf(),
                ));
            }
            cursor = dir.parent();
        }
    }
    None
}
