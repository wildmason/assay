//! External path-dependency detection and sandbox materialization.
//!
//! Cargo supports `path = "../foo"` style deps where the dep tree lives
//! outside the manifest's own repo (e.g. helm's
//! `wildmason-license = { path = "../../licensing/crate" }`). On the
//! host these resolve against the manifest's directory and the operator's
//! sibling-of-parent layout. Inside an assay isolation worktree, the
//! sibling layout doesn't exist — the worktree contains only the host
//! repo's tree — so cargo fails to resolve the dep and the applier blows
//! up at `cargo update --workspace`.
//!
//! This module:
//!
//! 1. Scans every `Cargo.toml` in the host workspace for path-shaped
//!    deps (in normal deps, dev-deps, build-deps, target-specific
//!    deps, and `[workspace.dependencies]`).
//! 2. Classifies each as in-tree (resolved location is under the host
//!    git top-level) or out-of-tree.
//! 3. For each out-of-tree dep, computes the path *inside the sandbox*
//!    where cargo would expect to find that source given the sandbox's
//!    mirror of the host directory structure.
//! 4. Recursively copies the host source to the computed sandbox
//!    location, skipping `target/` and `.git/`.
//!
//! Refuses to materialize when the computed destination would escape
//! the assay-managed boundary (i.e. land outside `.assay/`); this
//! prevents pathological `../../../../` chains from polluting the host.

use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};

/// One external path dependency declared in a host manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalPathDep {
    /// Dep table key (e.g. "wildmason-license").
    pub name: String,
    /// Manifest the dep was declared in (absolute, host-side).
    pub manifest_path: PathBuf,
    /// The literal path value as written ("../../licensing/crate").
    pub literal_path: String,
    /// Resolved absolute source location on the host (logical, not
    /// canonicalized — symlinks left alone).
    pub source_abs: PathBuf,
}

/// Outcome of materializing one external path dep into a sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedDep {
    pub dep: ExternalPathDep,
    /// Where the source tree was copied to.
    pub destination_abs: PathBuf,
}

/// Scan one manifest file for path-shaped deps that resolve outside
/// `repo_root`.
///
/// `manifest_path` must be absolute. `repo_root` is the boundary used
/// for the in-tree/out-of-tree classification (typically the host's
/// `git rev-parse --show-toplevel`).
pub fn scan_manifest_for_external_path_deps(
    manifest_path: &Path,
    repo_root: &Path,
) -> Result<Vec<ExternalPathDep>> {
    let bytes = std::fs::read(manifest_path).map_err(|source| Error::Io {
        path: manifest_path.to_path_buf(),
        source,
    })?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Error::InvalidManifest {
        path: manifest_path.to_path_buf(),
        message: "manifest is not valid UTF-8".into(),
    })?;
    let doc: toml::Value = toml::from_str(text).map_err(|e| Error::InvalidManifest {
        path: manifest_path.to_path_buf(),
        message: format!("toml parse failed: {e}"),
    })?;
    let manifest_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let repo_root_norm = logical_normalize(repo_root);

    let mut out: Vec<ExternalPathDep> = Vec::new();
    visit_all_dep_tables(&doc, &mut |name, value| {
        if let Some(literal) = extract_path_value(value)
            && !literal.is_empty()
        {
            let resolved = logical_normalize(&manifest_dir.join(&literal));
            if !resolved.starts_with(&repo_root_norm) {
                out.push(ExternalPathDep {
                    name: name.to_string(),
                    manifest_path: manifest_path.to_path_buf(),
                    literal_path: literal,
                    source_abs: resolved,
                });
            }
        }
    });
    Ok(out)
}

/// Convenience: discover external path deps from the operator's
/// `--repo` argument and materialize them into the sandbox in one call.
///
/// Used by both `cli::prepare_apply_local_tree` and
/// `apply_merger::prepare_isolated_worktree`. Returns Ok(empty) if the
/// repo declares no external path deps (the common case for projects
/// that follow the canonical git-rev dep pattern).
///
/// `sandbox_worktree_root` is the absolute path of the `git worktree add`
/// target (the worktree top, NOT a sub-directory of it). `boundary` is
/// the run-scoped directory the materialization must not escape —
/// typically `<operator_repo>/.assay/runs/<run-id>/`.
pub fn materialize_external_deps_into_sandbox(
    operator_repo: &Path,
    sandbox_worktree_root: &Path,
    boundary: &Path,
) -> Result<Vec<MaterializedDep>> {
    let deps = discover_repo_external_path_deps(operator_repo)?;
    if deps.is_empty() {
        return Ok(Vec::new());
    }
    // Canonicalize so containment checks are stable even when the
    // operator passed a relative `--repo` arg like `.`.
    let operator_repo_abs =
        std::path::absolute(operator_repo).unwrap_or_else(|_| operator_repo.to_path_buf());
    let host_repo_root = git_top_level_or(&operator_repo_abs).unwrap_or(operator_repo_abs);
    let sandbox_abs = std::path::absolute(sandbox_worktree_root)
        .unwrap_or_else(|_| sandbox_worktree_root.to_path_buf());
    let boundary_abs = std::path::absolute(boundary).unwrap_or_else(|_| boundary.to_path_buf());
    materialize_for_sandbox(&deps, &host_repo_root, &sandbox_abs, &boundary_abs)
}

/// Discover every external path dep across the workspace rooted at
/// `repo` (which may point at a sub-directory of a git repo).
///
/// Walks workspace members via `cargo metadata --no-deps` and dedupes
/// by `(manifest_path, name)`. Returns Ok(empty) if no Cargo.toml lives
/// at `repo` (the operator is targeting a non-cargo project).
pub fn discover_repo_external_path_deps(repo: &Path) -> Result<Vec<ExternalPathDep>> {
    let manifest_at_root = repo.join("Cargo.toml");
    if !manifest_at_root.is_file() {
        return Ok(Vec::new());
    }
    // Canonicalize so downstream manifest paths are absolute — without
    // this, `--repo .` produces relative manifest paths that fail the
    // strip_prefix step in materialize_for_sandbox.
    let repo_abs = std::path::absolute(repo).unwrap_or_else(|_| repo.to_path_buf());
    let manifests = crate::ecosystem::cargo_manifest_editor::list_workspace_manifests(&repo_abs)?;
    let repo_root = git_top_level_or(&repo_abs).unwrap_or_else(|| repo_abs.clone());
    let mut out: Vec<ExternalPathDep> = Vec::new();
    for manifest in manifests {
        let manifest_abs = std::path::absolute(&manifest).unwrap_or(manifest.clone());
        let found = scan_manifest_for_external_path_deps(&manifest_abs, &repo_root)?;
        for dep in found {
            if !out.iter().any(|e| {
                e.manifest_path == dep.manifest_path
                    && e.name == dep.name
                    && e.literal_path == dep.literal_path
            }) {
                out.push(dep);
            }
        }
    }
    Ok(out)
}

/// Materialize `deps` into the sandbox so cargo's path resolution from
/// inside the worktree lands on real directories.
///
/// - `host_repo_root` is the absolute path of the host git top-level
///   (where `deps` were discovered from).
/// - `sandbox_worktree_root` is the absolute path of the sandbox's
///   git-top-level mirror (e.g. the `git worktree add` target).
/// - `boundary` is the absolute path the materialization must not
///   escape (typically `<sandbox_worktree_root>.parent()` joined back
///   to the run's `.assay/runs/<run-id>/`).
///
/// Returns one `MaterializedDep` per `dep`, recording where the source
/// was copied. Idempotent: a destination that already exists is left
/// alone.
pub fn materialize_for_sandbox(
    deps: &[ExternalPathDep],
    host_repo_root: &Path,
    sandbox_worktree_root: &Path,
    boundary: &Path,
) -> Result<Vec<MaterializedDep>> {
    let host_root_norm = logical_normalize(host_repo_root);
    let boundary_norm = logical_normalize(boundary);

    let mut out: Vec<MaterializedDep> = Vec::new();
    for dep in deps {
        // Compute the destination by mirroring the manifest's host
        // location into the sandbox and resolving the literal path from
        // there — same arithmetic cargo will perform inside the
        // worktree.
        let manifest_dir = dep.manifest_path.parent().ok_or_else(|| {
            Error::other(format!(
                "external dep `{}` has no parent on manifest path `{}`",
                dep.name,
                dep.manifest_path.display(),
            ))
        })?;
        let manifest_dir_norm = logical_normalize(manifest_dir);
        let rel_manifest_dir = manifest_dir_norm
            .strip_prefix(&host_root_norm)
            .map_err(|_| {
                Error::other(format!(
                    "external dep `{}` declared in `{}` which is outside the host repo root `{}`",
                    dep.name,
                    manifest_dir.display(),
                    host_repo_root.display(),
                ))
            })?;
        let sandbox_manifest_dir = sandbox_worktree_root.join(rel_manifest_dir);
        let destination = logical_normalize(&sandbox_manifest_dir.join(&dep.literal_path));

        if !destination.starts_with(&boundary_norm) {
            return Err(Error::other(format!(
                "external path dep `{}` (from `{}`) would materialize at `{}`, which escapes \
                 the assay sandbox boundary `{}`. Either convert it to a git-rev dep \
                 (see mortar/src-tauri/Cargo.toml for the canonical pattern) or file a \
                 feature request for deeper nesting support.",
                dep.name,
                dep.manifest_path.display(),
                destination.display(),
                boundary.display(),
            )));
        }

        if destination.exists() {
            out.push(MaterializedDep {
                dep: dep.clone(),
                destination_abs: destination,
            });
            continue;
        }

        copy_dir_recursive(&dep.source_abs, &destination, &["target", ".git"])?;

        out.push(MaterializedDep {
            dep: dep.clone(),
            destination_abs: destination,
        });
    }
    Ok(out)
}

// ----- helpers ------------------------------------------------------------

fn extract_path_value(value: &toml::Value) -> Option<String> {
    // Path-shaped deps are always a table (inline or full) — a bare
    // string value is a version constraint, not a path.
    let table = value.as_table()?;
    let path = table.get("path")?.as_str()?;
    Some(path.to_string())
}

/// Walk every dep-table-like region of a `Cargo.toml` and invoke
/// `visitor(name, value)` for each `name = <value>` entry.
///
/// Covers:
/// - `[dependencies]`
/// - `[dev-dependencies]`
/// - `[build-dependencies]`
/// - `[target.<TRIPLE_OR_CFG>.dependencies]` and its dev / build siblings
/// - `[workspace.dependencies]`
fn visit_all_dep_tables<'a, F>(doc: &'a toml::Value, visitor: &mut F)
where
    F: FnMut(&'a str, &'a toml::Value),
{
    let root = match doc.as_table() {
        Some(t) => t,
        None => return,
    };
    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(table) = root.get(key).and_then(|v| v.as_table()) {
            for (k, v) in table {
                visitor(k.as_str(), v);
            }
        }
    }
    if let Some(targets) = root.get("target").and_then(|v| v.as_table()) {
        for (_triple, triple_value) in targets {
            let Some(triple_table) = triple_value.as_table() else {
                continue;
            };
            for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
                if let Some(table) = triple_table.get(key).and_then(|v| v.as_table()) {
                    for (k, v) in table {
                        visitor(k.as_str(), v);
                    }
                }
            }
        }
    }
    if let Some(workspace) = root.get("workspace").and_then(|v| v.as_table())
        && let Some(table) = workspace.get("dependencies").and_then(|v| v.as_table())
    {
        for (k, v) in table {
            visitor(k.as_str(), v);
        }
    }
}

/// Logical path normalization — collapses `.` and `..` components
/// without touching the filesystem.
///
/// Behavior on Windows is the same as on Unix for our purposes: this
/// is purely lexical. Forward / backslash mixing is left for the
/// filesystem APIs to sort out.
pub(crate) fn logical_normalize(path: &Path) -> PathBuf {
    let mut out: Vec<Component<'_>> = Vec::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                // Pop the last non-prefix/non-root component if any.
                if matches!(out.last(), Some(Component::Normal(_))) {
                    out.pop();
                } else if !matches!(
                    out.last(),
                    Some(Component::RootDir) | Some(Component::Prefix(_))
                ) {
                    out.push(Component::ParentDir);
                }
            }
            other => out.push(other),
        }
    }
    if out.is_empty() {
        return PathBuf::from(".");
    }
    let mut result = PathBuf::new();
    for c in out {
        result.push(c.as_os_str());
    }
    result
}

fn git_top_level_or(path: &Path) -> Option<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Some(PathBuf::from(stdout.trim()))
}

fn copy_dir_recursive(src: &Path, dst: &Path, skip_dirs: &[&str]) -> Result<()> {
    if !src.exists() {
        return Err(Error::other(format!(
            "external path dep source not found at `{}`",
            src.display()
        )));
    }
    if !src.is_dir() {
        return Err(Error::other(format!(
            "external path dep source `{}` exists but is not a directory",
            src.display()
        )));
    }
    std::fs::create_dir_all(dst).map_err(|source| Error::Io {
        path: dst.to_path_buf(),
        source,
    })?;
    for entry in std::fs::read_dir(src).map_err(|source| Error::Io {
        path: src.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| Error::Io {
            path: src.to_path_buf(),
            source,
        })?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let src_child = src.join(&name);
        let dst_child = dst.join(&name);
        let ft = entry.file_type().map_err(|source| Error::Io {
            path: src_child.clone(),
            source,
        })?;
        if ft.is_dir() {
            if skip_dirs.iter().any(|s| *s == name_str) {
                continue;
            }
            copy_dir_recursive(&src_child, &dst_child, skip_dirs)?;
        } else if ft.is_file() {
            std::fs::copy(&src_child, &dst_child).map_err(|source| Error::Io {
                path: dst_child.clone(),
                source,
            })?;
        }
        // Skip symlinks and other oddities — they're unusual in cargo
        // source trees and supporting them adds platform-specific
        // complexity not worth the marginal coverage.
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    // ---- logical_normalize ------------------------------------------------

    #[test]
    fn logical_normalize_collapses_parent_dirs() {
        assert_eq!(
            logical_normalize(Path::new("/a/b/../c")),
            PathBuf::from("/a/c")
        );
    }

    #[test]
    fn logical_normalize_collapses_curdir() {
        assert_eq!(
            logical_normalize(Path::new("/a/./b")),
            PathBuf::from("/a/b")
        );
    }

    #[test]
    fn logical_normalize_handles_chains_of_parent_dirs() {
        assert_eq!(
            logical_normalize(Path::new("/a/b/c/../../d")),
            PathBuf::from("/a/d")
        );
    }

    #[test]
    fn logical_normalize_preserves_leading_parent_dirs_on_relative_paths() {
        assert_eq!(
            logical_normalize(Path::new("../foo")),
            PathBuf::from("../foo")
        );
    }

    #[test]
    fn logical_normalize_empty_yields_dot() {
        assert_eq!(logical_normalize(Path::new("")), PathBuf::from("."));
    }

    // ---- scan_manifest_for_external_path_deps -----------------------------

    fn write_manifest(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("Cargo.toml");
        fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn scanner_finds_inline_table_path_dep() {
        let temp = tempdir().unwrap();
        let repo = temp.path();
        let sub = repo.join("crate-a");
        fs::create_dir_all(&sub).unwrap();
        // ../../external/foo from `crate-a/` resolves to `temp.path()/../external/foo`,
        // which is outside the repo.
        let manifest = write_manifest(
            &sub,
            r#"
[package]
name = "crate-a"
version = "0.1.0"

[dependencies]
some-dep = { path = "../../external/foo" }
"#,
        );
        let found = scan_manifest_for_external_path_deps(&manifest, repo).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "some-dep");
        assert_eq!(found[0].literal_path, "../../external/foo");
    }

    #[test]
    fn scanner_classifies_in_tree_path_as_not_external() {
        let temp = tempdir().unwrap();
        let repo = temp.path();
        fs::create_dir_all(repo.join("sibling")).unwrap();
        let manifest = write_manifest(
            repo,
            r#"
[package]
name = "root"
version = "0.1.0"

[dependencies]
sibling = { path = "./sibling" }
"#,
        );
        let found = scan_manifest_for_external_path_deps(&manifest, repo).unwrap();
        assert!(
            found.is_empty(),
            "in-tree path dep must not surface as external: {found:?}"
        );
    }

    #[test]
    fn scanner_walks_dev_and_build_deps() {
        let temp = tempdir().unwrap();
        let manifest = write_manifest(
            temp.path(),
            r#"
[package]
name = "root"
version = "0.1.0"

[dev-dependencies]
dev-only = { path = "../external-dev" }

[build-dependencies]
build-only = { path = "../external-build" }
"#,
        );
        let found = scan_manifest_for_external_path_deps(&manifest, temp.path()).unwrap();
        let names: Vec<_> = found.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"dev-only"));
        assert!(names.contains(&"build-only"));
    }

    #[test]
    fn scanner_walks_target_specific_deps() {
        let temp = tempdir().unwrap();
        let manifest = write_manifest(
            temp.path(),
            r#"
[package]
name = "root"
version = "0.1.0"

[target.'cfg(unix)'.dependencies]
unix-only = { path = "../unix-external" }
"#,
        );
        let found = scan_manifest_for_external_path_deps(&manifest, temp.path()).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "unix-only");
    }

    #[test]
    fn scanner_walks_workspace_dependencies() {
        let temp = tempdir().unwrap();
        let manifest = write_manifest(
            temp.path(),
            r#"
[workspace]
members = []

[workspace.dependencies]
shared = { path = "../external-shared" }
"#,
        );
        let found = scan_manifest_for_external_path_deps(&manifest, temp.path()).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "shared");
    }

    #[test]
    fn scanner_ignores_bare_version_string_deps() {
        let temp = tempdir().unwrap();
        let manifest = write_manifest(
            temp.path(),
            r#"
[package]
name = "root"
version = "0.1.0"

[dependencies]
serde = "1.0"
"#,
        );
        let found = scan_manifest_for_external_path_deps(&manifest, temp.path()).unwrap();
        assert!(found.is_empty());
    }

    #[test]
    fn scanner_returns_err_on_malformed_toml() {
        let temp = tempdir().unwrap();
        let manifest = write_manifest(temp.path(), "this is { not valid toml");
        let err = scan_manifest_for_external_path_deps(&manifest, temp.path())
            .expect_err("malformed toml must error");
        match err {
            Error::InvalidManifest { .. } => {}
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    // ---- materialize_for_sandbox -----------------------------------------

    /// Sets up a host repo with `helm/src-tauri/Cargo.toml` declaring
    /// `wildmason-license = { path = "../../licensing/crate" }`, where
    /// `licensing/crate/` is a sibling of `helm/` (outside the helm
    /// repo). Returns (host_root_for_helm, host_external_source).
    fn setup_helm_like_layout() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let outer = tempdir().unwrap();
        let helm = outer.path().join("helm");
        let src_tauri = helm.join("src-tauri");
        fs::create_dir_all(&src_tauri).unwrap();
        let licensing_crate = outer.path().join("licensing").join("crate");
        fs::create_dir_all(licensing_crate.join("src")).unwrap();
        fs::write(
            licensing_crate.join("Cargo.toml"),
            "[package]\nname = \"wildmason-license\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(licensing_crate.join("src").join("lib.rs"), "// stub\n").unwrap();
        fs::write(
            src_tauri.join("Cargo.toml"),
            "[package]\nname = \"helm\"\nversion = \"0.1.0\"\n\n[dependencies]\nwildmason-license = { path = \"../../licensing/crate\" }\n",
        )
        .unwrap();
        (outer, helm, licensing_crate)
    }

    #[test]
    fn materialize_lands_destination_inside_sandbox_boundary_for_helm_layout() {
        let (_outer, helm, licensing_crate) = setup_helm_like_layout();
        // Sandbox sits at <helm>/.assay/runs/run-1/work/sandbox-a/, mirroring
        // the helm tree (the worktree of helm). It already has src-tauri/
        // checked out as part of the worktree.
        let run_root = helm.join(".assay").join("runs").join("run-1");
        let work_root = run_root.join("work");
        let sandbox = work_root.join("sandbox-a");
        fs::create_dir_all(sandbox.join("src-tauri")).unwrap();

        let dep = ExternalPathDep {
            name: "wildmason-license".into(),
            manifest_path: helm.join("src-tauri").join("Cargo.toml"),
            literal_path: "../../licensing/crate".into(),
            source_abs: licensing_crate.clone(),
        };

        let mat = materialize_for_sandbox(std::slice::from_ref(&dep), &helm, &sandbox, &run_root)
            .unwrap();
        assert_eq!(mat.len(), 1);

        // Destination must equal what cargo will compute from
        // sandbox/src-tauri/Cargo.toml's path = "../../licensing/crate"
        // — i.e. work_root.join("licensing/crate").
        let expected = work_root.join("licensing").join("crate");
        assert_eq!(
            logical_normalize(&mat[0].destination_abs),
            logical_normalize(&expected)
        );
        assert!(expected.join("Cargo.toml").is_file());
        assert!(expected.join("src").join("lib.rs").is_file());
    }

    #[test]
    fn materialize_is_idempotent() {
        let (_outer, helm, licensing_crate) = setup_helm_like_layout();
        let run_root = helm.join(".assay").join("runs").join("run-1");
        let sandbox = run_root.join("work").join("sandbox-a");
        fs::create_dir_all(sandbox.join("src-tauri")).unwrap();

        let dep = ExternalPathDep {
            name: "wildmason-license".into(),
            manifest_path: helm.join("src-tauri").join("Cargo.toml"),
            literal_path: "../../licensing/crate".into(),
            source_abs: licensing_crate,
        };
        materialize_for_sandbox(std::slice::from_ref(&dep), &helm, &sandbox, &run_root).unwrap();
        // Second call must not error and must not duplicate.
        materialize_for_sandbox(std::slice::from_ref(&dep), &helm, &sandbox, &run_root).unwrap();
    }

    #[test]
    fn materialize_refuses_when_destination_escapes_boundary() {
        let outer = tempdir().unwrap();
        let helm = outer.path().join("helm");
        let src_tauri = helm.join("src-tauri");
        fs::create_dir_all(&src_tauri).unwrap();
        let very_external = outer.path().join("far").join("away");
        fs::create_dir_all(&very_external).unwrap();
        fs::write(
            very_external.join("Cargo.toml"),
            "[package]\nname = \"far\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();

        let run_root = helm.join(".assay").join("runs").join("run-1");
        let sandbox = run_root.join("work").join("sandbox-a");
        fs::create_dir_all(sandbox.join("src-tauri")).unwrap();

        // path = "../../../../far/away" from src-tauri/ escapes out of
        // run_root all the way past .assay/ and lands in helm/far/away/.
        // The boundary check must reject.
        let dep = ExternalPathDep {
            name: "far".into(),
            manifest_path: src_tauri.join("Cargo.toml"),
            literal_path: "../../../../far/away".into(),
            source_abs: very_external,
        };
        let err = materialize_for_sandbox(&[dep], &helm, &sandbox, &run_root)
            .expect_err("escapes the boundary");
        let msg = format!("{err}");
        assert!(
            msg.contains("escapes the assay sandbox boundary"),
            "error must explain the boundary violation: {msg}"
        );
    }

    #[test]
    fn materialize_skips_target_and_dotgit() {
        let outer = tempdir().unwrap();
        let helm = outer.path().join("helm");
        let src_tauri = helm.join("src-tauri");
        fs::create_dir_all(&src_tauri).unwrap();
        let lic = outer.path().join("licensing").join("crate");
        fs::create_dir_all(lic.join("src")).unwrap();
        fs::create_dir_all(lic.join("target").join("debug")).unwrap();
        fs::create_dir_all(lic.join(".git")).unwrap();
        fs::write(
            lic.join("Cargo.toml"),
            "[package]\nname = \"lic\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(lic.join("src").join("lib.rs"), "// stub\n").unwrap();
        fs::write(
            lic.join("target").join("debug").join("artifact"),
            "big binary",
        )
        .unwrap();
        fs::write(lic.join(".git").join("HEAD"), "ref: refs/heads/main\n").unwrap();

        let run_root = helm.join(".assay").join("runs").join("run-1");
        let sandbox = run_root.join("work").join("sandbox-a");
        fs::create_dir_all(sandbox.join("src-tauri")).unwrap();

        let dep = ExternalPathDep {
            name: "lic".into(),
            manifest_path: src_tauri.join("Cargo.toml"),
            literal_path: "../../licensing/crate".into(),
            source_abs: lic,
        };
        let mat = materialize_for_sandbox(&[dep], &helm, &sandbox, &run_root).unwrap();
        let dest = &mat[0].destination_abs;
        assert!(dest.join("Cargo.toml").is_file());
        assert!(dest.join("src").join("lib.rs").is_file());
        assert!(
            !dest.join("target").exists(),
            "target/ must be skipped during materialization"
        );
        assert!(
            !dest.join(".git").exists(),
            ".git/ must be skipped during materialization"
        );
    }

    #[test]
    fn materialize_errors_when_source_missing() {
        let outer = tempdir().unwrap();
        let helm = outer.path().join("helm");
        let src_tauri = helm.join("src-tauri");
        fs::create_dir_all(&src_tauri).unwrap();
        let run_root = helm.join(".assay").join("runs").join("run-1");
        let sandbox = run_root.join("work").join("sandbox-a");
        fs::create_dir_all(sandbox.join("src-tauri")).unwrap();

        let dep = ExternalPathDep {
            name: "ghost".into(),
            manifest_path: src_tauri.join("Cargo.toml"),
            literal_path: "../../missing/ghost".into(),
            source_abs: outer.path().join("missing").join("ghost"),
        };
        let err = materialize_for_sandbox(&[dep], &helm, &sandbox, &run_root)
            .expect_err("source missing must error");
        assert!(format!("{err}").contains("external path dep source not found"));
    }

    // ---- discover_repo_external_path_deps ---------------------------------

    #[test]
    fn discover_canonicalizes_relative_repo_arg() {
        // Regression: previously, --repo `.` produced relative manifest
        // paths that broke materialize_for_sandbox's strip_prefix step.
        // discover_repo_external_path_deps must canonicalize so every
        // returned dep carries an absolute manifest_path.
        let outer = tempdir().unwrap();
        let helm = outer.path().join("helm");
        let src_tauri = helm.join("src-tauri");
        fs::create_dir_all(&src_tauri).unwrap();
        let lic = outer.path().join("licensing").join("crate");
        fs::create_dir_all(lic.join("src")).unwrap();
        fs::write(
            lic.join("Cargo.toml"),
            "[package]\nname = \"lic\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n",
        )
        .unwrap();
        fs::write(lic.join("src").join("lib.rs"), "// stub\n").unwrap();
        fs::create_dir_all(src_tauri.join("src")).unwrap();
        fs::write(src_tauri.join("src").join("main.rs"), "fn main(){}\n").unwrap();
        fs::write(
            src_tauri.join("Cargo.toml"),
            "[package]\nname = \"helm\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[[bin]]\nname = \"helm\"\npath = \"src/main.rs\"\n\n[dependencies]\nlic = { path = \"../../licensing/crate\" }\n",
        )
        .unwrap();
        // Initialize a minimal git repo so git_top_level resolves.
        let _ = std::process::Command::new("git")
            .args(["init", "-q", "-b", "main"])
            .current_dir(&helm)
            .output();
        let _ = std::process::Command::new("git")
            .args(["-c", "user.email=t@t", "-c", "user.name=t", "add", "-A"])
            .current_dir(&helm)
            .output();
        let _ = std::process::Command::new("git")
            .args([
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "-qm",
                "init",
            ])
            .current_dir(&helm)
            .output();
        // Caller passes a relative path — this is what `--repo .` looks
        // like when assay was invoked from inside src-tauri/.
        let prev_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&src_tauri).unwrap();
        let found = discover_repo_external_path_deps(Path::new("."));
        std::env::set_current_dir(prev_cwd).unwrap();
        let found = found.expect("discover must succeed");
        // The licensing dep should be discovered with an absolute
        // manifest_path so downstream materialization can strip_prefix.
        assert_eq!(found.len(), 1, "expected one external dep, got {found:?}");
        assert!(
            found[0].manifest_path.is_absolute(),
            "manifest_path must be absolute, got `{}`",
            found[0].manifest_path.display()
        );
    }

    #[test]
    fn discover_returns_empty_for_non_cargo_repo() {
        let temp = tempdir().unwrap();
        // No Cargo.toml in temp/
        let found = discover_repo_external_path_deps(temp.path()).unwrap();
        assert!(found.is_empty());
    }
}
