//! Format-preserving Cargo.toml constraint editor.
//!
//! Used by the Cargo applier to widen the version constraint for a
//! Compatible or Breaking bump proposal — the third of the three
//! [`BumpTier`](crate::model::BumpTier) cases. Cargo's resolver alone
//! cannot bump an out-of-constraint dep (`cargo update` rejects
//! `--precise` if it conflicts with the manifest), so we have to
//! rewrite the constraint string before `cargo update` regenerates
//! the lockfile.
//!
//! Edits are format-preserving via `toml_edit::DocumentMut`. Comments,
//! ordering, and whitespace are kept intact. Path and git deps that
//! lack an explicit `version` field are skipped — those are local
//! references, not registry constraints.
//!
//! Workspace inheritance (`foo = { workspace = true }`) is detected
//! but not resolved here — the editor returns `None` from such a
//! manifest so the caller can navigate to the workspace root and edit
//! `[workspace.dependencies]` instead.

use std::path::{Path, PathBuf};

use toml_edit::{DocumentMut, Item, Table, Value};

use crate::error::{Error, Result};

/// Outcome of attempting to widen a constraint in a single Cargo.toml.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditOutcome {
    /// Dotted path of the dep table the entry was found in. Examples:
    /// `dependencies`, `dev-dependencies`, `workspace.dependencies`,
    /// `target."cfg(unix)".dependencies`.
    pub table: String,
    /// The version string the entry carried before the edit.
    pub previous: String,
    /// `true` when the manifest's bytes changed. `false` when the dep
    /// was found but inherited from `[workspace.dependencies]`
    /// (`workspace = true`) — callers must redirect the edit to the
    /// workspace root manifest in that case.
    pub changed: bool,
}

impl EditOutcome {
    pub fn inherited_from_workspace(table: String, previous: String) -> Self {
        Self {
            table,
            previous,
            changed: false,
        }
    }
}

/// Widen the version constraint for `crate_name` to `new_version` in
/// `toml_text`.
///
/// Returns `Ok(None)` when no entry for `crate_name` is found in any
/// of this manifest's dep tables (caller checks the next manifest in
/// the workspace).
///
/// Returns `Ok(Some((new_toml, outcome)))` when an entry was found.
/// `outcome.changed == true` means `new_toml` differs from the input;
/// `false` means workspace inheritance and the caller must redirect
/// to the workspace root.
pub fn update_constraint(
    toml_text: &str,
    crate_name: &str,
    new_version: &str,
) -> Result<Option<(String, EditOutcome)>> {
    let mut doc = toml_text
        .parse::<DocumentMut>()
        .map_err(|e| Error::other(format!("Cargo.toml parse error: {e}")))?;

    // `[workspace.dependencies]` is the source-of-truth for workspaces
    // that share constraints via `foo = { workspace = true }` in members.
    // It MUST be tried first: a workspace root commonly carries both the
    // declaration here AND a `foo.workspace = true` consumer entry in
    // its own `[dependencies]` (when the root manifest is also a binary
    // crate, as in rust-lang/cargo). Checking the consumer table first
    // would short-circuit on the inheritance marker and silently skip
    // the real edit site in the same file.
    if let Some(outcome) = try_edit_at(
        &mut doc,
        &["workspace", "dependencies"],
        crate_name,
        new_version,
    )? {
        return finalize(doc, outcome);
    }

    // Standard dep tables, in priority order. `dev-dependencies` and
    // `build-dependencies` matter when a single crate appears in
    // multiple sections — we edit the first match. If a real project
    // duplicates a dep across sections at different versions, the
    // proposer's `from` value pins which one we want anyway.
    for table_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(outcome) = try_edit_at(&mut doc, &[table_name], crate_name, new_version)? {
            return finalize(doc, outcome);
        }
    }

    // `[target.'<cfg>'.dependencies]` — iterate every cfg key. Member
    // crates often pin OS-specific deps here.
    if let Some(target_tbl) = doc.get_mut("target").and_then(|i| i.as_table_mut()) {
        // Collect the keys first so we don't hold a borrow while editing.
        let cfg_keys: Vec<String> = target_tbl.iter().map(|(k, _)| k.to_string()).collect();
        for cfg in &cfg_keys {
            for table_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
                if let Some(outcome) = try_edit_at(
                    &mut doc,
                    &["target", cfg, table_name],
                    crate_name,
                    new_version,
                )? {
                    return finalize(doc, outcome);
                }
            }
        }
    }

    Ok(None)
}

fn finalize(doc: DocumentMut, outcome: EditOutcome) -> Result<Option<(String, EditOutcome)>> {
    Ok(Some((doc.to_string(), outcome)))
}

/// Drill into `doc` at the dotted path, then try to edit an entry
/// named `crate_name`. Returns `None` if the table doesn't exist or
/// the dep entry isn't present.
///
/// Lookup is by **effective package name**, not by raw table key. Cargo
/// supports a renamed-dep syntax — `memmap = { package = "memmap2", ... }`
/// — where the local key (`memmap`) differs from the actual registry
/// package (`memmap2`). The `package = "..."` field, when present, is
/// the source of truth for what crate this entry resolves to;
/// `cargo_metadata` reports that name in `dep.name`, so the proposer
/// emits `subject = "memmap2"` and the editor must match accordingly.
fn try_edit_at(
    doc: &mut DocumentMut,
    path: &[&str],
    crate_name: &str,
    new_version: &str,
) -> Result<Option<EditOutcome>> {
    let mut cursor: &mut Item = doc.as_item_mut();
    for segment in path {
        let next = cursor.as_table_like_mut().and_then(|t| t.get_mut(segment));
        match next {
            Some(item) => cursor = item,
            None => return Ok(None),
        }
    }
    let Some(table) = cursor.as_table_like_mut() else {
        return Ok(None);
    };
    let matched_key: Option<String> = table.iter().find_map(|(key, item)| {
        let effective = entry_package_name(item).unwrap_or_else(|| key.to_string());
        if effective == crate_name {
            Some(key.to_string())
        } else {
            None
        }
    });
    let Some(key) = matched_key else {
        return Ok(None);
    };
    let entry = table
        .get_mut(&key)
        .expect("key was just enumerated from the same table");
    let table_label = path.join(".");
    edit_entry(entry, &table_label, new_version)
}

/// Return the `package = "..."` field value when the entry uses cargo's
/// renamed-dep syntax; `None` for bare-string deps or inline/full tables
/// without a `package` field (the table key is the package name in
/// those cases).
fn entry_package_name(item: &Item) -> Option<String> {
    match item {
        Item::Value(Value::InlineTable(t)) => {
            t.get("package").and_then(|v| v.as_str()).map(String::from)
        }
        Item::Table(t) => t
            .get("package")
            .and_then(|i| i.as_value())
            .and_then(|v| v.as_str())
            .map(String::from),
        _ => None,
    }
}

/// Edit a single dep entry (one of the three TOML shapes Cargo accepts).
fn edit_entry(
    entry: &mut Item,
    table_label: &str,
    new_version: &str,
) -> Result<Option<EditOutcome>> {
    match entry {
        // Shape 1: bare string — `serde = "1.0"`. `Formatted<String>`
        // is immutable on its inner value, so we replace the whole
        // Value but carry the existing `Decor` (whitespace + trailing
        // comments) forward onto the new one.
        Item::Value(v @ Value::String(_)) => {
            let Value::String(s) = v else { unreachable!() };
            let previous = s.value().to_string();
            let decor = s.decor().clone();
            let replacement = preserve_constraint_prefix(&previous, new_version);
            let mut new_val = Value::from(replacement);
            *new_val.decor_mut() = decor;
            *v = new_val;
            Ok(Some(EditOutcome {
                table: table_label.to_string(),
                previous,
                changed: true,
            }))
        }
        // Shape 2: inline table — `serde = { version = "1.0", features = [..] }`.
        Item::Value(Value::InlineTable(t)) => {
            if t.get("workspace").and_then(|v| v.as_bool()) == Some(true) {
                // Member inherits from [workspace.dependencies]; redirect.
                return Ok(Some(EditOutcome::inherited_from_workspace(
                    table_label.to_string(),
                    String::from("workspace"),
                )));
            }
            let Some(version_entry) = t.get_mut("version") else {
                // path = "..." or git = "..." with no version pin.
                // Nothing to bump here.
                return Ok(None);
            };
            let Value::String(s) = version_entry else {
                return Err(Error::other(format!(
                    "Cargo.toml dep `{table_label}` has non-string `version` field"
                )));
            };
            let previous = s.value().to_string();
            let decor = s.decor().clone();
            let replacement = preserve_constraint_prefix(&previous, new_version);
            let mut new_val = Value::from(replacement);
            *new_val.decor_mut() = decor;
            *version_entry = new_val;
            Ok(Some(EditOutcome {
                table: table_label.to_string(),
                previous,
                changed: true,
            }))
        }
        // Shape 3: full table — `[dependencies.serde]` … `version = "1.0"`.
        Item::Table(t) => edit_full_table_entry(t, table_label, new_version),
        _ => Ok(None),
    }
}

fn edit_full_table_entry(
    t: &mut Table,
    table_label: &str,
    new_version: &str,
) -> Result<Option<EditOutcome>> {
    if t.get("workspace").and_then(|i| i.as_bool()) == Some(true) {
        return Ok(Some(EditOutcome::inherited_from_workspace(
            table_label.to_string(),
            String::from("workspace"),
        )));
    }
    let Some(version_item) = t.get_mut("version") else {
        return Ok(None);
    };
    let Some(val) = version_item.as_value_mut() else {
        return Err(Error::other(format!(
            "Cargo.toml dep `{table_label}` has non-string `version` field"
        )));
    };
    let Value::String(s) = val else {
        return Err(Error::other(format!(
            "Cargo.toml dep `{table_label}` has non-string `version` field"
        )));
    };
    let previous = s.value().to_string();
    let decor = s.decor().clone();
    let replacement = preserve_constraint_prefix(&previous, new_version);
    let mut new_val = Value::from(replacement);
    *new_val.decor_mut() = decor;
    *val = new_val;
    Ok(Some(EditOutcome {
        table: table_label.to_string(),
        previous,
        changed: true,
    }))
}

/// Re-apply the original constraint operator (if any) onto `new_version`.
///
/// Cargo accepts these operator prefixes on a SemVer requirement:
/// `=`, `^`, `~`, `>`, `<`, `>=`, `<=`. Whitespace between operator
/// and version is allowed (`"= 1.0.0"` is valid). When the manifest
/// uses one of these, the user has made a deliberate choice — most
/// commonly `=` for exact-pin — that the editor must not silently
/// drop. Otherwise a bump from `"= 0.1.0-beta.1"` to `"0.1.0-beta.3"`
/// widens the constraint from "exactly this version" to "default
/// caret," which is a semantically different requirement.
///
/// Multi-requirement specs (`">=1.0, <2.0"`) and wildcards (`"*"`) are
/// opaque — half-rewriting them is worse than collapsing them to a
/// concrete bare version, so we fall back to verbatim replacement and
/// trust the user to audit the diff.
fn preserve_constraint_prefix(existing: &str, new_version: &str) -> String {
    if existing.contains(',') {
        return new_version.to_string();
    }
    let prefix_len = existing
        .find(|c: char| c.is_ascii_digit())
        .unwrap_or(existing.len());
    let prefix = &existing[..prefix_len];
    let is_operator_prefix = !prefix.is_empty()
        && prefix
            .chars()
            .all(|c| matches!(c, '=' | '~' | '^' | '>' | '<') || c.is_whitespace())
        && prefix.chars().any(|c| !c.is_whitespace());
    if !is_operator_prefix {
        return new_version.to_string();
    }
    format!("{prefix}{new_version}")
}

/// Walk every Cargo.toml in `workspace_root` (the root manifest + each
/// resolved workspace member, via `cargo metadata --no-deps`) and apply
/// [`update_constraint`] to each. Files that already carry the dep
/// have their constraint widened in place; files without it are left
/// alone.
///
/// Returns the **workspace-relative** paths of every Cargo.toml whose
/// bytes changed, sorted lexicographically so the receipt is
/// deterministic across runs.
///
/// `workspace_root` is the path that contains the top-level Cargo.toml.
/// This is what the `crate::cli::ProjectScope::resolve` flow already
/// hands the applier — for a Tauri project with `src-tauri/Cargo.toml`
/// that's `<project>/src-tauri`, NOT the git root.
pub fn apply_constraint_widening_to_workspace(
    workspace_root: &Path,
    crate_name: &str,
    new_version: &str,
) -> Result<Vec<PathBuf>> {
    let manifests = list_workspace_manifests(workspace_root)?;
    let mut modified: Vec<PathBuf> = Vec::new();
    for manifest_path in &manifests {
        let text = std::fs::read_to_string(manifest_path).map_err(|source| Error::Io {
            path: manifest_path.clone(),
            source,
        })?;
        let Some((new_text, outcome)) = update_constraint(&text, crate_name, new_version)? else {
            continue;
        };
        if !outcome.changed {
            // Workspace inheritance — this manifest carries no real
            // constraint to widen. The corresponding edit lives in
            // [workspace.dependencies] which the walker will find on
            // a different iteration (the root manifest).
            continue;
        }
        std::fs::write(manifest_path, new_text).map_err(|source| Error::Io {
            path: manifest_path.clone(),
            source,
        })?;
        let relative = manifest_path
            .strip_prefix(workspace_root)
            .unwrap_or(manifest_path)
            .to_path_buf();
        modified.push(relative);
    }
    modified.sort();
    Ok(modified)
}

/// Resolve every Cargo.toml the workspace owns: the root manifest plus
/// each `cargo metadata` workspace member. Returns absolute paths.
/// Exposed `pub(crate)` so the copy-back path can mirror exactly the
/// same manifest set when deciding which Cargo.toml files to ship from
/// sandbox to host.
pub(crate) fn list_workspace_manifests(workspace_root: &Path) -> Result<Vec<PathBuf>> {
    use cargo_metadata::MetadataCommand;
    let manifest_path = workspace_root.join("Cargo.toml");
    if !manifest_path.is_file() {
        return Err(Error::InvalidManifest {
            path: manifest_path,
            message: "Cargo.toml not found in workspace root".into(),
        });
    }
    let metadata = MetadataCommand::new()
        .manifest_path(&manifest_path)
        .no_deps()
        .exec()
        .map_err(|e| Error::other(format!("cargo metadata (for editor walk) failed: {e}")))?;
    let mut paths: Vec<PathBuf> = vec![manifest_path.clone()];
    for member_id in &metadata.workspace_members {
        if let Some(pkg) = metadata.packages.iter().find(|p| &p.id == member_id) {
            let member_manifest: PathBuf = pkg.manifest_path.clone().into();
            if !paths.iter().any(|p| p == &member_manifest) {
                paths.push(member_manifest);
            }
        }
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edits_bare_string_dependency() {
        let toml = r#"[dependencies]
serde = "1.0"
"#;
        let (out, outcome) = update_constraint(toml, "serde", "1.5.2").unwrap().unwrap();
        assert!(out.contains(r#"serde = "1.5.2""#));
        assert_eq!(outcome.table, "dependencies");
        assert_eq!(outcome.previous, "1.0");
        assert!(outcome.changed);
    }

    #[test]
    fn edits_inline_table_version_field() {
        let toml = r#"[dependencies]
serde = { version = "1.0", features = ["derive"] }
"#;
        let (out, outcome) = update_constraint(toml, "serde", "1.5.2").unwrap().unwrap();
        // Features list must survive intact; only `version` changes.
        assert!(out.contains(r#"version = "1.5.2""#), "got: {out}");
        assert!(out.contains(r#"features = ["derive"]"#), "got: {out}");
        assert_eq!(outcome.previous, "1.0");
        assert!(outcome.changed);
    }

    #[test]
    fn edits_full_table_form() {
        let toml = r#"[dependencies.serde]
version = "1.0"
features = ["derive"]
"#;
        let (out, outcome) = update_constraint(toml, "serde", "1.5.2").unwrap().unwrap();
        assert!(out.contains(r#"version = "1.5.2""#), "got: {out}");
        assert!(out.contains(r#"features = ["derive"]"#));
        assert_eq!(outcome.table, "dependencies");
        assert!(outcome.changed);
    }

    #[test]
    fn edits_dev_dependencies_section() {
        let toml = r#"[dev-dependencies]
tempfile = "3.20"
"#;
        let (out, outcome) = update_constraint(toml, "tempfile", "3.27.0")
            .unwrap()
            .unwrap();
        assert!(out.contains(r#"tempfile = "3.27.0""#));
        assert_eq!(outcome.table, "dev-dependencies");
    }

    #[test]
    fn edits_target_specific_dependencies() {
        let toml = r#"[target.'cfg(unix)'.dependencies]
libc = "0.2"
"#;
        let (out, outcome) = update_constraint(toml, "libc", "0.2.999").unwrap().unwrap();
        assert!(out.contains(r#"libc = "0.2.999""#));
        // Target table label must surface the cfg key so receipts can
        // distinguish `cfg(unix)` from `cfg(windows)` constraints.
        assert!(
            outcome.table.contains("target") && outcome.table.contains("dependencies"),
            "got table: {}",
            outcome.table,
        );
        assert!(outcome.changed);
    }

    #[test]
    fn edits_workspace_dependencies_section() {
        let toml = r#"[workspace.dependencies]
serde = "1.0"
"#;
        let (out, outcome) = update_constraint(toml, "serde", "1.5.2").unwrap().unwrap();
        assert!(out.contains(r#"serde = "1.5.2""#));
        assert_eq!(outcome.table, "workspace.dependencies");
        assert!(outcome.changed);
    }

    #[test]
    fn detects_workspace_inheritance_without_writing() {
        // Member crate inherits constraint from the workspace root.
        // The editor must NOT edit the member; it must report this so
        // the caller can navigate to the root and edit there.
        let toml = r#"[dependencies]
serde = { workspace = true }
"#;
        let (out, outcome) = update_constraint(toml, "serde", "1.5.2").unwrap().unwrap();
        // Manifest contents unchanged.
        assert_eq!(out, toml);
        assert!(!outcome.changed);
        assert_eq!(outcome.previous, "workspace");
    }

    #[test]
    fn skips_path_dep_without_version_field() {
        // `wildmason-license = { path = "../licensing/crate" }` — a
        // pure local-path reference. No version constraint to widen;
        // the editor returns None so the caller knows to skip it.
        let toml = r#"[dependencies]
wildmason-license = { path = "../licensing/crate" }
"#;
        let result = update_constraint(toml, "wildmason-license", "2.0.0").unwrap();
        assert!(result.is_none(), "path dep without version must yield None");
    }

    #[test]
    fn edits_git_dep_when_version_field_is_present() {
        // git deps with explicit `version` pins are valid Cargo
        // (cargo enforces semver alongside the git source).
        let toml = r#"[dependencies]
my-crate = { git = "https://example.invalid/x.git", version = "1.0" }
"#;
        let (out, outcome) = update_constraint(toml, "my-crate", "1.5.2")
            .unwrap()
            .unwrap();
        assert!(out.contains(r#"version = "1.5.2""#));
        assert!(out.contains(r#"git = "https://example.invalid/x.git""#));
        assert_eq!(outcome.previous, "1.0");
    }

    #[test]
    fn returns_none_when_dep_missing_from_manifest() {
        let toml = r#"[dependencies]
serde = "1.0"
"#;
        let result = update_constraint(toml, "tokio", "1.42.0").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn preserves_comments_and_whitespace() {
        // Format-preservation is the whole point of toml_edit. If a
        // future cargo version of toml_edit regresses on this we want
        // to catch it loudly.
        let toml = r#"# Top-of-file comment
[dependencies]
# inline note on serde
serde = "1.0"  # trailing comment

# blank line above
tokio = "1.0"
"#;
        let (out, _) = update_constraint(toml, "serde", "1.5.2").unwrap().unwrap();
        assert!(out.starts_with("# Top-of-file comment"));
        assert!(out.contains("# inline note on serde"));
        assert!(out.contains("# trailing comment"));
        assert!(out.contains("tokio = \"1.0\""));
    }

    #[test]
    fn errors_on_unparseable_toml() {
        let result = update_constraint("[this is not toml", "serde", "1.0.0");
        assert!(result.is_err());
    }

    #[test]
    fn errors_when_version_field_is_non_string() {
        // Cargo wouldn't accept this either, but defensively erroring
        // beats writing garbage.
        let toml = r#"[dependencies]
serde = { version = 1 }
"#;
        let result = update_constraint(toml, "serde", "1.0.0");
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------------
    // Renamed deps via cargo's `{ package = "real-name", ... }` syntax.
    //
    // Real-world case caught by the ripgrep dogfood (2026-05-18):
    // `crates/searcher/Cargo.toml` declares
    //   memmap = { package = "memmap2", version = "0.9.0" }
    // The local key is `memmap`; the actual registry package is `memmap2`.
    // `cargo_metadata` reports the package name (`memmap2`), so the
    // proposer correctly emits proposal subject = "memmap2", but the
    // editor's direct table-key lookup misses the entry (key is "memmap",
    // not "memmap2") and the apply fails with "no manifest carried a
    // matching dep entry."
    // -------------------------------------------------------------------------

    #[test]
    fn edits_renamed_inline_table_dep_by_package_field() {
        let toml = r#"[dependencies]
memmap = { package = "memmap2", version = "0.9.0" }
"#;
        let (out, outcome) = update_constraint(toml, "memmap2", "0.9.10")
            .unwrap()
            .unwrap();
        // Version widened, package field preserved, local rename key intact.
        assert!(out.contains(r#"version = "0.9.10""#), "got: {out}");
        assert!(out.contains(r#"package = "memmap2""#), "got: {out}");
        assert!(out.contains("memmap = {"), "got: {out}");
        assert_eq!(outcome.previous, "0.9.0");
        assert!(outcome.changed);
    }

    #[test]
    fn edits_renamed_full_table_dep_by_package_field() {
        let toml = r#"[dependencies.memmap]
package = "memmap2"
version = "0.9.0"
"#;
        let (out, outcome) = update_constraint(toml, "memmap2", "0.9.10")
            .unwrap()
            .unwrap();
        assert!(out.contains(r#"version = "0.9.10""#), "got: {out}");
        assert!(out.contains(r#"package = "memmap2""#), "got: {out}");
        assert_eq!(outcome.previous, "0.9.0");
        assert!(outcome.changed);
    }

    #[test]
    fn renamed_dep_does_not_match_on_local_key_alone() {
        // `memmap = { package = "different-pkg", ... }` — the local key
        // collides with what the caller is searching for, but the
        // `package` field says this entry IS NOT `memmap`. Editor must
        // return None so the caller keeps walking other manifests.
        let toml = r#"[dependencies]
memmap = { package = "different-pkg", version = "0.9.0" }
"#;
        let result = update_constraint(toml, "memmap", "0.9.10").unwrap();
        assert!(
            result.is_none(),
            "key=memmap with package=different-pkg must NOT match query crate_name=memmap"
        );
    }

    #[test]
    fn unrenamed_dep_still_matches_by_table_key() {
        // Sanity regression: when `package` is absent, the table key IS
        // the package name. Pre-fix behavior must keep working.
        let toml = r#"[dependencies]
serde = "1.0"
"#;
        let (out, outcome) = update_constraint(toml, "serde", "1.5.2").unwrap().unwrap();
        assert!(out.contains(r#"serde = "1.5.2""#));
        assert!(outcome.changed);
    }

    #[test]
    fn walker_handles_renamed_dep_in_member_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // Mirror ripgrep's shape: member declares the dep under a local
        // rename. The walker must locate it via the `package` field and
        // widen the constraint in place.
        let root_toml = "[workspace]\n\
            resolver = \"2\"\n\
            members = [\"a\", \"b\"]\n";
        build_walker_fixture(
            root,
            root_toml,
            &[
                (
                    "a",
                    r#"memmap = { package = "memmap2", version = "0.9.0" }"#,
                ),
                ("b", ""),
            ],
        );

        let modified = apply_constraint_widening_to_workspace(root, "memmap2", "0.9.10").unwrap();
        assert_eq!(modified, vec![PathBuf::from("a/Cargo.toml")]);
        let a = std::fs::read_to_string(root.join("a/Cargo.toml")).unwrap();
        assert!(a.contains(r#"version = "0.9.10""#), "a: {a}");
        assert!(a.contains(r#"package = "memmap2""#), "a: {a}");
        assert!(
            a.contains("memmap = {"),
            "local rename key must survive: {a}"
        );
    }

    // -------------------------------------------------------------------------
    // apply_constraint_widening_to_workspace — multi-manifest walker.
    //
    // Uses real `cargo metadata --no-deps` invocations, so these tests
    // need a synthetic Cargo workspace tree on disk with minimal valid
    // member crates. The fixtures intentionally mirror the same shape
    // that the cargo.rs Resolver tests use.
    // -------------------------------------------------------------------------

    /// Set up a workspace with `members = ["a", "b"]`, each as a tiny
    /// library crate. `dep_decls` is per-member raw TOML to inject into
    /// each member's `[dependencies]` section; an empty string means the
    /// member has no deps. The root manifest is written verbatim from
    /// `root_toml`.
    fn build_walker_fixture(root: &Path, root_toml: &str, dep_decls: &[(&str, &str)]) {
        std::fs::write(root.join("Cargo.toml"), root_toml).unwrap();
        let mut declared = std::collections::BTreeMap::new();
        for (member, decl) in dep_decls {
            declared.insert(*member, *decl);
        }
        for member in ["a", "b"] {
            let dir = root.join(member);
            std::fs::create_dir_all(dir.join("src")).unwrap();
            std::fs::write(dir.join("src/lib.rs"), "").unwrap();
            let decl = declared.get(member).copied().unwrap_or("");
            std::fs::write(
                dir.join("Cargo.toml"),
                format!(
                    "[package]\nname = \"{member}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n{decl}\n"
                ),
            )
            .unwrap();
        }
    }

    #[test]
    fn walker_edits_workspace_dependencies_in_root_when_members_inherit() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // Root declares constraint via [workspace.dependencies]; both
        // members inherit via `{ workspace = true }`. The walker must
        // edit the root manifest exactly once and leave member manifests
        // untouched.
        let root_toml = "[workspace]\n\
            resolver = \"2\"\n\
            members = [\"a\", \"b\"]\n\
            \n\
            [workspace.dependencies]\n\
            serde = \"1.0\"\n";
        build_walker_fixture(
            root,
            root_toml,
            &[
                ("a", "serde = { workspace = true }"),
                ("b", "serde = { workspace = true }"),
            ],
        );

        let modified = apply_constraint_widening_to_workspace(root, "serde", "1.5.2").unwrap();
        assert_eq!(modified, vec![PathBuf::from("Cargo.toml")]);
        let updated_root = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
        assert!(
            updated_root.contains(r#"serde = "1.5.2""#),
            "root: {updated_root}"
        );
        // Members must NOT have been rewritten — verify the inherit shape survives.
        let a = std::fs::read_to_string(root.join("a/Cargo.toml")).unwrap();
        assert!(a.contains("serde = { workspace = true }"), "a: {a}");
    }

    #[test]
    fn walker_edits_each_member_with_its_own_explicit_pin() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // No [workspace.dependencies] — each member carries its own
        // explicit constraint. Both must get widened.
        let root_toml = "[workspace]\n\
            resolver = \"2\"\n\
            members = [\"a\", \"b\"]\n";
        build_walker_fixture(
            root,
            root_toml,
            &[("a", "serde = \"1.0\""), ("b", "serde = \"1.0\"")],
        );

        let mut modified = apply_constraint_widening_to_workspace(root, "serde", "1.5.2").unwrap();
        modified.sort();
        assert_eq!(
            modified,
            vec![PathBuf::from("a/Cargo.toml"), PathBuf::from("b/Cargo.toml")],
        );
        for member in ["a", "b"] {
            let text = std::fs::read_to_string(root.join(member).join("Cargo.toml")).unwrap();
            assert!(
                text.contains(r#"serde = "1.5.2""#),
                "member {member}: {text}",
            );
        }
    }

    #[test]
    fn walker_returns_empty_when_no_manifest_carries_the_dep() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let root_toml = "[workspace]\nresolver = \"2\"\nmembers = [\"a\", \"b\"]\n";
        build_walker_fixture(root, root_toml, &[]);
        let modified = apply_constraint_widening_to_workspace(root, "tokio", "1.42.0").unwrap();
        assert!(modified.is_empty());
    }

    #[test]
    fn walker_errors_when_root_cargo_toml_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let err = apply_constraint_widening_to_workspace(tmp.path(), "serde", "1.5.2")
            .expect_err("missing Cargo.toml must surface as error");
        assert!(
            matches!(err, Error::InvalidManifest { .. }),
            "expected InvalidManifest, got {err:?}",
        );
    }

    // -------------------------------------------------------------------------
    // Constraint-prefix preservation.
    //
    // Real-world case caught by the tokio dogfood (2026-05-19):
    // `tokio/Cargo.toml` declares `tracing-mock = "= 0.1.0-beta.1"` under
    // `[target.'cfg(all(tokio_unstable, target_has_atomic = "64"))'.dev-dependencies]`.
    // The `= ` exact-pin operator is load-bearing — the user explicitly
    // does NOT want minor/patch drift. Pre-fix the editor replaced the
    // value verbatim and silently dropped the `=`, widening the
    // constraint from "exactly this version" to "default caret".
    //
    // The same class of bug applies to all prefix operators cargo
    // accepts: `=`, `~`, `^`, `>`, `<`, `>=`, `<=`. Multi-requirement
    // specs like `">=1, <2"` are opaque to us — we replace verbatim
    // rather than risk half-rewriting one half of the constraint.
    // -------------------------------------------------------------------------

    #[test]
    fn preserves_exact_pin_prefix_on_bare_string() {
        let toml = r#"[dependencies]
tracing-mock = "= 0.1.0-beta.1"
"#;
        let (out, outcome) = update_constraint(toml, "tracing-mock", "0.1.0-beta.3")
            .unwrap()
            .unwrap();
        assert!(
            out.contains(r#"tracing-mock = "= 0.1.0-beta.3""#),
            "exact-pin `= ` prefix must survive: {out}"
        );
        assert_eq!(outcome.previous, "= 0.1.0-beta.1");
        assert!(outcome.changed);
    }

    #[test]
    fn preserves_tilde_prefix_on_bare_string() {
        let toml = r#"[dependencies]
foo = "~1.2"
"#;
        let (out, _) = update_constraint(toml, "foo", "1.5.2").unwrap().unwrap();
        assert!(
            out.contains(r#"foo = "~1.5.2""#),
            "tilde prefix must survive: {out}"
        );
    }

    #[test]
    fn preserves_caret_prefix_on_bare_string() {
        let toml = r#"[dependencies]
foo = "^1.0"
"#;
        let (out, _) = update_constraint(toml, "foo", "1.5.2").unwrap().unwrap();
        assert!(
            out.contains(r#"foo = "^1.5.2""#),
            "explicit caret prefix must survive: {out}"
        );
    }

    #[test]
    fn preserves_gte_prefix_on_bare_string() {
        let toml = r#"[dependencies]
foo = ">=1.0"
"#;
        let (out, _) = update_constraint(toml, "foo", "1.5.2").unwrap().unwrap();
        assert!(
            out.contains(r#"foo = ">=1.5.2""#),
            ">= prefix must survive: {out}"
        );
    }

    #[test]
    fn preserves_exact_pin_prefix_on_inline_table_version() {
        let toml = r#"[dependencies]
foo = { version = "= 1.0", features = ["x"] }
"#;
        let (out, _) = update_constraint(toml, "foo", "1.5.2").unwrap().unwrap();
        assert!(
            out.contains(r#"version = "= 1.5.2""#),
            "inline-table exact-pin must survive: {out}"
        );
        assert!(out.contains(r#"features = ["x"]"#));
    }

    #[test]
    fn preserves_exact_pin_prefix_on_full_table_version() {
        let toml = r#"[dependencies.foo]
version = "= 1.0"
features = ["x"]
"#;
        let (out, _) = update_constraint(toml, "foo", "1.5.2").unwrap().unwrap();
        assert!(
            out.contains(r#"version = "= 1.5.2""#),
            "full-table exact-pin must survive: {out}"
        );
    }

    #[test]
    fn falls_back_to_verbatim_for_multi_requirement_constraint() {
        // `">=1, <2"` is two comma-separated constraints. Half-rewriting
        // one half is worse than replacing the whole string with the
        // resolved bare version — the user can audit the diff.
        let toml = r#"[dependencies]
foo = ">=1, <2"
"#;
        let (out, _) = update_constraint(toml, "foo", "1.5.2").unwrap().unwrap();
        assert!(
            out.contains(r#"foo = "1.5.2""#),
            "multi-requirement must collapse to bare: {out}"
        );
    }

    #[test]
    fn falls_back_to_verbatim_for_wildcard_constraint() {
        // `"*"` (any version) carries no operator we can preserve onto a
        // concrete version. Replace verbatim — the bump pins it.
        let toml = r#"[dependencies]
foo = "*"
"#;
        let (out, _) = update_constraint(toml, "foo", "1.5.2").unwrap().unwrap();
        assert!(
            out.contains(r#"foo = "1.5.2""#),
            "wildcard must collapse to bare: {out}"
        );
    }

    // -------------------------------------------------------------------------
    // Dotted-header dep declaration.
    //
    // Real-world case caught by the tokio dogfood (2026-05-19):
    // `tokio/Cargo.toml` declares
    //   [target.'cfg(windows)'.dependencies.windows-sys]
    //   version = "0.61"
    //   optional = true
    // The dep entry IS the table header — `windows-sys` is the final
    // segment of the dotted path, not a child key under
    // `[target.'cfg(windows)'.dependencies]`. The editor walks to
    // `["target", cfg, "dependencies"]` and iterates the children, so
    // `windows-sys` shows up as an `Item::Table` and is handled by the
    // existing full-table path — but we lacked a regression test for
    // this real-world shape until the dogfood surfaced it.
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // Workspace-root + binary-crate combined manifest.
    //
    // Real-world case caught by the rust-lang/cargo dogfood (2026-05-19):
    // `cargo/Cargo.toml` is BOTH the workspace root (declaring
    // `[workspace.dependencies] tar = { version = "0.4.45" }`) AND the
    // cargo binary's manifest (declaring `[dependencies] tar.workspace = true`).
    //
    // Pre-fix, `update_constraint` iterated `[dependencies]` first, found
    // `tar.workspace = true`, returned `inherited_from_workspace`
    // (changed=false), and short-circuited without ever checking
    // `[workspace.dependencies]` in the same manifest. The walker then
    // moved on to member manifests, none of which carried
    // `[workspace.dependencies]` either, and the apply failed with
    // "no manifest carried a matching dep entry."
    //
    // Fix: try `[workspace.dependencies]` first. If the dep is declared
    // there, the bump lands at the source-of-truth; if not, fall back
    // to the other tables (where `workspace = true` correctly marks
    // inheritance and the walker continues to the next manifest).
    // -------------------------------------------------------------------------

    #[test]
    fn edits_workspace_dependencies_when_root_also_inherits_in_its_own_dep_table() {
        // Root manifest declares the constraint AND consumes it via
        // workspace inheritance — the same manifest is both source and
        // consumer.
        let toml = r#"[workspace]
members = []

[workspace.dependencies]
tar = { version = "0.4.45", default-features = false }

[package]
name = "cargo"
version = "0.1.0"

[dependencies]
tar.workspace = true
"#;
        let (out, outcome) = update_constraint(toml, "tar", "0.4.46").unwrap().unwrap();
        // The [workspace.dependencies] entry must be widened. The
        // [dependencies] inheritance marker must survive unchanged.
        assert!(
            out.contains(r#"tar = { version = "0.4.46""#),
            "[workspace.dependencies] tar must update: {out}"
        );
        assert!(
            out.contains("tar.workspace = true"),
            "[dependencies] inheritance marker must survive: {out}"
        );
        assert_eq!(outcome.table, "workspace.dependencies");
        assert!(outcome.changed);
    }

    #[test]
    fn member_with_workspace_inheritance_still_redirects_when_root_lacks_dep() {
        // Member-only manifest that inherits — must still return the
        // inheritance marker so the walker keeps looking in OTHER
        // manifests (the root). This is the inverse of the fix above:
        // when [workspace.dependencies] is absent, the walker MUST be
        // able to defer to a different manifest.
        let toml = r#"[package]
name = "member"
version = "0.1.0"

[dependencies]
tar = { workspace = true }
"#;
        let (out, outcome) = update_constraint(toml, "tar", "0.4.46").unwrap().unwrap();
        assert_eq!(out, toml, "member manifest must not be rewritten");
        assert!(!outcome.changed);
        assert_eq!(outcome.previous, "workspace");
    }

    #[test]
    fn edits_dotted_header_target_cfg_dep_entry() {
        let toml = r#"[target.'cfg(windows)'.dependencies.windows-sys]
version = "0.61"
optional = true
"#;
        let (out, outcome) = update_constraint(toml, "windows-sys", "0.62.0")
            .unwrap()
            .unwrap();
        assert!(
            out.contains(r#"version = "0.62.0""#),
            "dotted-header dep version must update: {out}"
        );
        assert!(
            out.contains("optional = true"),
            "sibling fields must survive: {out}"
        );
        assert!(outcome.changed);
    }
}
