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

    // `[workspace.dependencies]` is the source-of-truth for workspaces
    // that share constraints via `foo = { workspace = true }` in members.
    if let Some(outcome) = try_edit_at(
        &mut doc,
        &["workspace", "dependencies"],
        crate_name,
        new_version,
    )? {
        return finalize(doc, outcome);
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
    let Some(entry) = table.get_mut(crate_name) else {
        return Ok(None);
    };
    let table_label = path.join(".");
    edit_entry(entry, &table_label, new_version)
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
            let mut new_val = Value::from(new_version);
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
            let mut new_val = Value::from(new_version);
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
    let mut new_val = Value::from(new_version);
    *new_val.decor_mut() = decor;
    *val = new_val;
    Ok(Some(EditOutcome {
        table: table_label.to_string(),
        previous,
        changed: true,
    }))
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
}
