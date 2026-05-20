//! Detect `.github/workflows/*.yml` and `.github/actions/*/action.yml`
//! files, parse `uses:` references, and turn them into [`Manifest`] entries.
//!
//! Uses a line-based scanner (not a full YAML parse) so trailing inline
//! comments like `uses: foo/bar@sha # v1.2.3` survive byte-for-byte for
//! the applier to rewrite.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::model::{Manifest, ManifestKind};

use super::tag_utils::is_version_char;
use super::{UsesKind, UsesReference};

pub(super) fn is_yaml(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    matches!(ext, "yml" | "yaml")
}

pub(super) fn walk_composite_actions(actions_dir: &Path) -> Result<Vec<PathBuf>> {
    // Composite actions live at `.github/actions/<name>/action.yml`.
    let mut out = Vec::new();
    for entry in std::fs::read_dir(actions_dir).map_err(|source| Error::Io {
        path: actions_dir.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| Error::Io {
            path: actions_dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        for filename in ["action.yml", "action.yaml"] {
            let candidate = path.join(filename);
            if candidate.is_file() {
                out.push(candidate);
                break;
            }
        }
    }
    Ok(out)
}

pub(super) fn workflow_to_manifest(path: &Path, repo: &Path) -> Result<Option<Manifest>> {
    let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let uses = collect_uses_references(&text);
    if uses.is_empty() {
        return Ok(None);
    }
    let mut metadata: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    metadata.insert(
        "uses".to_string(),
        serde_json::to_value(&uses).map_err(Error::Json)?,
    );
    let rel = path
        .strip_prefix(repo)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| path.to_path_buf());
    Ok(Some(Manifest {
        path: rel,
        kind: ManifestKind::WorkflowYaml,
        metadata,
    }))
}

/// Extracts every `uses:` reference from a workflow YAML file.
///
/// Uses a line-based scanner rather than a full YAML parse because workflow
/// files frequently use trailing inline comments (`uses: foo/bar@sha # v1.2.3`)
/// that we want to preserve byte-for-byte when rewriting in the Applier.
/// The Applier itself walks the YAML tree separately to find the byte range.
pub fn collect_uses_references(workflow_text: &str) -> Vec<UsesReference> {
    let mut out = Vec::new();
    for raw_line in workflow_text.lines() {
        let mut line = raw_line.trim_start();
        // Accept both `uses: ...` and `- uses: ...` (the YAML list-item form).
        if let Some(after_dash) = line.strip_prefix("- ") {
            line = after_dash.trim_start();
        }
        let rest = match line.strip_prefix("uses:") {
            Some(rest) => rest,
            None => continue,
        };
        // Strip leading whitespace after the colon, then capture up to the
        // first whitespace or `#` (start of an inline comment).
        let after_colon = rest.trim_start();
        let (value, comment_after_hash) = match after_colon.split_once('#') {
            Some((before, after)) => (before.trim_end(), Some(after)),
            None => match after_colon.split_once(char::is_whitespace) {
                Some((before, _)) => (before, None),
                None => (after_colon, None),
            },
        };
        let trimmed = value.trim().trim_matches('"').trim_matches('\'');
        if trimmed.is_empty() {
            continue;
        }
        let mut parsed = parse_uses_value(trimmed);
        parsed.tag_comment = extract_tag_comment(comment_after_hash);
        out.push(parsed);
    }
    out
}

/// Extract a version-tag-shaped comment body from the post-`#` content
/// of a `uses:` line. Mirrors the version-tag heuristic used by the
/// Applier's comment rewriter — leading whitespace stripped, body kept
/// only when its first char looks like a version (`v`, `V`, or a digit).
///
/// Examples:
/// - `" v3.5.2"` → `Some("v3.5.2")`
/// - `" 1.2.3"` → `Some("1.2.3")`
/// - `" # pinned for security"` → `None` (no version-shaped body)
fn extract_tag_comment(after_hash: Option<&str>) -> Option<String> {
    let raw = after_hash?;
    let trimmed = raw.trim();
    let first = trimmed.chars().next()?;
    if !is_version_char(first) {
        return None;
    }
    // Stop at first whitespace to drop trailing words like
    // `# v3.5.2 (pinned)`.
    let body = trimmed
        .split(char::is_whitespace)
        .next()
        .unwrap_or(trimmed)
        .to_string();
    if body.is_empty() { None } else { Some(body) }
}

fn parse_uses_value(raw: &str) -> UsesReference {
    let raw_string = raw.to_string();
    if let Some(stripped) = raw.strip_prefix("docker://") {
        return UsesReference {
            raw: raw_string,
            kind: UsesKind::Docker,
            owner: None,
            repo: None,
            subpath: None,
            git_ref: stripped
                .rsplit_once(':')
                .map(|(_, tag)| tag.to_string())
                .or_else(|| Some(stripped.to_string())),
            is_sha_pinned: None,
            tag_comment: None,
        };
    }
    if raw.starts_with("./") || raw.starts_with("../") {
        return UsesReference {
            raw: raw_string,
            kind: UsesKind::Local,
            owner: None,
            repo: None,
            subpath: None,
            git_ref: None,
            is_sha_pinned: None,
            tag_comment: None,
        };
    }
    let (path_part, ref_part) = match raw.split_once('@') {
        Some((p, r)) => (p, Some(r.to_string())),
        None => (raw, None),
    };
    let mut path_segments = path_part.splitn(3, '/');
    let owner = path_segments.next().map(|s| s.to_string());
    let repo = path_segments.next().map(|s| s.to_string());
    let subpath = path_segments.next().map(|s| s.to_string());
    let is_sha_pinned = ref_part.as_ref().map(|r| is_full_sha(r));
    UsesReference {
        raw: raw_string,
        kind: UsesKind::Remote,
        owner,
        repo,
        subpath,
        git_ref: ref_part,
        is_sha_pinned,
        tag_comment: None,
    }
}

fn is_full_sha(value: &str) -> bool {
    value.len() == 40 && value.chars().all(|c| c.is_ascii_hexdigit())
}
