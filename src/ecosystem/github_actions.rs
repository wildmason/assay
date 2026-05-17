//! GitHub Actions ecosystem.
//!
//! Detects pinned `uses:` references in `.github/workflows/*.{yml,yaml}` and
//! `.github/actions/**/action.yml`. Each detected reference becomes a
//! `Manifest` entry with the parsed `owner/repo[/path]@<sha-or-ref>` shape
//! stored as metadata.
//!
//! v1 stops at detection — actual tag→SHA resolution and proposal
//! generation require Octocrab + the GitHub App auth flow which lands in
//! the Publisher slice (§H steps 5, 9).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::model::{Manifest, ManifestKind, Proposal, ValidationOutcome};

use super::{DependencyEcosystem, EcosystemContext, EcosystemName};

/// Parsed shape of a single `uses:` reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsesReference {
    /// The full string as it appears in the workflow (`owner/repo@ref` or
    /// `owner/repo/subpath@ref` or a local path like `./path/to/action`).
    pub raw: String,
    pub kind: UsesKind,
    /// Set only for `Remote` kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subpath: Option<String>,
    /// Everything after the `@`. May be a SHA, tag, or branch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    /// `Some(true)` if `git_ref` is a 40-char hex SHA; `Some(false)` if it
    /// is clearly something else (tag or branch); `None` if no git_ref.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_sha_pinned: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UsesKind {
    /// `owner/repo[/subpath]@ref`.
    Remote,
    /// `./path/to/action` (composite action checked in alongside the workflow).
    Local,
    /// `docker://image:tag` style.
    Docker,
}

#[derive(Debug, Default, Clone)]
pub struct GitHubActionsEcosystem;

impl DependencyEcosystem for GitHubActionsEcosystem {
    fn name(&self) -> &'static str {
        EcosystemName::GitHubActions.as_str()
    }

    fn detect_manifests(&self, repo: &Path) -> Result<Vec<Manifest>> {
        if !repo.is_dir() {
            return Err(Error::RepoNotFound(repo.to_path_buf()));
        }
        let mut out = Vec::new();
        let workflows_dir = repo.join(".github").join("workflows");
        if workflows_dir.is_dir() {
            for entry in std::fs::read_dir(&workflows_dir).map_err(|source| Error::Io {
                path: workflows_dir.clone(),
                source,
            })? {
                let entry = entry.map_err(|source| Error::Io {
                    path: workflows_dir.clone(),
                    source,
                })?;
                let path = entry.path();
                if !is_yaml(&path) {
                    continue;
                }
                if let Some(manifest) = workflow_to_manifest(&path, repo)? {
                    out.push(manifest);
                }
            }
        }
        let actions_dir = repo.join(".github").join("actions");
        if actions_dir.is_dir() {
            for entry in walk_composite_actions(&actions_dir)? {
                if let Some(manifest) = workflow_to_manifest(&entry, repo)? {
                    let mut m = manifest;
                    m.kind = ManifestKind::CompositeActionYaml;
                    out.push(m);
                }
            }
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    fn propose_updates(
        &self,
        _manifests: &[Manifest],
        _repo: &Path,
        _ctx: &EcosystemContext,
    ) -> Result<Vec<Proposal>> {
        // Implemented after Octocrab + GitHub App auth lands. v1 detection
        // surface ships first; proposal generation needs network access
        // to the GitHub REST API which is gated behind App credentials.
        Ok(Vec::new())
    }

    fn gate_workflows(&self, _proposal: &Proposal, _repo: &Path) -> Result<Vec<PathBuf>> {
        // A `uses:` bump only affects the workflows that reference it; the
        // Validator narrows the set after consulting `Proposal.manifest_paths`.
        Ok(Vec::new())
    }

    fn affected_consumers(
        &self,
        _proposal: &Proposal,
        _tree: &Path,
    ) -> Result<Vec<crate::model::ConsumerId>> {
        // GHA has no workspace-member axis — workflows live at the repo
        // root. The Reporter collapses to a flat single-project format.
        Ok(Vec::new())
    }

    fn copy_back(&self, proposal: &Proposal, _sandbox: &Path, host: &Path) -> Result<Vec<PathBuf>> {
        if !matches!(proposal.kind, crate::model::ProposalKind::ActionPin) {
            return Err(Error::other(format!(
                "GitHubActionsEcosystem expected ActionPin, got {:?}",
                proposal.kind
            )));
        }
        let mut modified = Vec::new();
        for manifest_path in &proposal.manifest_paths {
            let absolute = host.join(manifest_path);
            let original = std::fs::read_to_string(&absolute).map_err(|source| Error::Io {
                path: absolute.clone(),
                source,
            })?;
            // rewrite_uses_in_workflow refuses on `from` mismatch with a
            // clear error — that's the mid-flight-edit defense. We don't
            // need to compare sandbox vs host bytes here; the from-pin
            // check is sufficient.
            let rewritten = rewrite_uses_in_workflow(
                &original,
                &proposal.subject,
                &proposal.from,
                &proposal.to,
                proposal.notes.iter().find_map(|n| n.strip_prefix("tag:")),
            )
            .map_err(|err| {
                Error::other(format!(
                    "copy-back rejected for `{}`: the host workflow file at `{}` does not contain `{}@{}`. \
                     The file may have been edited between validation and apply-local. \
                     Re-run assay against the current tree, or revert the local edit.\n\
                     underlying error: {err}",
                    proposal.id,
                    absolute.display(),
                    proposal.subject,
                    proposal.from,
                ))
            })?;
            if rewritten != original {
                std::fs::write(&absolute, rewritten).map_err(|source| Error::Io {
                    path: absolute.clone(),
                    source,
                })?;
                modified.push(manifest_path.clone());
            }
        }
        Ok(modified)
    }

    fn apply_proposal(&self, proposal: &Proposal, tree_path: &Path) -> Result<()> {
        if !matches!(proposal.kind, crate::model::ProposalKind::ActionPin) {
            return Err(Error::other(format!(
                "GitHubActionsEcosystem expected ActionPin, got {:?}",
                proposal.kind
            )));
        }
        // Each affected workflow file is rewritten independently.
        for manifest_path in &proposal.manifest_paths {
            let absolute = tree_path.join(manifest_path);
            let original = std::fs::read_to_string(&absolute).map_err(|source| Error::Io {
                path: absolute.clone(),
                source,
            })?;
            let rewritten = rewrite_uses_in_workflow(
                &original,
                &proposal.subject,
                &proposal.from,
                &proposal.to,
                proposal.notes.iter().find_map(|n| n.strip_prefix("tag:")),
            )?;
            if rewritten != original {
                std::fs::write(&absolute, rewritten).map_err(|source| Error::Io {
                    path: absolute.clone(),
                    source,
                })?;
            }
        }
        Ok(())
    }

    fn pr_body_fragment(&self, proposal: &Proposal, outcome: &ValidationOutcome) -> String {
        format!(
            "- **{action}**: `{from}` → `{to}` ({classification})",
            action = proposal.subject,
            from = proposal.from,
            to = proposal.to,
            classification = outcome.classification.as_str(),
        )
    }
}

fn is_yaml(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    matches!(ext, "yml" | "yaml")
}

fn walk_composite_actions(actions_dir: &Path) -> Result<Vec<PathBuf>> {
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

fn workflow_to_manifest(path: &Path, repo: &Path) -> Result<Option<Manifest>> {
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
        let value = after_colon
            .split_once(|c: char| c.is_whitespace() || c == '#')
            .map(|(v, _)| v)
            .unwrap_or(after_colon);
        let trimmed = value.trim().trim_matches('"').trim_matches('\'');
        if trimmed.is_empty() {
            continue;
        }
        out.push(parse_uses_value(trimmed));
    }
    out
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
    }
}

fn is_full_sha(value: &str) -> bool {
    value.len() == 40 && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// Rewrite every `uses: <subject>@<from>` line to `uses: <subject>@<to>`
/// in a workflow YAML string. Updates the inline `# vX.Y.Z` comment to
/// match `version_tag` when one is provided. Preserves all surrounding
/// formatting — leading whitespace, indentation, dashes, list markers,
/// the colon-spacing after `uses:`, and any inline comment whitespace
/// before the `#`.
///
/// Returns the rewritten text. If no line matches, returns the input
/// unchanged (allowing the caller to skip the write).
///
/// `subject` is the `owner/repo[/subpath]` part (without the `@<ref>`).
/// `from` is the current pinned SHA (or tag/branch); `to` is the desired
/// commit SHA. The function requires `from` to match exactly — it will
/// NOT rewrite a line whose current ref doesn't match (defends against
/// double-application and out-of-sync proposals).
pub fn rewrite_uses_in_workflow(
    text: &str,
    subject: &str,
    from: &str,
    to: &str,
    version_tag: Option<&str>,
) -> Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut any_match = false;
    for raw_line in text.split_inclusive('\n') {
        let (line, terminator) = split_line_terminator(raw_line);
        let trimmed_leading = line.trim_start();
        let lead_len = line.len() - trimmed_leading.len();
        let leading = &line[..lead_len];

        // Accept both `uses: ...` and `- uses: ...` shapes.
        let (dash_prefix, after_dash) = match trimmed_leading.strip_prefix("- ") {
            Some(rest) => ("- ", rest.trim_start()),
            None => ("", trimmed_leading),
        };
        let after_uses = match after_dash.strip_prefix("uses:") {
            Some(rest) => rest,
            None => {
                out.push_str(raw_line);
                continue;
            }
        };
        // Capture the whitespace after `uses:` so we can reproduce it.
        let value_part = after_uses.trim_start();
        let space_after_uses = &after_uses[..after_uses.len() - value_part.len()];

        // Split off any inline comment.
        let (value_with_quotes, comment_segment) = match value_part.split_once('#') {
            Some((before, after)) => (before.trim_end(), Some(after)),
            None => (value_part.trim_end(), None),
        };
        // Strip quotes from the value so we can compare with subject@from.
        let (open_quote, close_quote, bare_value) = {
            let v = value_with_quotes;
            if let Some(inner) = v.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                ("\"", "\"", inner)
            } else if let Some(inner) = v.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
                ("'", "'", inner)
            } else {
                ("", "", v)
            }
        };
        let expected = format!("{subject}@{from}");
        if bare_value != expected {
            out.push_str(raw_line);
            continue;
        }
        any_match = true;
        let new_value = format!("{subject}@{to}");
        let new_comment = comment_segment.map(|after_hash| {
            let mut leading_ws = String::new();
            for ch in after_hash.chars() {
                if ch == ' ' || ch == '\t' {
                    leading_ws.push(ch);
                } else {
                    break;
                }
            }
            let comment_body = &after_hash[leading_ws.len()..];
            // If the existing comment looks like a version tag (e.g.
            // `v1.2.3` or `1.2.3`) AND we have a fresh tag to substitute,
            // replace it. Otherwise leave the comment untouched.
            let looks_like_version = !comment_body.is_empty()
                && comment_body.chars().next().is_some_and(is_version_char);
            if let (Some(tag), true) = (version_tag, looks_like_version) {
                format!("#{leading_ws}{tag}")
            } else {
                format!("#{leading_ws}{comment_body}")
            }
        });

        let mut rewritten = String::new();
        rewritten.push_str(leading);
        rewritten.push_str(dash_prefix);
        rewritten.push_str("uses:");
        rewritten.push_str(space_after_uses);
        rewritten.push_str(open_quote);
        rewritten.push_str(&new_value);
        rewritten.push_str(close_quote);
        if let Some(comment) = new_comment {
            // Preserve the single space that typically separates value from `#`.
            rewritten.push(' ');
            rewritten.push_str(comment.trim_end());
        }
        rewritten.push_str(terminator);
        out.push_str(&rewritten);
    }
    if !any_match {
        return Err(Error::other(format!(
            "rewrite_uses_in_workflow: no `uses:` line matched `{subject}@{from}`; bump may have been pre-applied or proposal is stale"
        )));
    }
    Ok(out)
}

fn split_line_terminator(raw: &str) -> (&str, &str) {
    if let Some(stripped) = raw.strip_suffix("\r\n") {
        (stripped, "\r\n")
    } else if let Some(stripped) = raw.strip_suffix('\n') {
        (stripped, "\n")
    } else if let Some(stripped) = raw.strip_suffix('\r') {
        (stripped, "\r")
    } else {
        (raw, "")
    }
}

fn is_version_char(ch: char) -> bool {
    ch == 'v' || ch == 'V' || ch.is_ascii_digit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_uses_picks_simple_sha_pin() {
        let yaml = r#"
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567 # v4
      - run: echo hi
"#;
        let refs = collect_uses_references(yaml);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].owner.as_deref(), Some("actions"));
        assert_eq!(refs[0].repo.as_deref(), Some("checkout"));
        assert_eq!(
            refs[0].git_ref.as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
        assert_eq!(refs[0].is_sha_pinned, Some(true));
        assert_eq!(refs[0].kind, UsesKind::Remote);
    }

    #[test]
    fn collect_uses_picks_tag_ref_unpinned() {
        let yaml = "      - uses: actions/setup-node@v4\n";
        let refs = collect_uses_references(yaml);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].git_ref.as_deref(), Some("v4"));
        assert_eq!(refs[0].is_sha_pinned, Some(false));
    }

    #[test]
    fn collect_uses_handles_quoted_value() {
        let yaml = r#"  - uses: "actions/checkout@v4""#;
        let refs = collect_uses_references(yaml);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].owner.as_deref(), Some("actions"));
        assert_eq!(refs[0].repo.as_deref(), Some("checkout"));
        assert_eq!(refs[0].git_ref.as_deref(), Some("v4"));
    }

    #[test]
    fn collect_uses_handles_subpath() {
        let yaml = "      - uses: my/monorepo/sub/action@v1\n";
        let refs = collect_uses_references(yaml);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].owner.as_deref(), Some("my"));
        assert_eq!(refs[0].repo.as_deref(), Some("monorepo"));
        assert_eq!(refs[0].subpath.as_deref(), Some("sub/action"));
    }

    #[test]
    fn collect_uses_picks_local_action() {
        let yaml = "      - uses: ./.github/actions/my-action\n";
        let refs = collect_uses_references(yaml);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].kind, UsesKind::Local);
        assert!(refs[0].git_ref.is_none());
    }

    #[test]
    fn collect_uses_picks_docker_action() {
        let yaml = "      - uses: docker://alpine:3.18\n";
        let refs = collect_uses_references(yaml);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].kind, UsesKind::Docker);
        assert_eq!(refs[0].git_ref.as_deref(), Some("3.18"));
    }

    #[test]
    fn collect_uses_strips_inline_comments() {
        let yaml = "      - uses: actions/checkout@v4   # v4.0.0\n";
        let refs = collect_uses_references(yaml);
        assert_eq!(refs.len(), 1);
        // The trailing comment was correctly excluded from the parsed value.
        assert_eq!(refs[0].git_ref.as_deref(), Some("v4"));
    }

    #[test]
    fn collect_uses_finds_multiple() {
        let yaml = r#"
jobs:
  a:
    steps:
      - uses: actions/checkout@v4
  b:
    steps:
      - uses: actions/setup-node@v5
      - uses: ./.github/actions/local
"#;
        let refs = collect_uses_references(yaml);
        assert_eq!(refs.len(), 3);
    }

    #[test]
    fn detect_manifests_lists_workflows_with_uses() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        let workflows = repo.join(".github").join("workflows");
        std::fs::create_dir_all(&workflows).unwrap();
        std::fs::write(
            workflows.join("ci.yml"),
            "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n",
        )
        .unwrap();
        std::fs::write(
            workflows.join("empty.yml"),
            "name: empty\non: workflow_dispatch\n",
        )
        .unwrap();
        let eco = GitHubActionsEcosystem;
        let manifests = eco.detect_manifests(repo).unwrap();
        assert_eq!(
            manifests.len(),
            1,
            "only workflows with `uses:` produce a manifest"
        );
        assert!(manifests[0].path.ends_with("ci.yml"));
    }

    // ---- byte-range uses: rewriter ----

    const OLD: &str = "0123456789abcdef0123456789abcdef01234567";
    const NEW: &str = "fedcba9876543210fedcba9876543210fedcba98";

    #[test]
    fn rewriter_updates_sha_pinned_line() {
        let yaml = format!("      - uses: actions/checkout@{OLD} # v4\n");
        let out = rewrite_uses_in_workflow(&yaml, "actions/checkout", OLD, NEW, Some("v4.1.0"))
            .expect("rewrite ok");
        let expected = format!("      - uses: actions/checkout@{NEW} # v4.1.0\n");
        assert_eq!(out, expected);
    }

    #[test]
    fn rewriter_preserves_unrelated_whitespace_and_lines() {
        let yaml = format!(
            "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@{OLD}\n      - run: echo hi\n"
        );
        let out = rewrite_uses_in_workflow(&yaml, "actions/checkout", OLD, NEW, None)
            .expect("rewrite ok");
        // Every line BUT the uses: line should be byte-identical.
        for (orig_line, new_line) in yaml.lines().zip(out.lines()) {
            if orig_line.contains("uses:") {
                continue;
            }
            assert_eq!(orig_line, new_line, "non-uses line was mutated");
        }
        // And the uses: line should now reference NEW.
        assert!(out.contains(&format!("actions/checkout@{NEW}")));
        assert!(!out.contains(OLD));
    }

    #[test]
    fn rewriter_preserves_inline_comment_when_no_version_tag() {
        // Without a fresh tag, the comment body is left exactly as-is.
        let yaml = format!("  - uses: actions/checkout@{OLD}   # pinned 2026-05-01\n");
        let out = rewrite_uses_in_workflow(&yaml, "actions/checkout", OLD, NEW, None).unwrap();
        assert!(out.contains("# pinned 2026-05-01"));
    }

    #[test]
    fn rewriter_handles_quoted_values() {
        let yaml = format!("  - uses: \"actions/checkout@{OLD}\"\n");
        let out = rewrite_uses_in_workflow(&yaml, "actions/checkout", OLD, NEW, None).unwrap();
        // Quote style preserved.
        assert!(out.contains(&format!("\"actions/checkout@{NEW}\"")));
    }

    #[test]
    fn rewriter_handles_single_quoted_values() {
        let yaml = format!("  - uses: 'actions/checkout@{OLD}'\n");
        let out = rewrite_uses_in_workflow(&yaml, "actions/checkout", OLD, NEW, None).unwrap();
        assert!(out.contains(&format!("'actions/checkout@{NEW}'")));
    }

    #[test]
    fn rewriter_handles_subpath() {
        let yaml = format!("  - uses: my/monorepo/sub/action@{OLD}\n");
        let out =
            rewrite_uses_in_workflow(&yaml, "my/monorepo/sub/action", OLD, NEW, None).unwrap();
        assert!(out.contains(&format!("my/monorepo/sub/action@{NEW}")));
    }

    #[test]
    fn rewriter_rejects_when_from_does_not_match() {
        // Defense against double-application or stale proposal.
        let yaml = format!("  - uses: actions/checkout@{NEW}\n");
        let err = rewrite_uses_in_workflow(&yaml, "actions/checkout", OLD, NEW, None);
        assert!(err.is_err(), "rewriter must refuse when from doesn't match");
    }

    #[test]
    fn rewriter_handles_crlf_line_endings() {
        let yaml = format!("  - uses: actions/checkout@{OLD}\r\n  - run: echo hi\r\n");
        let out = rewrite_uses_in_workflow(&yaml, "actions/checkout", OLD, NEW, None).unwrap();
        assert!(
            out.contains("\r\n"),
            "CRLF terminator must be preserved: {out:?}"
        );
        assert!(out.contains(&format!("@{NEW}")));
    }

    #[test]
    fn rewriter_idempotent_when_applied_twice_is_an_error() {
        // First application succeeds.
        let yaml = format!("  - uses: actions/checkout@{OLD}\n");
        let after_one =
            rewrite_uses_in_workflow(&yaml, "actions/checkout", OLD, NEW, None).unwrap();
        // Second application of the same proposal must fail (the from
        // value no longer matches).
        let result = rewrite_uses_in_workflow(&after_one, "actions/checkout", OLD, NEW, None);
        assert!(result.is_err());
    }

    #[test]
    fn rewriter_does_not_touch_other_actions() {
        let yaml = format!(
            "  - uses: actions/checkout@{OLD}\n  - uses: actions/setup-node@v5\n  - uses: actions/cache@{OLD}\n"
        );
        let out = rewrite_uses_in_workflow(&yaml, "actions/checkout", OLD, NEW, None).unwrap();
        // Only the named subject was bumped; the other two are untouched.
        assert!(out.contains(&format!("actions/checkout@{NEW}")));
        assert!(out.contains("actions/setup-node@v5"));
        assert!(out.contains(&format!("actions/cache@{OLD}")));
    }

    #[test]
    fn rewriter_only_replaces_comment_when_it_looks_like_a_version() {
        // Comment that doesn't start with v/V/digit must be preserved.
        let yaml = format!("  - uses: actions/checkout@{OLD} # pinned-by-hand\n");
        let out =
            rewrite_uses_in_workflow(&yaml, "actions/checkout", OLD, NEW, Some("v4.2.0")).unwrap();
        assert!(
            out.contains("# pinned-by-hand"),
            "non-version comment must survive: {out}"
        );
    }

    #[test]
    fn integration_detect_then_apply_round_trip() {
        // Synthesize a tiny repo with one workflow pinned to an old SHA,
        // exercise the full ecosystem trait surface end-to-end: detect →
        // construct proposal → apply → verify file contents.
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        let workflows = repo.join(".github").join("workflows");
        std::fs::create_dir_all(&workflows).unwrap();
        let wf_path = workflows.join("ci.yml");
        let wf_content = format!(
            "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@{OLD} # v4\n      - run: echo ok\n"
        );
        std::fs::write(&wf_path, &wf_content).unwrap();

        let eco = GitHubActionsEcosystem;

        // 1. Detect manifests.
        let manifests = eco.detect_manifests(repo).unwrap();
        assert_eq!(manifests.len(), 1, "expected one workflow manifest");
        let manifest = &manifests[0];
        let uses_metadata = manifest
            .metadata
            .get("uses")
            .expect("uses metadata present");
        let parsed: Vec<UsesReference> = serde_json::from_value(uses_metadata.clone()).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].owner.as_deref(), Some("actions"));
        assert_eq!(parsed[0].repo.as_deref(), Some("checkout"));
        assert_eq!(parsed[0].is_sha_pinned, Some(true));

        // 2. Construct a Proposal as the future GHA proposer would.
        let proposal = crate::model::Proposal {
            id: "gha-actions-checkout-fedcba".into(),
            ecosystem: "github-actions".into(),
            kind: crate::model::ProposalKind::ActionPin,
            subject: "actions/checkout".into(),
            from: OLD.into(),
            to: NEW.into(),
            initial_classification: crate::model::Classification::Exact,
            manifest_paths: vec![manifest.path.clone()],
            notes: vec!["tag:v4.1.0".into()],
            bump_tier: crate::model::BumpTier::LockfileOnly,
        };

        // 3. Apply.
        eco.apply_proposal(&proposal, repo).expect("apply succeeds");

        // 4. Verify the workflow file was rewritten correctly.
        let updated = std::fs::read_to_string(&wf_path).unwrap();
        assert!(
            updated.contains(&format!("actions/checkout@{NEW}")),
            "new SHA must be present: {updated}"
        );
        assert!(!updated.contains(OLD), "old SHA must be gone: {updated}");
        assert!(
            updated.contains("# v4.1.0"),
            "inline comment must update to new tag: {updated}"
        );
        // Surrounding YAML structure is byte-identical (modulo the uses: line).
        for (orig_line, new_line) in wf_content.lines().zip(updated.lines()) {
            if orig_line.contains("uses:") {
                continue;
            }
            assert_eq!(orig_line, new_line);
        }
    }

    #[test]
    fn copy_back_rewrites_host_workflow_when_from_matches() {
        let host = tempfile::tempdir().unwrap();
        let sandbox = tempfile::tempdir().unwrap();
        let workflows = host.path().join(".github").join("workflows");
        std::fs::create_dir_all(&workflows).unwrap();
        let wf_path = workflows.join("ci.yml");
        let wf_content = format!(
            "name: ci\non: pull_request\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@{OLD}\n"
        );
        std::fs::write(&wf_path, &wf_content).unwrap();

        let proposal = crate::model::Proposal {
            id: "gha-actions-checkout-fedcba".into(),
            ecosystem: "github-actions".into(),
            kind: crate::model::ProposalKind::ActionPin,
            subject: "actions/checkout".into(),
            from: OLD.into(),
            to: NEW.into(),
            initial_classification: crate::model::Classification::Exact,
            manifest_paths: vec![PathBuf::from(".github/workflows/ci.yml")],
            notes: vec![],
            bump_tier: crate::model::BumpTier::LockfileOnly,
        };
        let eco = GitHubActionsEcosystem;
        let modified = eco
            .copy_back(&proposal, sandbox.path(), host.path())
            .expect("copy-back should succeed");
        assert_eq!(modified, vec![PathBuf::from(".github/workflows/ci.yml")]);
        let post = std::fs::read_to_string(&wf_path).unwrap();
        assert!(
            post.contains(&format!("actions/checkout@{NEW}")),
            "host workflow should carry the new SHA: {post}"
        );
    }

    #[test]
    fn copy_back_refuses_when_host_file_edited_mid_flight() {
        let host = tempfile::tempdir().unwrap();
        let sandbox = tempfile::tempdir().unwrap();
        let workflows = host.path().join(".github").join("workflows");
        std::fs::create_dir_all(&workflows).unwrap();
        let wf_path = workflows.join("ci.yml");
        // Host file no longer contains `from` — simulating an operator edit
        // that happened between sandbox-apply and copy-back. The rewriter's
        // from-mismatch defense should fire.
        let edited_content = "name: ci\non: pull_request\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4-unrelated-edit\n";
        std::fs::write(&wf_path, edited_content).unwrap();

        let proposal = crate::model::Proposal {
            id: "gha-actions-checkout-fedcba".into(),
            ecosystem: "github-actions".into(),
            kind: crate::model::ProposalKind::ActionPin,
            subject: "actions/checkout".into(),
            from: OLD.into(),
            to: NEW.into(),
            initial_classification: crate::model::Classification::Exact,
            manifest_paths: vec![PathBuf::from(".github/workflows/ci.yml")],
            notes: vec![],
            bump_tier: crate::model::BumpTier::LockfileOnly,
        };
        let eco = GitHubActionsEcosystem;
        let err = eco
            .copy_back(&proposal, sandbox.path(), host.path())
            .expect_err("from-mismatch should reject");
        let msg = err.to_string();
        assert!(
            msg.contains("copy-back rejected"),
            "error should call out copy-back rejection: {msg}"
        );
        assert!(
            msg.contains("between validation and apply-local"),
            "error should suggest the mid-flight-edit cause: {msg}"
        );
        // Host file should be UNCHANGED.
        let post = std::fs::read_to_string(&wf_path).unwrap();
        assert_eq!(post, edited_content);
    }

    #[test]
    fn detect_manifests_finds_composite_actions() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        let action_dir = repo.join(".github").join("actions").join("my-action");
        std::fs::create_dir_all(&action_dir).unwrap();
        std::fs::write(
            action_dir.join("action.yml"),
            "runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n",
        )
        .unwrap();
        let eco = GitHubActionsEcosystem;
        let manifests = eco.detect_manifests(repo).unwrap();
        assert_eq!(manifests.len(), 1);
        assert!(matches!(
            manifests[0].kind,
            ManifestKind::CompositeActionYaml
        ));
    }
}
