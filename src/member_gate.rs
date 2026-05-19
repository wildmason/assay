//! Member-precise validator gating.
//!
//! When a workspace member-A is the only consumer of an upgraded dep,
//! running gate workflows that exclusively target member-B is wasted
//! CI time. This module scans each gate workflow for explicit
//! workspace-member selectors and classifies the workflow as:
//!
//! - **`KeepWildcard`** — uses `--workspace` / `--workspaces` / `-r`,
//!   so the workflow touches every member. Keep regardless.
//! - **`KeepNamesAffected`** — names at least one affected consumer
//!   (e.g. `-p crate-a` and crate-a appears in `affected_consumers`).
//! - **`KeepNoSelectors`** — has no member selectors at all
//!   (CWD-based, monolithic script, etc.). Keep conservatively —
//!   we can't tell what it touches without running it.
//! - **`DropOnlyOthers`** — every member selector found names a
//!   non-affected member. Safe to drop: the upgraded dep isn't
//!   consumed by any of those members, so the workflow can't observe
//!   the bump.
//!
//! The classification is a heuristic that biases toward **keeping**
//! workflows when uncertain — false positives (keeping more than
//! strictly necessary) are safe; false negatives (dropping a
//! workflow that DOES touch an affected member) would silently miss
//! regressions.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Result of scanning one workflow text for member selectors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowMembershipDecision {
    /// Workflow uses a wildcard selector (Cargo `--workspace` /
    /// `--all`, npm `--workspaces`, pnpm `-r` / `--recursive`,
    /// yarn berry `workspaces foreach`). Touches every member.
    KeepWildcard { token: String },
    /// Workflow names at least one affected consumer explicitly.
    KeepNamesAffected { matched: Vec<String> },
    /// Workflow has no recognizable member selectors. Could be a
    /// CWD-based invocation or a script we don't parse. Keep
    /// conservatively.
    KeepNoSelectors,
    /// Workflow names members but none of them are affected.
    DropOnlyOthers { non_affected: Vec<String> },
}

impl WorkflowMembershipDecision {
    pub fn should_keep(&self) -> bool {
        !matches!(self, WorkflowMembershipDecision::DropOnlyOthers { .. })
    }
}

/// Classify a workflow's relationship to a set of affected workspace
/// members.
///
/// `text` is the raw workflow YAML content. `affected` is the set of
/// workspace member names that consume the upgraded dependency
/// (from [`crate::model::Proposal::affected_consumers`]).
///
/// The scanner is regex-free and walks the text once. It recognises:
/// - Wildcards: `--workspace`, `--workspaces`, `--all`, `-r`,
///   `--recursive`, `workspaces foreach` (berry).
/// - Explicit selectors: Cargo `-p NAME`/`--package NAME`/`--package=NAME`,
///   npm `--workspace=NAME`/`--workspace NAME`, pnpm
///   `--filter NAME`/`--filter=NAME`, yarn `workspace NAME` (the yarn
///   subcommand shape).
///
/// Unknown selectors and scripts fall into `KeepNoSelectors`.
pub fn classify_workflow_membership(
    text: &str,
    affected: &BTreeSet<&str>,
) -> WorkflowMembershipDecision {
    if let Some(token) = scan_wildcard(text) {
        return WorkflowMembershipDecision::KeepWildcard { token };
    }

    let selectors = scan_member_selectors(text);
    if selectors.is_empty() {
        return WorkflowMembershipDecision::KeepNoSelectors;
    }

    let mut matched: Vec<String> = Vec::new();
    let mut non_affected: Vec<String> = Vec::new();
    for sel in &selectors {
        if affected.contains(sel.as_str()) {
            matched.push(sel.clone());
        } else {
            non_affected.push(sel.clone());
        }
    }
    matched.sort();
    matched.dedup();
    non_affected.sort();
    non_affected.dedup();
    if !matched.is_empty() {
        WorkflowMembershipDecision::KeepNamesAffected { matched }
    } else {
        WorkflowMembershipDecision::DropOnlyOthers { non_affected }
    }
}

/// Return the first wildcard token found in `text`, if any. Wildcard
/// tokens are package-manager flags that select every workspace
/// member.
fn scan_wildcard(text: &str) -> Option<String> {
    // Multi-word wildcards first — substring search is fine.
    for needle in &["--workspaces", "--all", "--recursive", "workspaces foreach"] {
        if text.contains(needle) {
            return Some((*needle).to_string());
        }
    }
    // Cargo `--workspace` is the wildcard when it appears WITHOUT a
    // value attached. The disambiguation rules:
    // - `--workspace ` followed by another flag (`--something`) is a wildcard.
    // - `--workspace ` followed by an alphanumeric token is the npm
    //   selector form (`npm test --workspace pkg-a`) — NOT a wildcard.
    // - `--workspace=foo` is a selector.
    // - `--workspaces` already matched above.
    // - End-of-string or end-of-line after `--workspace` is wildcard.
    let mut search_from = 0;
    while let Some(rel) = text[search_from..].find("--workspace") {
        let idx = search_from + rel;
        let after_idx = idx + "--workspace".len();
        let after = &text[after_idx..];
        // Reject `--workspaces` (the `s` continuation).
        let next = after.chars().next();
        if matches!(next, Some('s')) {
            search_from = after_idx;
            continue;
        }
        if matches!(next, Some('=')) {
            search_from = after_idx;
            continue;
        }
        // Tokenize what follows the whitespace. If the next non-
        // whitespace token starts with a letter/digit/@ it's the
        // selector form. If it starts with `-` (another flag) or
        // the line ends, treat as wildcard.
        let trimmed = after.trim_start_matches([' ', '\t']);
        let first_non_ws = trimmed.chars().next();
        match first_non_ws {
            None | Some('\n') | Some('\r') => return Some("--workspace".to_string()),
            Some('-') => return Some("--workspace".to_string()),
            Some(c) if c.is_alphanumeric() || c == '@' || c == '_' => {
                // Selector form — keep scanning for another `--workspace`
                // occurrence (rare but possible).
                search_from = after_idx;
                continue;
            }
            _ => return Some("--workspace".to_string()),
        }
    }
    // pnpm `-r` is short enough that a substring match would have a
    // very high false-positive rate (literally any letter `r`
    // preceded by `-`). Match it only when isolated by whitespace.
    if find_token(text, "-r") {
        return Some("-r".to_string());
    }
    None
}

/// Whether `needle` appears in `text` surrounded by ASCII whitespace
/// or string boundaries.
fn find_token(text: &str, needle: &str) -> bool {
    let nlen = needle.len();
    let bytes = text.as_bytes();
    let mut idx = 0;
    while idx + nlen <= bytes.len() {
        if &bytes[idx..idx + nlen] == needle.as_bytes() {
            let before_ok =
                idx == 0 || matches!(bytes[idx - 1], b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'');
            let after_idx = idx + nlen;
            let after_ok = after_idx == bytes.len()
                || matches!(
                    bytes[after_idx],
                    b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\''
                );
            if before_ok && after_ok {
                return true;
            }
        }
        idx += 1;
    }
    false
}

/// Extract every workspace-member name targeted by an explicit
/// selector in `text`. Output is unsorted; the caller dedups +
/// classifies. Scans for these selector shapes:
///
/// - Cargo: `-p NAME`, `-pNAME`, `--package NAME`, `--package=NAME`
/// - npm:   `--workspace NAME`, `--workspace=NAME`
/// - pnpm:  `--filter NAME`, `--filter=NAME`
/// - yarn:  `workspace NAME` (the subcommand form)
///
/// Names may be scoped (`@scope/pkg`). The scanner stops at the next
/// whitespace, quote, or end-of-line.
fn scan_member_selectors(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        push_selectors_from_line(line, &mut out);
    }
    out
}

fn push_selectors_from_line(line: &str, out: &mut Vec<String>) {
    // Compact spaces around `=` so `--package=foo` and `--package foo`
    // are handled by one extraction pass.
    let line = line.trim();
    let line_lc = line.to_ascii_lowercase();
    // Spawn helper closures.
    let push_after_token = |token: &str, line: &str, out: &mut Vec<String>| {
        let mut start = 0;
        while let Some(idx) = line[start..].find(token) {
            let abs = start + idx;
            let before_ok =
                abs == 0 || matches!(line.as_bytes()[abs - 1], b' ' | b'\t' | b'"' | b'\'');
            if !before_ok {
                start = abs + token.len();
                continue;
            }
            let after = &line[abs + token.len()..];
            if let Some(name) = take_selector_value(after) {
                out.push(name);
            }
            start = abs + token.len();
        }
    };
    push_after_token("-p ", line, out);
    push_after_token("--package ", line, out);
    push_after_token("--package=", line, out);
    push_after_token("--workspace=", line, out);
    push_after_token("--filter ", line, out);
    push_after_token("--filter=", line, out);
    // `--workspace ` (with space) selector — but ONLY if the next
    // token is not another flag. Skip wildcards (npm
    // `--workspaces foo` doesn't exist; `--workspace foo` is the
    // selector form).
    if line_lc.contains("--workspace ") {
        let mut start = 0;
        let needle = "--workspace ";
        while let Some(idx) = line[start..].find(needle) {
            let abs = start + idx;
            let after = &line[abs + needle.len()..];
            if let Some(name) = take_selector_value(after) {
                out.push(name);
            }
            start = abs + needle.len();
        }
    }
    // `-pNAME` (no space) — Cargo accepts it. Watch for the literal
    // `-p ` pattern above already, so this branch is the no-space
    // form. We require the next char to be alphanumeric / `@` /
    // `_` so `-pkg` is treated as a flag itself, not `-p` + `kg`.
    {
        let mut start = 0;
        let needle = "-p";
        while let Some(idx) = line[start..].find(needle) {
            let abs = start + idx;
            let before_ok =
                abs == 0 || matches!(line.as_bytes()[abs - 1], b' ' | b'\t' | b'"' | b'\'');
            if !before_ok {
                start = abs + needle.len();
                continue;
            }
            let after = &line[abs + needle.len()..];
            // Reject if first char after `-p` is whitespace (handled
            // by the earlier `-p ` extractor), `=` (would be `-p=`
            // which isn't real Cargo syntax), or `-` (separate flag
            // like `-pX-Y`).
            let next = after.chars().next();
            if matches!(next, Some(' ') | Some('\t') | Some('=') | Some('-') | None) {
                start = abs + needle.len();
                continue;
            }
            // First char must look like the start of a package
            // name: alphanumeric, underscore, or `@` for scoped npm
            // names. (Cargo crate names can't start with `@` but the
            // selector applies across ecosystems.)
            if !matches!(next, Some(c) if c.is_alphanumeric() || c == '@' || c == '_') {
                start = abs + needle.len();
                continue;
            }
            if let Some(name) = take_selector_value(after) {
                out.push(name);
            }
            start = abs + needle.len();
        }
    }
    // yarn `workspace NAME` subcommand. Match only when preceded by
    // `yarn ` so we don't pick up the `workspace:` protocol in
    // package.json fragments.
    if let Some(idx) = line_lc.find("yarn workspace ") {
        let after = &line[idx + "yarn workspace ".len()..];
        if let Some(name) = take_selector_value(after) {
            out.push(name);
        }
    }
}

/// Extract a package-name token from the start of `tail`. The token
/// ends at the first whitespace, comma, quote, semicolon, or end-of-
/// string. Returns `None` if the token is empty or starts with a `-`
/// (suggests we hit another flag).
fn take_selector_value(tail: &str) -> Option<String> {
    let tail = tail.trim_start_matches(['"', '\'']);
    let mut end = 0;
    for (i, ch) in tail.char_indices() {
        if ch.is_whitespace() || matches!(ch, ',' | '"' | '\'' | ';') {
            end = i;
            break;
        }
        end = i + ch.len_utf8();
    }
    let value = &tail[..end];
    if value.is_empty() || value.starts_with('-') {
        return None;
    }
    Some(value.to_string())
}

/// One workflow's filter outcome — what the classifier decided plus
/// the path that produced the decision. Used by the report so the
/// operator can see exactly which workflows were skipped.
#[derive(Debug, Clone)]
pub struct WorkflowFilterRecord {
    pub workflow: PathBuf,
    pub decision: WorkflowMembershipDecision,
}

/// Partition `workflows` into a `kept` set and a `dropped` set based
/// on `affected_consumers`. Walks each workflow file, reads its
/// content, runs [`classify_workflow_membership`], and routes to
/// the appropriate bucket.
///
/// Workflows we can't read (permission errors, missing files) are
/// kept conservatively — same rationale as `KeepNoSelectors`. The
/// I/O error is swallowed silently; the validator stage will surface
/// any genuine problem when it tries to use the workflow.
///
/// `tree` is the prepared sandbox directory; workflow paths are
/// resolved relative to it.
pub fn filter_workflows_by_member(
    tree: &Path,
    workflows: &[PathBuf],
    affected_consumers: &[String],
) -> (Vec<PathBuf>, Vec<WorkflowFilterRecord>) {
    let affected: BTreeSet<&str> = affected_consumers.iter().map(String::as_str).collect();
    let mut kept: Vec<PathBuf> = Vec::new();
    let mut dropped: Vec<WorkflowFilterRecord> = Vec::new();
    for workflow in workflows {
        let abs = if workflow.is_absolute() {
            workflow.clone()
        } else {
            tree.join(workflow)
        };
        let text = match std::fs::read_to_string(&abs) {
            Ok(t) => t,
            Err(_) => {
                kept.push(workflow.clone());
                continue;
            }
        };
        let decision = classify_workflow_membership(&text, &affected);
        if decision.should_keep() {
            kept.push(workflow.clone());
        } else {
            dropped.push(WorkflowFilterRecord {
                workflow: workflow.clone(),
                decision,
            });
        }
    }
    (kept, dropped)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn affected<'a>(names: &[&'a str]) -> BTreeSet<&'a str> {
        names.iter().copied().collect()
    }

    #[test]
    fn workspace_wildcard_returns_keep_wildcard() {
        let yaml = "      - run: cargo test --workspace\n";
        let decision = classify_workflow_membership(yaml, &affected(&["crate-a"]));
        assert!(matches!(
            decision,
            WorkflowMembershipDecision::KeepWildcard { .. }
        ));
        assert!(decision.should_keep());
    }

    #[test]
    fn pnpm_recursive_returns_keep_wildcard() {
        let yaml = "      - run: pnpm test -r\n";
        let decision = classify_workflow_membership(yaml, &affected(&["pkg-a"]));
        assert!(matches!(
            decision,
            WorkflowMembershipDecision::KeepWildcard { .. }
        ));
    }

    #[test]
    fn npm_workspaces_wildcard_returns_keep_wildcard() {
        let yaml = "      - run: npm test --workspaces\n";
        let decision = classify_workflow_membership(yaml, &affected(&["pkg-a"]));
        assert!(matches!(
            decision,
            WorkflowMembershipDecision::KeepWildcard { .. }
        ));
    }

    #[test]
    fn workspaces_foreach_returns_keep_wildcard() {
        let yaml = "      - run: yarn workspaces foreach run test\n";
        let decision = classify_workflow_membership(yaml, &affected(&["a"]));
        assert!(matches!(
            decision,
            WorkflowMembershipDecision::KeepWildcard { .. }
        ));
    }

    #[test]
    fn cargo_dash_p_with_affected_returns_keep_names_affected() {
        let yaml = "      - run: cargo test -p crate-a\n";
        let decision = classify_workflow_membership(yaml, &affected(&["crate-a"]));
        match decision {
            WorkflowMembershipDecision::KeepNamesAffected { matched } => {
                assert_eq!(matched, vec!["crate-a"]);
            }
            other => panic!("expected KeepNamesAffected, got {other:?}"),
        }
    }

    #[test]
    fn cargo_long_package_with_affected_returns_keep_names_affected() {
        let yaml = "      - run: cargo test --package crate-a\n";
        let decision = classify_workflow_membership(yaml, &affected(&["crate-a"]));
        assert!(matches!(
            decision,
            WorkflowMembershipDecision::KeepNamesAffected { .. }
        ));
    }

    #[test]
    fn cargo_long_package_equals_form_returns_keep_names_affected() {
        let yaml = "      - run: cargo test --package=crate-a\n";
        let decision = classify_workflow_membership(yaml, &affected(&["crate-a"]));
        assert!(matches!(
            decision,
            WorkflowMembershipDecision::KeepNamesAffected { .. }
        ));
    }

    #[test]
    fn cargo_dash_p_with_only_others_returns_drop() {
        let yaml = "      - run: cargo test -p crate-b\n";
        let decision = classify_workflow_membership(yaml, &affected(&["crate-a"]));
        assert!(!decision.should_keep());
        match decision {
            WorkflowMembershipDecision::DropOnlyOthers { non_affected } => {
                assert_eq!(non_affected, vec!["crate-b"]);
            }
            other => panic!("expected DropOnlyOthers, got {other:?}"),
        }
    }

    #[test]
    fn cargo_multiple_dash_p_keeps_when_any_match() {
        let yaml = "      - run: cargo test -p crate-a -p crate-c\n";
        let decision = classify_workflow_membership(yaml, &affected(&["crate-a"]));
        match decision {
            WorkflowMembershipDecision::KeepNamesAffected { matched } => {
                assert!(matched.contains(&"crate-a".to_string()));
            }
            other => panic!("expected KeepNamesAffected, got {other:?}"),
        }
    }

    #[test]
    fn cargo_multiple_dash_p_drops_when_none_match() {
        let yaml = "      - run: cargo test -p crate-b -p crate-c\n";
        let decision = classify_workflow_membership(yaml, &affected(&["crate-a"]));
        match decision {
            WorkflowMembershipDecision::DropOnlyOthers { non_affected } => {
                assert!(non_affected.contains(&"crate-b".to_string()));
                assert!(non_affected.contains(&"crate-c".to_string()));
            }
            other => panic!("expected DropOnlyOthers, got {other:?}"),
        }
    }

    #[test]
    fn no_selectors_returns_keep_no_selectors() {
        let yaml = "      - run: cargo test\n";
        let decision = classify_workflow_membership(yaml, &affected(&["crate-a"]));
        assert!(matches!(
            decision,
            WorkflowMembershipDecision::KeepNoSelectors
        ));
    }

    #[test]
    fn npm_workspace_equals_selector_returns_keep_names_affected() {
        let yaml = "      - run: npm test --workspace=pkg-a\n";
        let decision = classify_workflow_membership(yaml, &affected(&["pkg-a"]));
        assert!(matches!(
            decision,
            WorkflowMembershipDecision::KeepNamesAffected { .. }
        ));
    }

    #[test]
    fn npm_workspace_space_selector_drops_when_only_others() {
        let yaml = "      - run: npm test --workspace pkg-b\n";
        let decision = classify_workflow_membership(yaml, &affected(&["pkg-a"]));
        match decision {
            WorkflowMembershipDecision::DropOnlyOthers { non_affected } => {
                assert_eq!(non_affected, vec!["pkg-b"]);
            }
            other => panic!("expected DropOnlyOthers, got {other:?}"),
        }
    }

    #[test]
    fn pnpm_filter_with_affected_keeps() {
        let yaml = "      - run: pnpm --filter pkg-a test\n";
        let decision = classify_workflow_membership(yaml, &affected(&["pkg-a"]));
        assert!(matches!(
            decision,
            WorkflowMembershipDecision::KeepNamesAffected { .. }
        ));
    }

    #[test]
    fn pnpm_filter_equals_form_works() {
        let yaml = "      - run: pnpm --filter=pkg-a test\n";
        let decision = classify_workflow_membership(yaml, &affected(&["pkg-a"]));
        assert!(matches!(
            decision,
            WorkflowMembershipDecision::KeepNamesAffected { .. }
        ));
    }

    #[test]
    fn yarn_workspace_subcommand_matches() {
        let yaml = "      - run: yarn workspace pkg-a test\n";
        let decision = classify_workflow_membership(yaml, &affected(&["pkg-a"]));
        assert!(matches!(
            decision,
            WorkflowMembershipDecision::KeepNamesAffected { .. }
        ));
    }

    #[test]
    fn scoped_npm_package_names_match() {
        let yaml = "      - run: pnpm --filter @scope/pkg-a test\n";
        let decision = classify_workflow_membership(yaml, &affected(&["@scope/pkg-a"]));
        assert!(matches!(
            decision,
            WorkflowMembershipDecision::KeepNamesAffected { .. }
        ));
    }

    #[test]
    fn dash_r_alone_is_wildcard_not_dropped() {
        // Pnpm's `-r` flag is one of the more dangerous patterns to
        // detect — random `r` characters shouldn't trigger it. The
        // tokenizer requires it to be surrounded by whitespace.
        let yaml = "      - run: pnpm -r test\n";
        let decision = classify_workflow_membership(yaml, &affected(&["pkg-a"]));
        assert!(matches!(
            decision,
            WorkflowMembershipDecision::KeepWildcard { .. }
        ));
    }

    #[test]
    fn r_inside_word_is_not_dash_r() {
        // The token `-rrun` shouldn't trigger the `-r` wildcard.
        let yaml = "      - run: cargo build --target=x86_64-rrun\n";
        let decision = classify_workflow_membership(yaml, &affected(&["crate-a"]));
        // Should NOT be KeepWildcard.
        assert!(!matches!(
            decision,
            WorkflowMembershipDecision::KeepWildcard { .. }
        ));
    }

    #[test]
    fn workspace_substring_is_not_workspaces_wildcard_misfire() {
        // npm `--workspace=foo` (selector) shouldn't be misread as
        // the `--workspace` wildcard.
        let yaml = "      - run: npm test --workspace=other-pkg\n";
        let decision = classify_workflow_membership(yaml, &affected(&["pkg-a"]));
        // Should be DropOnlyOthers (selector for other-pkg only).
        assert!(matches!(
            decision,
            WorkflowMembershipDecision::DropOnlyOthers { .. }
        ));
    }

    #[test]
    fn multiline_workflow_aggregates_selectors() {
        let yaml = "\
jobs:
  a:
    steps:
      - run: cargo test -p crate-a
      - run: cargo build -p crate-b
";
        let decision = classify_workflow_membership(yaml, &affected(&["crate-a"]));
        // crate-a matches → KeepNamesAffected.
        match decision {
            WorkflowMembershipDecision::KeepNamesAffected { matched } => {
                assert!(matched.contains(&"crate-a".to_string()));
            }
            other => panic!("expected KeepNamesAffected, got {other:?}"),
        }
    }

    #[test]
    fn multiline_workflow_drops_when_no_match() {
        let yaml = "\
jobs:
  a:
    steps:
      - run: cargo test -p crate-b
      - run: cargo build -p crate-c
";
        let decision = classify_workflow_membership(yaml, &affected(&["crate-a"]));
        assert!(matches!(
            decision,
            WorkflowMembershipDecision::DropOnlyOthers { .. }
        ));
    }

    #[test]
    fn empty_affected_set_drops_all_explicit_selectors() {
        // When affected_consumers is empty (e.g. the dep isn't
        // declared in any workspace member), every explicit
        // selector points at a non-affected member by definition.
        let yaml = "      - run: cargo test -p crate-a\n";
        let decision = classify_workflow_membership(yaml, &affected(&[]));
        assert!(matches!(
            decision,
            WorkflowMembershipDecision::DropOnlyOthers { .. }
        ));
    }

    #[test]
    fn empty_affected_keeps_wildcard_workflows() {
        // Even with no affected members, a `--workspace` workflow
        // could still observe the bump (the dep IS in the workspace
        // root manifest, just not in any member's deps).
        let yaml = "      - run: cargo test --workspace\n";
        let decision = classify_workflow_membership(yaml, &affected(&[]));
        assert!(matches!(
            decision,
            WorkflowMembershipDecision::KeepWildcard { .. }
        ));
    }

    #[test]
    fn dash_p_no_space_form_matches() {
        // Cargo accepts `-pcrate-a` (no space). Our parser should
        // recognise this.
        let yaml = "      - run: cargo test -pcrate-a\n";
        let decision = classify_workflow_membership(yaml, &affected(&["crate-a"]));
        match decision {
            WorkflowMembershipDecision::KeepNamesAffected { matched } => {
                assert_eq!(matched, vec!["crate-a"]);
            }
            other => panic!("expected KeepNamesAffected, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // filter_workflows_by_member — file-aware end-to-end filter.
    // -------------------------------------------------------------------------

    #[test]
    fn filter_keeps_workspace_wildcard_workflows() {
        let tmp = tempfile::tempdir().unwrap();
        let wf_dir = tmp.path().join(".github/workflows");
        std::fs::create_dir_all(&wf_dir).unwrap();
        let wf = wf_dir.join("ci.yml");
        std::fs::write(
            &wf,
            "name: ci\non: pull_request\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo test --workspace\n",
        )
        .unwrap();
        let rel = PathBuf::from(".github/workflows/ci.yml");
        let (kept, dropped) = filter_workflows_by_member(
            tmp.path(),
            std::slice::from_ref(&rel),
            &["unrelated-member".to_string()],
        );
        assert_eq!(kept, vec![rel]);
        assert!(dropped.is_empty());
    }

    #[test]
    fn filter_drops_workflow_for_unrelated_member_only() {
        let tmp = tempfile::tempdir().unwrap();
        let wf_dir = tmp.path().join(".github/workflows");
        std::fs::create_dir_all(&wf_dir).unwrap();
        let wf = wf_dir.join("crate-b.yml");
        std::fs::write(
            &wf,
            "name: crate-b\non: pull_request\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo test -p crate-b\n",
        )
        .unwrap();
        let rel = PathBuf::from(".github/workflows/crate-b.yml");
        let (kept, dropped) = filter_workflows_by_member(
            tmp.path(),
            std::slice::from_ref(&rel),
            &["crate-a".to_string()],
        );
        assert!(kept.is_empty());
        assert_eq!(dropped.len(), 1);
        assert!(matches!(
            dropped[0].decision,
            WorkflowMembershipDecision::DropOnlyOthers { .. }
        ));
    }

    #[test]
    fn filter_keeps_when_workflow_unreadable() {
        let tmp = tempfile::tempdir().unwrap();
        // Workflow path that doesn't exist on disk — conservative
        // keep so the validator can surface the real problem.
        let rel = PathBuf::from(".github/workflows/missing.yml");
        let (kept, dropped) = filter_workflows_by_member(
            tmp.path(),
            std::slice::from_ref(&rel),
            &["crate-a".to_string()],
        );
        assert_eq!(kept, vec![rel]);
        assert!(dropped.is_empty());
    }

    #[test]
    fn filter_mixes_keep_and_drop_across_multiple_workflows() {
        let tmp = tempfile::tempdir().unwrap();
        let wf_dir = tmp.path().join(".github/workflows");
        std::fs::create_dir_all(&wf_dir).unwrap();
        std::fs::write(wf_dir.join("a.yml"), "      - run: cargo test -p crate-a\n").unwrap();
        std::fs::write(wf_dir.join("b.yml"), "      - run: cargo test -p crate-b\n").unwrap();
        std::fs::write(
            wf_dir.join("ws.yml"),
            "      - run: cargo test --workspace\n",
        )
        .unwrap();
        let rels = vec![
            PathBuf::from(".github/workflows/a.yml"),
            PathBuf::from(".github/workflows/b.yml"),
            PathBuf::from(".github/workflows/ws.yml"),
        ];
        let (kept, dropped) =
            filter_workflows_by_member(tmp.path(), &rels, &["crate-a".to_string()]);
        let kept_names: Vec<String> = kept
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(kept_names.contains(&"a.yml".to_string()));
        assert!(kept_names.contains(&"ws.yml".to_string()));
        assert!(!kept_names.contains(&"b.yml".to_string()));
        assert_eq!(dropped.len(), 1);
        assert_eq!(
            dropped[0].workflow,
            PathBuf::from(".github/workflows/b.yml")
        );
    }

    #[test]
    fn filter_with_empty_affected_keeps_workspace_wildcard() {
        // Even when no workspace member uses the dep directly (e.g.
        // the dep is in the workspace root deps only), a `--workspace`
        // workflow should still run — it builds everything against
        // the new dep version.
        let tmp = tempfile::tempdir().unwrap();
        let wf_dir = tmp.path().join(".github/workflows");
        std::fs::create_dir_all(&wf_dir).unwrap();
        std::fs::write(
            wf_dir.join("ws.yml"),
            "      - run: cargo test --workspace\n",
        )
        .unwrap();
        let rel = PathBuf::from(".github/workflows/ws.yml");
        let (kept, dropped) =
            filter_workflows_by_member(tmp.path(), std::slice::from_ref(&rel), &[]);
        assert_eq!(kept, vec![rel]);
        assert!(dropped.is_empty());
    }
}
