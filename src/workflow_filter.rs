//! Workflow filter — narrows the set of workflow files the Validator runs.
//!
//! Default policy: include only workflows whose `on:` block declares a
//! `pull_request` trigger. An impact analyzer wants to exercise the CI
//! suite that runs against pull requests — that's the ground truth for
//! "is this safe to merge?". Deploy/release/schedule workflows target
//! main or fire on a clock and would produce false negatives at best,
//! destructive side effects at worst.
//!
//! Overrides:
//! - `--include-workflow <glob>` always include matching workflows
//!   regardless of trigger
//! - `--exclude-workflow <glob>` always exclude matching workflows
//!   (takes precedence over `--include-workflow`)
//! - `--no-workflow-filter` disable the trigger check entirely
//!
//! Unparseable YAML defaults to *included* — over-running is a less
//! surprising failure than silently dropping a workflow the operator
//! expects to be validated. The Reporter logs which workflows fell into
//! this path so the operator can investigate.

use std::path::{Path, PathBuf};

use regex::Regex;

/// Sentinel returned by [`parse_workflow_triggers`] when YAML parsing
/// fails. Distinct from a real `on:` value so [`WorkflowFilter`] can tell
/// "no triggers" from "couldn't read".
pub const UNPARSEABLE_SENTINEL: &str = "__assay_unparseable__";

#[derive(Debug, Clone)]
pub struct WorkflowFilter {
    /// When `true` (default), workflows must declare `pull_request` (or
    /// match an `include_globs` entry) to be kept. When `false`, every
    /// candidate workflow passes the trigger check.
    pub require_pull_request_trigger: bool,
    pub include_globs: Vec<String>,
    pub exclude_globs: Vec<String>,
}

impl Default for WorkflowFilter {
    fn default() -> Self {
        Self::pull_request_default()
    }
}

impl WorkflowFilter {
    /// Default filter: `pull_request` triggers only, no overrides.
    pub fn pull_request_default() -> Self {
        Self {
            require_pull_request_trigger: true,
            include_globs: Vec::new(),
            exclude_globs: Vec::new(),
        }
    }

    /// No-op filter: every workflow passes. Used by `--no-workflow-filter`
    /// and by tests that don't want to construct a YAML fixture.
    pub fn accept_all() -> Self {
        Self {
            require_pull_request_trigger: false,
            include_globs: Vec::new(),
            exclude_globs: Vec::new(),
        }
    }

    /// Filter `workflows`, returning a new vec in the original order with
    /// excluded entries removed. `tree` is the workspace root used to
    /// resolve relative workflow paths when their YAML must be read.
    pub fn apply(&self, workflows: &[PathBuf], tree: &Path) -> Vec<PathBuf> {
        let exclude_res: Vec<Regex> = self
            .exclude_globs
            .iter()
            .map(|g| glob_to_regex(g))
            .collect();
        let include_res: Vec<Regex> = self
            .include_globs
            .iter()
            .map(|g| glob_to_regex(g))
            .collect();

        let mut out = Vec::with_capacity(workflows.len());
        for workflow in workflows {
            if path_matches_any(workflow, &exclude_res) {
                continue;
            }
            if path_matches_any(workflow, &include_res) {
                out.push(workflow.clone());
                continue;
            }
            if !self.require_pull_request_trigger {
                out.push(workflow.clone());
                continue;
            }
            let absolute = if workflow.is_absolute() {
                workflow.clone()
            } else {
                tree.join(workflow)
            };
            let triggers = match std::fs::read_to_string(&absolute) {
                Ok(yaml) => parse_workflow_triggers(&yaml),
                Err(_) => vec![UNPARSEABLE_SENTINEL.to_string()],
            };
            if triggers
                .iter()
                .any(|t| t == "pull_request" || t == UNPARSEABLE_SENTINEL)
            {
                out.push(workflow.clone());
            }
        }
        out
    }
}

/// Extract trigger names from a workflow YAML's `on:` block.
///
/// Handles the four canonical shapes:
/// 1. scalar: `on: push`
/// 2. sequence: `on: [push, pull_request]`
/// 3. mapping (bare keys): `on:\n  push:\n  pull_request:`
/// 4. mapping (keys with sub-config): `on:\n  pull_request:\n    types: [opened]`
///
/// Returns `[UNPARSEABLE_SENTINEL]` on YAML parse errors so the caller can
/// distinguish "couldn't read" from "no triggers".
pub fn parse_workflow_triggers(yaml: &str) -> Vec<String> {
    let value: serde_yml::Value = match serde_yml::from_str(yaml) {
        Ok(v) => v,
        Err(_) => return vec![UNPARSEABLE_SENTINEL.to_string()],
    };
    match on_node(&value) {
        Some(on) => triggers_from_value(on),
        None => Vec::new(),
    }
}

fn on_node(root: &serde_yml::Value) -> Option<&serde_yml::Value> {
    let mapping = root.as_mapping()?;
    // YAML 1.1 parsers coerce bare `on:` keys into the boolean `true`
    // (yes/no/on/off all alias to bool there). GitHub Actions YAML files
    // frequently use the bare form, so look up both spellings.
    mapping
        .get(serde_yml::Value::String("on".into()))
        .or_else(|| mapping.get(serde_yml::Value::Bool(true)))
}

fn triggers_from_value(value: &serde_yml::Value) -> Vec<String> {
    if let Some(s) = value.as_str() {
        return vec![s.to_string()];
    }
    if let Some(seq) = value.as_sequence() {
        return seq
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
    }
    if let Some(map) = value.as_mapping() {
        return map
            .keys()
            .filter_map(|k| k.as_str().map(str::to_string))
            .collect();
    }
    Vec::new()
}

fn glob_to_regex(glob: &str) -> Regex {
    let mut out = String::from("^");
    for ch in glob.chars() {
        match ch {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '\\' | '^' | '$' | '|' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out.push('$');
    // Invariant: every char is either escaped or maps to a valid regex
    // construct, so compilation never fails.
    Regex::new(&out).expect("glob_to_regex always produces a valid regex")
}

fn path_matches_any(path: &Path, patterns: &[Regex]) -> bool {
    if patterns.is_empty() {
        return false;
    }
    let basename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let full = path.to_string_lossy();
    let full_alt = full.replace('\\', "/");
    patterns
        .iter()
        .any(|re| re.is_match(basename) || re.is_match(full.as_ref()) || re.is_match(&full_alt))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // parse_workflow_triggers
    // -------------------------------------------------------------------------

    #[test]
    fn parse_triggers_scalar_form() {
        let yaml = "name: CI\non: push\njobs: {}\n";
        let triggers = parse_workflow_triggers(yaml);
        assert_eq!(triggers, vec!["push".to_string()]);
    }

    #[test]
    fn parse_triggers_sequence_form() {
        let yaml = "name: CI\non: [push, pull_request]\njobs: {}\n";
        let triggers = parse_workflow_triggers(yaml);
        assert_eq!(
            triggers,
            vec!["push".to_string(), "pull_request".to_string()]
        );
    }

    #[test]
    fn parse_triggers_mapping_form_bare_keys() {
        let yaml = "name: CI\non:\n  push:\n  pull_request:\njobs: {}\n";
        let triggers = parse_workflow_triggers(yaml);
        // Mapping iteration is insertion-ordered for serde_yml's Mapping,
        // but assertions check membership rather than order to avoid being
        // brittle if the dependency's iteration semantics change.
        assert!(triggers.iter().any(|t| t == "push"));
        assert!(triggers.iter().any(|t| t == "pull_request"));
    }

    #[test]
    fn parse_triggers_mapping_form_with_sub_config() {
        let yaml = "name: CI\non:\n  pull_request:\n    types: [opened, synchronize]\njobs: {}\n";
        let triggers = parse_workflow_triggers(yaml);
        assert_eq!(triggers, vec!["pull_request".to_string()]);
    }

    #[test]
    fn parse_triggers_quoted_on_key_is_recognized() {
        // Quoted key avoids YAML 1.1 bool coercion. Some hand-written
        // workflows do this to defend against legacy parsers — assay must
        // still recognize it.
        let yaml = "name: CI\n\"on\":\n  pull_request: null\njobs: {}\n";
        let triggers = parse_workflow_triggers(yaml);
        assert_eq!(triggers, vec!["pull_request".to_string()]);
    }

    #[test]
    fn parse_triggers_returns_unparseable_sentinel_on_invalid_yaml() {
        let triggers = parse_workflow_triggers("name: : :\nthis: is: invalid\n");
        assert_eq!(triggers, vec![UNPARSEABLE_SENTINEL.to_string()]);
    }

    #[test]
    fn parse_triggers_returns_empty_when_on_block_absent() {
        let yaml = "name: CI\njobs: {}\n";
        let triggers = parse_workflow_triggers(yaml);
        assert!(triggers.is_empty());
    }

    #[test]
    fn parse_triggers_handles_yaml_bool_on_key() {
        // If the operator's YAML parser collapses bare `on:` to `true:`,
        // the resulting Value mapping has Bool(true) as the key. The
        // helper must still find it.
        let mut mapping = serde_yml::Mapping::new();
        mapping.insert(
            serde_yml::Value::Bool(true),
            serde_yml::Value::String("push".into()),
        );
        let root = serde_yml::Value::Mapping(mapping);
        let on = on_node(&root).expect("Bool(true) key should be discovered");
        assert_eq!(triggers_from_value(on), vec!["push".to_string()]);
    }

    // -------------------------------------------------------------------------
    // WorkflowFilter::apply
    // -------------------------------------------------------------------------

    /// Write a workflow YAML under `tree/.github/workflows/<name>` and
    /// return its repo-relative path (the shape `gate_workflows` produces).
    fn write_workflow(tree: &Path, name: &str, yaml: &str) -> PathBuf {
        let dir = tree.join(".github").join("workflows");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), yaml).unwrap();
        PathBuf::from(".github/workflows").join(name)
    }

    #[test]
    fn default_filter_keeps_pull_request_only_workflow() {
        let tmp = tempfile::tempdir().unwrap();
        let pr_only = write_workflow(
            tmp.path(),
            "ci.yml",
            "name: CI\non: pull_request\njobs: {}\n",
        );
        let kept = WorkflowFilter::pull_request_default()
            .apply(std::slice::from_ref(&pr_only), tmp.path());
        assert_eq!(kept, vec![pr_only]);
    }

    #[test]
    fn default_filter_drops_push_only_workflow() {
        let tmp = tempfile::tempdir().unwrap();
        let push_only = write_workflow(
            tmp.path(),
            "deploy.yml",
            "name: deploy\non: push\njobs: {}\n",
        );
        let kept = WorkflowFilter::pull_request_default().apply(&[push_only], tmp.path());
        assert!(
            kept.is_empty(),
            "push-only workflow should be dropped by default"
        );
    }

    #[test]
    fn default_filter_drops_schedule_only_workflow() {
        let tmp = tempfile::tempdir().unwrap();
        let scheduled = write_workflow(
            tmp.path(),
            "nightly.yml",
            "name: nightly\non:\n  schedule:\n    - cron: '0 0 * * *'\njobs: {}\n",
        );
        let kept = WorkflowFilter::pull_request_default().apply(&[scheduled], tmp.path());
        assert!(kept.is_empty());
    }

    #[test]
    fn default_filter_drops_release_only_workflow() {
        let tmp = tempfile::tempdir().unwrap();
        let release = write_workflow(
            tmp.path(),
            "release.yml",
            "name: release\non:\n  release:\n    types: [published]\njobs: {}\n",
        );
        let kept = WorkflowFilter::pull_request_default().apply(&[release], tmp.path());
        assert!(kept.is_empty());
    }

    #[test]
    fn default_filter_keeps_workflow_with_pull_request_in_a_list() {
        let tmp = tempfile::tempdir().unwrap();
        let combo = write_workflow(
            tmp.path(),
            "ci.yml",
            "name: CI\non: [push, pull_request]\njobs: {}\n",
        );
        let kept =
            WorkflowFilter::pull_request_default().apply(std::slice::from_ref(&combo), tmp.path());
        assert_eq!(kept, vec![combo]);
    }

    #[test]
    fn default_filter_keeps_workflow_with_pull_request_in_mapping() {
        let tmp = tempfile::tempdir().unwrap();
        let combo = write_workflow(
            tmp.path(),
            "ci.yml",
            "name: CI\non:\n  push:\n    branches: [main]\n  pull_request:\n    types: [opened]\njobs: {}\n",
        );
        let kept =
            WorkflowFilter::pull_request_default().apply(std::slice::from_ref(&combo), tmp.path());
        assert_eq!(kept, vec![combo]);
    }

    #[test]
    fn exclude_glob_drops_matching_workflow_even_if_pull_request() {
        let tmp = tempfile::tempdir().unwrap();
        let workflow = write_workflow(
            tmp.path(),
            "smoke.yml",
            "name: smoke\non: pull_request\njobs: {}\n",
        );
        let filter = WorkflowFilter {
            exclude_globs: vec!["smoke.yml".into()],
            ..WorkflowFilter::pull_request_default()
        };
        let kept = filter.apply(&[workflow], tmp.path());
        assert!(kept.is_empty());
    }

    #[test]
    fn include_glob_keeps_matching_workflow_even_if_push_only() {
        let tmp = tempfile::tempdir().unwrap();
        let workflow = write_workflow(
            tmp.path(),
            "deploy.yml",
            "name: deploy\non: push\njobs: {}\n",
        );
        let filter = WorkflowFilter {
            include_globs: vec!["deploy.yml".into()],
            ..WorkflowFilter::pull_request_default()
        };
        let kept = filter.apply(std::slice::from_ref(&workflow), tmp.path());
        assert_eq!(kept, vec![workflow]);
    }

    #[test]
    fn exclude_takes_precedence_over_include() {
        let tmp = tempfile::tempdir().unwrap();
        let workflow = write_workflow(
            tmp.path(),
            "deploy.yml",
            "name: deploy\non: pull_request\njobs: {}\n",
        );
        let filter = WorkflowFilter {
            include_globs: vec!["*.yml".into()],
            exclude_globs: vec!["deploy.yml".into()],
            ..WorkflowFilter::pull_request_default()
        };
        let kept = filter.apply(&[workflow], tmp.path());
        assert!(kept.is_empty(), "exclude must win over include");
    }

    #[test]
    fn unparseable_yaml_defaults_to_included() {
        let tmp = tempfile::tempdir().unwrap();
        let bad = write_workflow(tmp.path(), "broken.yml", "name: : :\ninvalid: : :\n");
        let kept =
            WorkflowFilter::pull_request_default().apply(std::slice::from_ref(&bad), tmp.path());
        assert_eq!(
            kept,
            vec![bad],
            "unparseable workflows should be over-included, not silently dropped"
        );
    }

    #[test]
    fn missing_workflow_file_defaults_to_included() {
        let tmp = tempfile::tempdir().unwrap();
        let phantom = PathBuf::from(".github/workflows/nonexistent.yml");
        let kept = WorkflowFilter::pull_request_default()
            .apply(std::slice::from_ref(&phantom), tmp.path());
        assert_eq!(kept, vec![phantom]);
    }

    #[test]
    fn accept_all_keeps_everything() {
        let tmp = tempfile::tempdir().unwrap();
        let deploy = write_workflow(
            tmp.path(),
            "deploy.yml",
            "name: deploy\non: push\njobs: {}\n",
        );
        let ci = write_workflow(
            tmp.path(),
            "ci.yml",
            "name: CI\non: pull_request\njobs: {}\n",
        );
        let kept = WorkflowFilter::accept_all().apply(&[deploy.clone(), ci.clone()], tmp.path());
        assert_eq!(kept, vec![deploy, ci]);
    }

    #[test]
    fn glob_supports_star_wildcard() {
        let tmp = tempfile::tempdir().unwrap();
        let deploy_a = write_workflow(
            tmp.path(),
            "deploy-staging.yml",
            "name: a\non: push\njobs: {}\n",
        );
        let deploy_b = write_workflow(
            tmp.path(),
            "deploy-prod.yml",
            "name: b\non: push\njobs: {}\n",
        );
        let other = write_workflow(
            tmp.path(),
            "ci.yml",
            "name: ci\non: pull_request\njobs: {}\n",
        );
        let filter = WorkflowFilter {
            exclude_globs: vec!["deploy-*.yml".into()],
            ..WorkflowFilter::pull_request_default()
        };
        let kept = filter.apply(&[deploy_a, deploy_b, other.clone()], tmp.path());
        assert_eq!(kept, vec![other]);
    }

    #[test]
    fn include_glob_matches_both_basename_and_full_path() {
        let tmp = tempfile::tempdir().unwrap();
        let workflow = write_workflow(tmp.path(), "release.yml", "name: r\non: push\njobs: {}\n");
        // Basename match
        let filter_basename = WorkflowFilter {
            include_globs: vec!["release.yml".into()],
            ..WorkflowFilter::pull_request_default()
        };
        assert_eq!(
            filter_basename.apply(std::slice::from_ref(&workflow), tmp.path()),
            vec![workflow.clone()]
        );
        // Full-path match (use forward slashes; the matcher normalizes
        // backslashes so this works on Windows too).
        let filter_fullpath = WorkflowFilter {
            include_globs: vec![".github/workflows/release.yml".into()],
            ..WorkflowFilter::pull_request_default()
        };
        assert_eq!(
            filter_fullpath.apply(std::slice::from_ref(&workflow), tmp.path()),
            vec![workflow]
        );
    }

    #[test]
    fn filter_preserves_original_order() {
        let tmp = tempfile::tempdir().unwrap();
        let a = write_workflow(tmp.path(), "a.yml", "on: pull_request\njobs: {}\n");
        let b = write_workflow(tmp.path(), "b.yml", "on: pull_request\njobs: {}\n");
        let c = write_workflow(tmp.path(), "c.yml", "on: pull_request\njobs: {}\n");
        let kept = WorkflowFilter::pull_request_default()
            .apply(&[c.clone(), a.clone(), b.clone()], tmp.path());
        assert_eq!(kept, vec![c, a, b]);
    }
}
