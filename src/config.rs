//! `.assay.toml` parser.
//!
//! The config lives at the repo root and tells assay which
//! ecosystems are enabled, which workflows validate each kind of bump,
//! and which safety knobs to enforce on `--apply-remote`. When the file
//! is absent, every field uses the documented v1 default.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const CURRENT_SCHEMA_VERSION: u32 = 1;
const CONFIG_FILENAME: &str = ".assay.toml";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssayConfig {
    #[serde(rename = "assay")]
    pub meta: MetaSection,
    #[serde(default)]
    pub ecosystems: EcosystemsSection,
    #[serde(default, rename = "pull-request")]
    pub pull_request: PullRequestSection,
    #[serde(default)]
    pub validation: ValidationSection,
    #[serde(default)]
    pub safety: SafetySection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetaSection {
    pub schema_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcosystemsSection {
    #[serde(default = "default_cargo_ecosystem")]
    pub cargo: EcosystemEntry,
    #[serde(
        default = "default_github_actions_ecosystem",
        rename = "github-actions"
    )]
    pub github_actions: EcosystemEntry,
}

impl Default for EcosystemsSection {
    fn default() -> Self {
        Self {
            cargo: default_cargo_ecosystem(),
            github_actions: default_github_actions_ecosystem(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcosystemEntry {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// `"auto"` or a list of workflow paths. Parsed as a string-or-list
    /// surface; canonical form is a `Vec<PathBuf>` after resolution.
    #[serde(default)]
    pub validate_workflows: WorkflowSelection,
    #[serde(default)]
    pub grouping: Grouping,
    /// Only meaningful for the GitHub Actions ecosystem; ignored otherwise.
    #[serde(default)]
    pub allow_major: bool,
    /// Cap on concurrent WorkUnits processed for this ecosystem. Defaults
    /// to `1` for Cargo (defends against `.cargo/registry/.package-cache`
    /// MutateExclusive contention) and `0` (= unlimited, bounded only by
    /// `--threads`) for GitHub Actions and any future ecosystem without
    /// a known shared mutable resource. Set to `0` to opt into unlimited
    /// parallelism; any other value caps the per-ecosystem worker count.
    #[serde(default)]
    pub max_parallel: usize,
    /// Per-ecosystem ignore list. Entries match the proposer's `subject`
    /// field — for GitHub Actions that's `owner/repo` (e.g.
    /// `"actions/checkout"`), for cargo a crate name, for npm a package
    /// name. The proposer skips any aggregate / outdated row whose
    /// subject equals an entry in this list.
    ///
    /// Useful when an action publishes noisy prereleases, an operator
    /// intentionally pins below latest for compatibility reasons, or
    /// when assay's proposed bump is wrong for some local reason.
    #[serde(default)]
    pub ignore: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WorkflowSelection {
    Auto(String),
    Explicit(Vec<PathBuf>),
}

impl Default for WorkflowSelection {
    fn default() -> Self {
        WorkflowSelection::Auto("auto".into())
    }
}

impl WorkflowSelection {
    pub fn explicit(&self) -> Option<&[PathBuf]> {
        match self {
            WorkflowSelection::Auto(_) => None,
            WorkflowSelection::Explicit(paths) => Some(paths),
        }
    }

    pub fn is_auto(&self) -> bool {
        matches!(self, WorkflowSelection::Auto(value) if value == "auto")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Grouping {
    #[default]
    AllInOne,
    OnePerCrate,
    ByKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PullRequestSection {
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub reviewers: Vec<String>,
    #[serde(default)]
    pub draft: bool,
    #[serde(default = "default_body_template")]
    pub body_template: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationSection {
    #[serde(default)]
    pub executor: ValidationExecutor,
    #[serde(default)]
    pub on_unvalidated: OnUnvalidated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ValidationExecutor {
    #[default]
    Docker,
    Host,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum OnUnvalidated {
    #[default]
    OpenPrWithWarning,
    Skip,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetySection {
    #[serde(default = "default_true")]
    pub refuse_in_ci: bool,
    #[serde(default = "default_true")]
    pub refuse_dirty_tree: bool,
    #[serde(default = "default_true")]
    pub require_force_for_overrides: bool,
}

impl Default for SafetySection {
    fn default() -> Self {
        Self {
            refuse_in_ci: true,
            refuse_dirty_tree: true,
            require_force_for_overrides: true,
        }
    }
}

impl Default for AssayConfig {
    fn default() -> Self {
        Self {
            meta: MetaSection {
                schema_version: CURRENT_SCHEMA_VERSION,
            },
            ecosystems: EcosystemsSection {
                cargo: default_cargo_ecosystem(),
                github_actions: default_github_actions_ecosystem(),
            },
            pull_request: PullRequestSection {
                labels: vec!["assay".into(), "dependencies".into()],
                reviewers: Vec::new(),
                draft: false,
                body_template: default_body_template(),
            },
            validation: ValidationSection::default(),
            safety: SafetySection::default(),
        }
    }
}

fn default_cargo_ecosystem() -> EcosystemEntry {
    EcosystemEntry {
        enabled: true,
        validate_workflows: WorkflowSelection::Explicit(vec![PathBuf::from(
            ".github/workflows/ci.yml",
        )]),
        grouping: Grouping::AllInOne,
        allow_major: false,
        // Cargo's `.cargo/registry/.package-cache` is held in
        // `MutateExclusive` mode during `cargo update`; concurrent
        // updates serialize anyway and risk lockfile contention. Cap-of-1
        // is conservative but predictable.
        max_parallel: 1,
        ignore: Vec::new(),
    }
}

fn default_github_actions_ecosystem() -> EcosystemEntry {
    EcosystemEntry {
        enabled: true,
        validate_workflows: WorkflowSelection::default(),
        grouping: Grouping::AllInOne,
        allow_major: false,
        // GHA bump-application is pure file rewriting — no shared mutable
        // resource. Bounded only by `--threads`.
        max_parallel: 0,
        ignore: Vec::new(),
    }
}

fn default_body_template() -> String {
    "default".to_string()
}

const fn default_true() -> bool {
    true
}

/// Try to load `.assay.toml` from `repo`. If absent, returns the
/// documented v1 defaults. If present but invalid (bad TOML, unknown
/// key, wrong schema_version), returns an `InvalidConfig` error.
pub fn load(repo: &Path) -> Result<AssayConfig> {
    let path = repo.join(CONFIG_FILENAME);
    if !path.is_file() {
        return Ok(AssayConfig::default());
    }
    let text = std::fs::read_to_string(&path).map_err(|source| Error::Io {
        path: path.clone(),
        source,
    })?;
    parse(&text, &path)
}

/// Parse a config string with an explicit `source_path` for error context.
pub fn parse(text: &str, source_path: &Path) -> Result<AssayConfig> {
    let config: AssayConfig = toml::from_str(text).map_err(|source| Error::InvalidConfig {
        path: source_path.to_path_buf(),
        message: source.to_string(),
    })?;
    if config.meta.schema_version != CURRENT_SCHEMA_VERSION {
        return Err(Error::InvalidConfig {
            path: source_path.to_path_buf(),
            message: format!(
                "schema_version = {actual}; only schema_version = {expected} is supported in this release. See docs/assay-plan.md for the migration path.",
                actual = config.meta.schema_version,
                expected = CURRENT_SCHEMA_VERSION,
            ),
        });
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_when_file_is_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let config = load(tmp.path()).expect("should fall back to defaults");
        assert_eq!(config.meta.schema_version, CURRENT_SCHEMA_VERSION);
        assert!(config.ecosystems.cargo.enabled);
        assert!(config.ecosystems.github_actions.enabled);
        assert!(config.safety.refuse_in_ci);
        assert!(config.safety.refuse_dirty_tree);
        assert!(config.safety.require_force_for_overrides);
        assert_eq!(config.validation.executor, ValidationExecutor::Docker);
    }

    #[test]
    fn parses_full_config_round_trip() {
        let text = r#"
[assay]
schema_version = 1

[ecosystems.cargo]
enabled = true
validate_workflows = [".github/workflows/ci.yml"]
grouping = "all-in-one"

[ecosystems.github-actions]
enabled = false
validate_workflows = "auto"
grouping = "by-kind"
allow_major = true

[pull-request]
labels = ["assay"]
reviewers = ["matt"]
draft = true
body_template = "custom"

[validation]
executor = "host"
on_unvalidated = "fail"

[safety]
refuse_in_ci = false
refuse_dirty_tree = false
require_force_for_overrides = false
"#;
        let config = parse(text, Path::new(".assay.toml")).expect("parses ok");
        assert_eq!(config.meta.schema_version, 1);
        assert!(!config.ecosystems.github_actions.enabled);
        assert!(config.ecosystems.github_actions.allow_major);
        assert!(matches!(
            config.ecosystems.github_actions.grouping,
            Grouping::ByKind
        ));
        assert_eq!(config.pull_request.reviewers, vec!["matt".to_string()]);
        assert!(config.pull_request.draft);
        assert!(matches!(
            config.validation.executor,
            ValidationExecutor::Host
        ));
        assert!(matches!(
            config.validation.on_unvalidated,
            OnUnvalidated::Fail
        ));
        assert!(!config.safety.refuse_in_ci);
    }

    #[test]
    fn rejects_unknown_top_level_key() {
        let text = r#"
[assay]
schema_version = 1

[some-other-thing]
foo = "bar"
"#;
        let err =
            parse(text, Path::new(".assay.toml")).expect_err("unknown section must be rejected");
        assert!(matches!(err, Error::InvalidConfig { .. }), "got {err:?}");
    }

    #[test]
    fn rejects_unknown_field_inside_section() {
        let text = r#"
[assay]
schema_version = 1

[ecosystems.cargo]
enabled = true
mystery_field = "huh"
"#;
        let err =
            parse(text, Path::new(".assay.toml")).expect_err("unknown field must be rejected");
        assert!(matches!(err, Error::InvalidConfig { .. }));
    }

    #[test]
    fn rejects_wrong_schema_version() {
        let text = r#"
[assay]
schema_version = 99
"#;
        let err = parse(text, Path::new(".assay.toml"))
            .expect_err("schema_version != 1 must be rejected");
        match err {
            Error::InvalidConfig { message, .. } => {
                assert!(message.contains("schema_version = 99"));
                assert!(message.contains("docs/assay-plan.md"));
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    #[test]
    fn workflow_selection_auto_is_detected() {
        let text = r#"
[assay]
schema_version = 1

[ecosystems.cargo]
enabled = true
validate_workflows = "auto"
"#;
        let config = parse(text, Path::new(".assay.toml")).unwrap();
        assert!(config.ecosystems.cargo.validate_workflows.is_auto());
        assert!(
            config
                .ecosystems
                .cargo
                .validate_workflows
                .explicit()
                .is_none()
        );
    }

    #[test]
    fn workflow_selection_explicit_returns_paths() {
        let text = r#"
[assay]
schema_version = 1

[ecosystems.cargo]
enabled = true
validate_workflows = [".github/workflows/ci.yml", ".github/workflows/release.yml"]
"#;
        let config = parse(text, Path::new(".assay.toml")).unwrap();
        let paths = config
            .ecosystems
            .cargo
            .validate_workflows
            .explicit()
            .unwrap();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0], PathBuf::from(".github/workflows/ci.yml"));
    }

    #[test]
    fn parses_per_ecosystem_ignore_list() {
        let text = r#"
[assay]
schema_version = 1

[ecosystems.github-actions]
ignore = ["dtolnay/rust-toolchain", "actions/setup-deno"]

[ecosystems.cargo]
ignore = ["criterion"]
"#;
        let config = parse(text, Path::new(".assay.toml")).expect("ignore list parses");
        assert_eq!(
            config.ecosystems.github_actions.ignore,
            vec![
                "dtolnay/rust-toolchain".to_string(),
                "actions/setup-deno".to_string()
            ]
        );
        assert_eq!(
            config.ecosystems.cargo.ignore,
            vec!["criterion".to_string()]
        );
    }

    #[test]
    fn ignore_defaults_to_empty_when_absent() {
        let text = r#"
[assay]
schema_version = 1
"#;
        let config = parse(text, Path::new(".assay.toml")).unwrap();
        assert!(config.ecosystems.github_actions.ignore.is_empty());
        assert!(config.ecosystems.cargo.ignore.is_empty());
    }

    #[test]
    fn invalid_grouping_is_rejected() {
        let text = r#"
[assay]
schema_version = 1

[ecosystems.cargo]
enabled = true
grouping = "haphazard"
"#;
        let err = parse(text, Path::new(".assay.toml"))
            .expect_err("unknown grouping value must be rejected");
        assert!(matches!(err, Error::InvalidConfig { .. }));
    }
}
