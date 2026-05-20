//! CLI argument types — the public clap surface of `assay`.
//!
//! Lives in its own submodule so the orchestration code in
//! [`super::analyze`] and friends stays focused on control flow
//! rather than flag bookkeeping. Anything tied to the stability
//! promise (`Cli`, `Command`, `AnalyzeArgs`) is re-exported from
//! [`crate::cli`] so external callers see the historical surface.

use std::path::PathBuf;

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "assay")]
#[command(
    about = "Dependency upgrade impact analyzer — test upgrades against your projects' real CI before you adopt them"
)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Analyze a repository for dependency upgrade impact; report per-proposal pass/fail.
    Analyze(AnalyzeArgs),
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("apply_mode")
        .args(["apply_local", "apply_pr", "validate"])
        .multiple(false)
))]
#[command(group(
    ArgGroup::new("gate_override")
        .args(["gate_cmd", "gate_file"])
        .multiple(false)
))]
pub struct AnalyzeArgs {
    /// Repository root to scan. Defaults to the current directory.
    #[arg(long, default_value = ".")]
    pub repo: PathBuf,

    /// Which ecosystems to scan. Defaults to all enabled in config.
    #[arg(long, value_enum)]
    pub ecosystem: Option<EcosystemSelector>,

    /// Run the validator stage on every proposal in an isolated sandbox
    /// and report per-proposal pass/fail — WITHOUT committing or opening
    /// PRs. The "test upgrades before adopting" mode. Mutually exclusive
    /// with `--apply-local` and `--apply-pr`.
    #[arg(long)]
    pub validate: bool,

    /// Write proposed bumps into an isolated retained worktree but do NOT open PRs.
    /// Mutually exclusive with --apply-pr.
    #[arg(long)]
    pub apply_local: bool,

    /// Open PR(s) on the remote forge. Refused when $CI is set, when the
    /// working tree is dirty, or when the push target is a protected
    /// branch — override with --force. Mutually exclusive with --apply-local.
    #[arg(long)]
    pub apply_pr: bool,

    /// Validate Cargo bumps on the host instead of inside Docker. Defeats
    /// the build-script-isolation default. Only use against repos whose
    /// transitive crate graph you fully audit.
    #[arg(long)]
    pub unsafe_host_validation: bool,

    /// Override the apply-pr safety refusals ($CI / dirty tree /
    /// protected branch). Logged as a top-level provenance record.
    #[arg(long)]
    pub force: bool,

    /// Executor used by the Validator stage.
    #[arg(long, value_enum, default_value = "docker")]
    pub executor: ExecutorChoice,

    /// Output format for terminal summaries.
    #[arg(long, value_enum, default_value = "text")]
    pub format: OutputFormat,

    /// Workflow path glob to always include, regardless of trigger.
    /// Repeatable. Match runs against the workflow's basename and its
    /// repo-relative path (forward-slash normalized).
    #[arg(long = "include-workflow", value_name = "GLOB")]
    pub include_workflows: Vec<String>,

    /// Workflow path glob to always exclude. Repeatable. Takes precedence
    /// over `--include-workflow`.
    #[arg(long = "exclude-workflow", value_name = "GLOB")]
    pub exclude_workflows: Vec<String>,

    /// Disable the default pull_request-trigger filter; run every
    /// workflow returned by the ecosystem. Use for projects whose CI
    /// suite isn't expressed via pull_request triggers.
    #[arg(long)]
    pub no_workflow_filter: bool,

    /// Override the auto-selected validator backend with an operator-
    /// supplied shell-line. Whitespace-split argv (no shell features —
    /// for pipes/redirection write a script and use `--gate-file`).
    /// Mutually exclusive with `--gate-file`. When set, `--executor` is
    /// silently ignored (CustomBackend bypasses forge entirely).
    #[arg(long = "gate-cmd", value_name = "SHELL_LINE")]
    pub gate_cmd: Option<String>,

    /// Override the auto-selected validator backend with a script.
    /// The script's shebang controls interpretation. Mutually exclusive
    /// with `--gate-cmd`. When set, `--executor` is silently ignored.
    #[arg(long = "gate-file", value_name = "PATH")]
    pub gate_file: Option<PathBuf>,

    /// Git remote to push to when `--apply-pr` is set. Defaults to `origin`.
    #[arg(long, default_value = "origin")]
    pub remote: String,

    /// Project entry point. Accepts a manifest file (e.g. `Cargo.toml`,
    /// `.github/workflows/ci.yml`) or a directory. With a manifest file,
    /// the file's repo root is inferred and only the matching ecosystem
    /// runs. With a directory, every configured ecosystem runs against it.
    /// Overrides `--repo` and any `--ecosystem` value.
    #[arg(long, value_name = "PATH")]
    pub project: Option<PathBuf>,

    /// Worker threads for the per-proposal apply+validate pipeline.
    /// Defaults to `min(4, available_parallelism())`. Cargo proposals
    /// stay capped at 1 concurrent worker by default (configurable via
    /// `.assay.toml [ecosystems.cargo] max_parallel`).
    #[arg(long, value_name = "N")]
    pub threads: Option<usize>,

    /// Stop dispatching new proposals after the first non-success outcome.
    /// In-flight proposals run to completion. Default is run-all-and-report.
    #[arg(long)]
    pub fail_fast: bool,

    /// Suppress SHA-pin hardening proposals for tag-pinned GitHub
    /// Actions references. By default, every `actions/foo@vN` pin
    /// also gets a "pin to SHA at `vN.M.P`" proposal so workflows
    /// can adopt the supply-chain-hardened form
    /// (`actions/foo@<sha> # vN.M.P`). Set this when an operator
    /// deliberately prefers tag pins for readability and doesn't
    /// want the extra proposals in the report. Has no effect on
    /// actions that are ALREADY SHA-pinned — those get the normal
    /// SHA-to-SHA bump proposal regardless.
    #[arg(long = "no-sha-pin-proposals")]
    pub no_sha_pin_proposals: bool,

    /// Suppress the per-ecosystem manifest-detection breadcrumbs
    /// (`[npm] manifests detected: N`, `[cargo] manifests detected:
    /// M`, etc.) and the per-proposal `proposal <id>: ...` lines.
    /// The bottom-of-run summary + tier breakdown + per-tier detail
    /// section still print. Useful when piping text output into
    /// another tool or when the breadcrumbs are too noisy. No effect
    /// on `--format json` (which already batches output to a single
    /// document at end-of-run).
    #[arg(long)]
    pub quiet: bool,

    /// Disable network calls during proposer phase. Network-bound
    /// ecosystems (currently: GitHub Actions, which resolves
    /// `uses:@SHA` against the latest release on github.com) fall
    /// back to whatever the action-store cache already holds —
    /// proposals are still emitted, but each is annotated with
    /// `source:offline-cache` and a "may be stale" note in the
    /// receipt. When no cache entry exists for an action, no
    /// proposal is emitted. Local-only ecosystems (Cargo, npm) are
    /// unaffected. Defaults to network-enabled.
    #[arg(long)]
    pub offline: bool,

    /// Bypass the action-store cache and force a fresh fetch for every
    /// GitHub API lookup. No effect in `--offline` mode (no source to
    /// refresh from). Default behavior: cache entries are served when
    /// fresh (< 7 days old) and re-fetched when stale.
    #[arg(long = "refresh-cache")]
    pub refresh_cache: bool,

    /// Suppress a specific proposal subject for this run, in addition to
    /// any `[ecosystems.<eco>] ignore = [...]` lists in `.assay.toml`.
    /// Format: `<ecosystem>:<subject>` (e.g. `cargo:reqwest` or
    /// `github-actions:actions/checkout`). Repeatable. CLI ignores are
    /// merged with — and never override — config-file ignores.
    #[arg(long = "ignore", value_name = "ECO:SUBJECT")]
    pub ignore: Vec<String>,

    /// Bypass the per-workflow verdict cache: every validator invocation
    /// runs the gate workflow fresh, and no entry is written. Use when
    /// you suspect a cached entry is stale beyond its TTL or want a
    /// clean CI baseline. Has no effect on DryRun (validator skipped).
    #[arg(long = "no-cache")]
    pub no_cache: bool,

    /// Verdict cache TTL. Cached entries older than this value are
    /// treated as cache misses and re-validated. Accepts shorthand
    /// durations: `30m`, `2h`, `7d`, `1w`. Default: `7d`.
    #[arg(long = "cache-ttl", value_name = "DURATION", default_value = "7d")]
    pub cache_ttl: String,

    /// For every proposal, attach a structured rationale to the
    /// receipt and surface it in the report. Each explanation names
    /// the classifier rule that fired (e.g. `cargo:caret-major-1-plus`,
    /// `gha:ref-shape-loosening`), the inputs that drove the decision,
    /// and the resulting tier. Useful for auditing why a bump was
    /// classified Compatible vs Breaking when the choice isn't obvious.
    #[arg(long)]
    pub explain: bool,

    /// Filter validator gate workflows by workspace-member precision:
    /// when a workflow uses an explicit `-p <member>` / `--package
    /// <member>` / `--workspace <member>` selector that targets ONLY
    /// non-affected members, skip the workflow. Workflows with
    /// wildcard selectors (`--workspace` / `-r` / etc.) and workflows
    /// with no member selectors are kept conservatively. Opt-in via
    /// this flag for v1; default behavior is unchanged (every gate
    /// workflow runs against every proposal). Speeds up validation
    /// on large monorepos where a dep is consumed by only a small
    /// subset of members.
    #[arg(long = "member-gate")]
    pub member_gate: bool,

    /// Validate a single, operator-specified dependency upgrade instead
    /// of enumerating every available bump. Format: `<name>@<version>`
    /// (scoped npm packages use `@scope/name@version`). Bypasses the
    /// standard outdated-discovery proposer (`cargo update --dry-run`,
    /// `npm outdated`, etc.) and builds a synthetic proposal with
    /// `from` resolved from the project's lockfile/manifest and `to`
    /// set to the supplied version. The proposal flows through the
    /// same classifier / validator / apply pipeline as a discovered
    /// proposal, so `--dep foo@1.2.3 --validate` is the canonical way
    /// to ask "would moving to foo 1.2.3 break my project?" without
    /// scanning the rest of the dep graph. When the dep isn't declared
    /// in any enabled ecosystem, or is already at the requested
    /// version, the run exits cleanly with a one-line explanation.
    #[arg(long = "dep", value_name = "NAME@VERSION")]
    pub dep: Option<String>,
}

/// Parse a `<name>@<version>` dep spec for `--dep`.
///
/// Scoped npm packages start with `@` (e.g. `@angular/core@22.0.0`); the
/// leading `@` is part of the name and the version separator is the
/// rightmost `@` whose index is > 0.
///
/// Returns the parsed `(name, version)` pair or a human-readable error
/// describing why the spec was rejected. The error string is rendered
/// verbatim by the CLI surface, so it's tuned for operator legibility
/// rather than programmatic consumption.
pub fn parse_dep_spec(spec: &str) -> Result<(String, String), String> {
    if spec.is_empty() {
        return Err("--dep value is empty; expected `<name>@<version>`".into());
    }
    // rsplit_once finds the rightmost `@`, which is the separator for
    // both `name@version` and `@scope/name@version`.
    let (name, version) = spec.rsplit_once('@').ok_or_else(|| {
        format!("--dep value `{spec}` is missing `@version`; expected `<name>@<version>`")
    })?;
    // If the rsplit gave us an empty name (e.g. `@1.0.0`), the spec is
    // malformed — a leading-`@` scope without a `/` follow-up is not a
    // valid package name.
    if name.is_empty() {
        return Err(format!(
            "--dep value `{spec}` has an empty name; expected `<name>@<version>` (use `@scope/name@version` for scoped npm packages)"
        ));
    }
    if version.is_empty() {
        return Err(format!(
            "--dep value `{spec}` has an empty version; expected `<name>@<version>`"
        ));
    }
    Ok((name.to_string(), version.to_string()))
}

#[cfg(test)]
mod parse_dep_spec_tests {
    use super::parse_dep_spec;

    #[test]
    fn parses_plain_cargo_name() {
        assert_eq!(
            parse_dep_spec("serde@1.0.228").unwrap(),
            ("serde".into(), "1.0.228".into())
        );
    }

    #[test]
    fn parses_scoped_npm_name() {
        assert_eq!(
            parse_dep_spec("@angular/core@22.0.0").unwrap(),
            ("@angular/core".into(), "22.0.0".into())
        );
    }

    #[test]
    fn parses_prerelease_version() {
        assert_eq!(
            parse_dep_spec("tokio@1.45.0-rc.1").unwrap(),
            ("tokio".into(), "1.45.0-rc.1".into())
        );
    }

    #[test]
    fn parses_build_metadata_version() {
        assert_eq!(
            parse_dep_spec("toml@1.1.2+spec-1.1.0").unwrap(),
            ("toml".into(), "1.1.2+spec-1.1.0".into())
        );
    }

    #[test]
    fn rejects_missing_at_separator() {
        let err = parse_dep_spec("serde").unwrap_err();
        assert!(err.contains("missing `@version`"), "got: {err}");
    }

    #[test]
    fn rejects_empty_version() {
        let err = parse_dep_spec("serde@").unwrap_err();
        assert!(err.contains("empty version"), "got: {err}");
    }

    #[test]
    fn rejects_empty_name_with_scope_marker() {
        // "@1.0.0".rsplit_once('@') splits at the only `@`, giving an
        // empty name. Scoped packages MUST include `/<name>` after the
        // leading `@`.
        let err = parse_dep_spec("@1.0.0").unwrap_err();
        assert!(err.contains("empty name"), "got: {err}");
    }

    #[test]
    fn rejects_empty_spec() {
        let err = parse_dep_spec("").unwrap_err();
        assert!(err.contains("empty"), "got: {err}");
    }

    #[test]
    fn rejects_bare_scope_without_version() {
        let err = parse_dep_spec("@angular/core").unwrap_err();
        // Trailing `core` after the scope `@` — rsplit_once produces
        // ("@angular/core", ""? no — finds the `@` at index 0, splits
        // into ("", "angular/core"). The empty-name guard catches it.
        assert!(err.contains("empty name") || err.contains("empty version"), "got: {err}");
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum EcosystemSelector {
    Cargo,
    GithubActions,
    Npm,
    All,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum ExecutorChoice {
    Host,
    Docker,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable text. Default. Per-tier sections, cohort headers,
    /// red proposal details, verdict cache summary — designed for a
    /// terminal reader.
    Text,
    /// Single JSON document emitted at end of run, mirroring
    /// `.assay/runs/<id>/run.json` with a `receipt_path` sibling.
    /// One valid JSON object per invocation; `JSON.parse(stdout)`
    /// succeeds. Suitable for scripted consumers that want the full
    /// receipt without re-reading the on-disk artifact.
    Json,
    /// Newline-delimited JSON event stream emitted in real time as
    /// the run progresses. One JSON object per line; each has a
    /// `type` discriminator. Events: `run_started`,
    /// `proposal_discovered`, `cohort_grouped`, `proposal_validating`,
    /// `proposal_completed`, `cohort_validating`, `cohort_completed`,
    /// `run_completed`. Suppresses all text output (no per-tier
    /// section, no human summary) so the stream is parseable
    /// without prefixes. Stable schema under the 1.0 promise:
    /// new event types and fields are additive minor changes;
    /// existing types and required fields don't change shape
    /// within a major version. Designed for GUIs (e.g. assay-gui)
    /// and live-progress sidecars that want to update UI state as
    /// each proposal flows through the worker pool.
    Ndjson,
}

/// Apply mode derived from mutually-exclusive --apply-local / --apply-pr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyMode {
    /// Proposer phase only. Fast — no per-proposal sandbox or
    /// validator. Reports proposals as `unvalidated`.
    DryRun,
    /// Proposer + validator. Runs each proposal through an isolated
    /// sandbox + the configured validator gate and reports pass/fail.
    /// Does NOT commit or open PRs — closes the dogfood-tour-2026-05-19
    /// finding A (default `analyze` not delivering the "test before
    /// adopt" value-prop).
    Validate,
    ApplyLocal,
    ApplyPr,
}

impl ApplyMode {
    pub fn from_args(args: &AnalyzeArgs) -> Self {
        if args.apply_pr {
            ApplyMode::ApplyPr
        } else if args.apply_local {
            ApplyMode::ApplyLocal
        } else if args.validate {
            ApplyMode::Validate
        } else {
            ApplyMode::DryRun
        }
    }

    /// `true` when the mode runs the validator stage (Validate /
    /// ApplyLocal / ApplyPr). DryRun is the only mode that skips it.
    pub fn runs_validator(self) -> bool {
        matches!(
            self,
            ApplyMode::Validate | ApplyMode::ApplyLocal | ApplyMode::ApplyPr
        )
    }

    /// `true` when the mode copies validated greens back to the host
    /// repo (ApplyLocal commits / ApplyPr pushes). Validate and DryRun
    /// both leave the host unchanged.
    pub fn mutates_host(self) -> bool {
        matches!(self, ApplyMode::ApplyLocal | ApplyMode::ApplyPr)
    }
}
