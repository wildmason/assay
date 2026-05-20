//! Per-run config + CLI-arg resolution helpers.
//!
//! Glue between [`AnalyzeArgs`] / `.assay.toml` and the worker
//! pipeline's expected inputs: validator construction, workflow
//! filter shape, per-proposal explanation injection, ignore-list
//! merging, ecosystem enablement, and the small "X has no manifests"
//! remediation hint.

use std::path::Path;
use std::time::Duration;

use crate::ecosystem::DependencyEcosystem;
use crate::error::{Error, Result};
use crate::model::Proposal;
use crate::validator::{CustomBackend, Validator, ValidatorExecutor};
use crate::workflow_filter::WorkflowFilter;

use super::args::{AnalyzeArgs, EcosystemSelector, ExecutorChoice};

/// Per-ecosystem remediation hint when `--ecosystem <name>` returns
/// no manifests. Each branch points at the most common reason from
/// the 2026-05-20 dogfood: gha repos that don't have
/// `.github/workflows/`, cargo crates without a lockfile, npm
/// projects without a `package.json`.
pub(super) fn zero_manifest_hint(eco_name: &str) -> &'static str {
    match eco_name {
        "github-actions" => {
            " (no `.github/workflows/*.yml` present — github-actions runs only against \
             workflow files)"
        }
        "cargo" => {
            " (no `Cargo.toml` at the scan root; pass --project <member> to target a \
             workspace member directly)"
        }
        "npm" => {
            " (no `package.json` at the scan root; pass --project <subdir> if the npm \
             project lives in a subdirectory)"
        }
        _ => "",
    }
}

/// Construct the [`Validator`] for this run.
///
/// `--gate-cmd` / `--gate-file` short-circuit auto-selection by wrapping
/// the operator-supplied command in a [`CustomBackend`]; otherwise we
/// defer to [`Validator::auto`] to pick `forge-run` (when `forge` and
/// `.github/workflows/` are both present) or `build-test` (manifest-
/// inferred fallback).
///
/// The verdict cache is wired in when `!args.no_cache`. Cache entries
/// live under `<artifact_root>/.assay/verdict-cache/` so every
/// (workspace, workflow) pair has a content-addressed verdict file. The
/// cache TTL comes from `args.cache_ttl` (parsed via
/// [`parse_cache_ttl`]).
pub(super) fn build_validator(args: &AnalyzeArgs, artifact_root: &Path) -> Result<Validator> {
    let base = if let Some(cmd) = args.gate_cmd.as_deref() {
        Validator::with_backend(Box::new(CustomBackend::from_gate_cmd(cmd)))
    } else if let Some(file) = args.gate_file.as_deref() {
        Validator::with_backend(Box::new(CustomBackend::from_gate_file(file)))
    } else {
        let validator_executor = match args.executor {
            ExecutorChoice::Host => ValidatorExecutor::Host,
            ExecutorChoice::Docker => ValidatorExecutor::Docker,
        };
        Validator::auto(&args.repo, validator_executor)?
    };

    if args.no_cache {
        return Ok(base);
    }

    let ttl = parse_cache_ttl(&args.cache_ttl).map_err(|msg| {
        Error::other(format!(
            "--cache-ttl `{}` is not a valid duration: {}. \
             Accepts `<n>s`, `<n>m`, `<n>h`, `<n>d`, or `<n>w`.",
            args.cache_ttl, msg
        ))
    })?;
    let cache_dir = artifact_root.join(".assay").join("verdict-cache");
    let cache = crate::verdict_cache::VerdictCache::new(cache_dir, ttl);
    Ok(base.with_cache(cache))
}

/// Parse a `--cache-ttl` value (e.g. `7d`, `30m`, `2h`, `1w`, `300s`)
/// into a `Duration`. Accepts integer-valued suffixed forms only — no
/// fractions, no compound expressions like `1h30m`. Returns a
/// human-readable error string on failure.
pub fn parse_cache_ttl(s: &str) -> std::result::Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty value".into());
    }
    let (num_part, unit_part): (&str, &str) = match s.find(|c: char| !c.is_ascii_digit()) {
        Some(idx) => (&s[..idx], &s[idx..]),
        None => (s, "s"),
    };
    if num_part.is_empty() {
        return Err(format!("missing number in `{s}`"));
    }
    let n: u64 = num_part
        .parse()
        .map_err(|_| format!("`{num_part}` is not a non-negative integer"))?;
    let secs = match unit_part.trim() {
        "s" => n,
        "m" => n.saturating_mul(60),
        "h" => n.saturating_mul(60 * 60),
        "d" => n.saturating_mul(60 * 60 * 24),
        "w" => n.saturating_mul(60 * 60 * 24 * 7),
        other => return Err(format!("unknown unit `{other}`")),
    };
    Ok(Duration::from_secs(secs))
}

/// Build the [`WorkflowFilter`] from the parsed CLI args.
///
/// Defaults to [`WorkflowFilter::pull_request_default`]; flipped to
/// [`WorkflowFilter::accept_all`] when `--no-workflow-filter` is set.
/// Include/exclude globs are layered on top of either base.
pub(super) fn workflow_filter_from_args(args: &AnalyzeArgs) -> WorkflowFilter {
    let base = if args.no_workflow_filter {
        WorkflowFilter::accept_all()
    } else {
        WorkflowFilter::pull_request_default()
    };
    WorkflowFilter {
        include_globs: args.include_workflows.clone(),
        exclude_globs: args.exclude_workflows.clone(),
        ..base
    }
}

/// Populate `proposal.explanation` for each proposal in `proposals`
/// by dispatching to the matching ecosystem's explainer. Called only
/// when `--explain` is set; otherwise proposals retain their default
/// `explanation: None`.
///
/// The dispatch keys on the ecosystem name (matching the strings
/// `ecosystem.name()` returns: `"cargo"`, `"github-actions"`,
/// `"npm"`). Proposals from a future ecosystem without a registered
/// explainer fall through with `None` rather than panic — the
/// reporter handles that gracefully (no rationale line printed).
pub(super) fn populate_proposal_explanations(proposals: &mut [Proposal], ecosystem_name: &str) {
    use crate::ecosystem::{cargo as cargo_eco, github_actions as gha_eco, npm as npm_eco};
    use crate::model::BumpTier;
    for proposal in proposals.iter_mut() {
        // Skip proposals that carry their own explanation already —
        // the GHA SHA-pin proposer attaches `gha:tag-to-sha-pinning`
        // at construction time because the generic per-tier
        // classifier would mis-classify a tag → SHA bump as
        // `gha:unparseable-tag`. Honor what the proposer already
        // chose to say.
        if proposal.explanation.is_some() {
            continue;
        }
        let explanation = match (ecosystem_name, proposal.bump_tier) {
            ("cargo", BumpTier::LockfileOnly) => Some(cargo_eco::explain_lockfile_only_bump(
                &proposal.from,
                &proposal.to,
                None,
            )),
            ("cargo", _) => Some(cargo_eco::explain_unchanged_bump(
                &proposal.from,
                &proposal.to,
            )),
            ("github-actions", _) => Some(gha_eco::explain_action_bump(
                Some(&proposal.from),
                &proposal.to,
            )),
            ("npm", BumpTier::LockfileOnly) => Some(npm_eco::explain_npm_lockfile_only_bump(
                &proposal.from,
                &proposal.to,
                None,
            )),
            ("npm", _) => Some(npm_eco::explain_npm_bump(&proposal.from, &proposal.to)),
            _ => None,
        };
        proposal.explanation = explanation;
    }
}

/// Return the `.assay.toml` ignore list for `ecosystem_name`. When the
/// config has no entry for this ecosystem, returns an empty Vec.
///
/// npm and yarn1 share the npm ecosystem entry (both use the
/// `NpmEcosystem` impl). Other ecosystems get their own section in
/// the config.
pub(super) fn resolve_ignore_list(
    config: &crate::config::AssayConfig,
    cli_ignores: &[String],
    ecosystem_name: &str,
) -> Vec<String> {
    let mut out: Vec<String> = match ecosystem_name {
        "cargo" => config.ecosystems.cargo.ignore.clone(),
        "github-actions" => config.ecosystems.github_actions.ignore.clone(),
        // npm/yarn1/pnpm aren't represented in the .assay.toml today;
        // a future config rev can add an `npm` section. For now return
        // an empty list (no ignores), matching the no-config default.
        _ => Vec::new(),
    };
    for entry in cli_ignores {
        if let Some((eco, subject)) = parse_cli_ignore(entry)
            && eco == ecosystem_name
            && !out.iter().any(|s| s == subject)
        {
            out.push(subject.to_string());
        }
    }
    out
}

/// Parse a `--ignore <eco>:<subject>` argument into its two halves.
/// Returns `None` for malformed input (no colon, empty halves), which
/// the caller silently drops — clap's value parsing handled the
/// repeat-and-collect, and a typo'd entry shouldn't crash the run.
pub(super) fn parse_cli_ignore(raw: &str) -> Option<(&str, &str)> {
    let (eco, subject) = raw.split_once(':')?;
    let eco = eco.trim();
    let subject = subject.trim();
    if eco.is_empty() || subject.is_empty() {
        return None;
    }
    Some((eco, subject))
}

pub(super) fn ecosystem_enabled(args: &AnalyzeArgs, ecosystem: &dyn DependencyEcosystem) -> bool {
    let Some(selector) = args.ecosystem else {
        return true;
    };
    matches!(
        (selector, ecosystem.name()),
        (EcosystemSelector::All, _)
            | (EcosystemSelector::Cargo, "cargo")
            | (EcosystemSelector::GithubActions, "github-actions")
            | (EcosystemSelector::Npm, "npm")
    )
}
