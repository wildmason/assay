//! Proposal generation for GitHub Actions: aggregate `uses:` references,
//! query the latest release per `(owner, repo)`, and emit one [`Proposal`]
//! per action (plus an optional SHA-pin hardening proposal for tag pins).
//!
//! Classification routes through [`classify_action_bump`] /
//! [`explain_action_bump`] — same-major non-loosening → Compatible,
//! anything else → Breaking. Tag granularity is preserved via
//! [`pick_target_tag`] so `actions/checkout@v4` doesn't get re-pinned to
//! the full `v4.1.7`.

use std::collections::BTreeMap;

use crate::model::{BumpTier, Classification, Manifest, ManifestKind, Proposal, ProposalKind};

use super::super::EcosystemName;
use super::super::github_actions_api::{GitHubApiClient, ReleaseInfo};
use super::tag_utils::{
    count_version_segments, is_shortcut_ref, parse_action_tag, tag_specificity, truncate_tag,
};
use super::{ActionAggregate, PinKind, UsesKind, UsesReference};

/// Collect every distinct `owner/repo` action from the detected manifest
/// set, grouping by `(owner, repo)`. Per-manifest `subpath` (e.g.
/// `actions/cache/save`) is folded into the subject only at proposal-build
/// time so we don't query the same repo N times for each subpath that
/// happens to live in it.
pub(crate) fn aggregate_actions_from_manifests(manifests: &[Manifest]) -> Vec<ActionAggregate> {
    let mut out: Vec<ActionAggregate> = Vec::new();
    for manifest in manifests {
        if !matches!(
            manifest.kind,
            ManifestKind::WorkflowYaml | ManifestKind::CompositeActionYaml
        ) {
            continue;
        }
        let Some(uses_value) = manifest.metadata.get("uses") else {
            continue;
        };
        let refs: Vec<UsesReference> = match serde_json::from_value(uses_value.clone()) {
            Ok(v) => v,
            Err(_) => continue,
        };
        for r in refs {
            if !matches!(r.kind, UsesKind::Remote) {
                continue;
            }
            let (Some(owner), Some(repo), Some(git_ref)) = (r.owner, r.repo, r.git_ref) else {
                continue;
            };
            let pin_kind = match r.is_sha_pinned {
                Some(true) => PinKind::Sha,
                Some(false) => PinKind::Tag,
                // No git_ref at all (the `Some/Some/Some` pattern above
                // makes this unreachable, but be defensive).
                None => continue,
            };
            // Skip well-known shortcut refs that aren't tags at all
            // (`@stable`, `@nightly` for dtolnay/rust-toolchain, `@main`
            // for action repos that recommend branch-pinning). These
            // are "track upstream" semantics — proposing a hard pin
            // would change behavior, not bump a version.
            if matches!(pin_kind, PinKind::Tag) && is_shortcut_ref(&git_ref) {
                continue;
            }
            if let Some(existing) = out.iter_mut().find(|a| a.owner == owner && a.repo == repo) {
                if !existing.manifest_paths.contains(&manifest.path) {
                    existing.manifest_paths.push(manifest.path.clone());
                }
                if existing.current_tag.is_none() {
                    existing.current_tag = r.tag_comment.clone();
                }
                // Mixed-pin reconciliation (same action pinned at
                // different SHAs or tags across files) is a follow-up;
                // first-seen wins for v1.
                let _ = (pin_kind, git_ref);
            } else {
                out.push(ActionAggregate {
                    owner,
                    repo,
                    pin_kind,
                    current_ref: git_ref,
                    current_tag: r.tag_comment,
                    manifest_paths: vec![manifest.path.clone()],
                });
            }
        }
    }
    out.sort_by(|a, b| a.owner.cmp(&b.owner).then_with(|| a.repo.cmp(&b.repo)));
    out
}

/// Build proposals from aggregated actions. Queries the GH API client
/// once per aggregate for the latest release. The `from`/`to` semantics
/// depend on the pin shape:
///
/// - **SHA pin**: `from = current_sha`, `to = release.commit_sha`. The
///   `tag:` note carries the new release tag so the applier can rewrite
///   the trailing `# v3.5.2` comment on the same line.
/// - **Tag pin**: `from = current_tag` (e.g. `v3`), `to = picked tag`
///   (granularity-matched against current; see [`pick_target_tag`]).
///   The applier rewrites the tag directly via `rewrite_uses_in_workflow`.
///
/// Tier classification reuses [`classify_action_bump`] against the
/// best-known from-tag (the comment for SHA pins, the pin itself for
/// tag pins) vs the resolved latest release tag.
pub(crate) fn build_action_proposals(
    manifests: &[Manifest],
    client: &GitHubApiClient,
    sha_pin_proposals: bool,
) -> Vec<Proposal> {
    let aggregates = aggregate_actions_from_manifests(manifests);
    let mut proposals: Vec<Proposal> = Vec::new();
    for agg in aggregates {
        let release = match client.latest_release(&agg.owner, &agg.repo) {
            Ok(Some(info)) => info,
            _ => continue,
        };
        // Tag-pinned actions get a SHA-pin proposal IN ADDITION to
        // the tag-bump proposal when `sha_pin_proposals` is on
        // (default). The two proposals offer the operator different
        // levels of hardening: the tag bump tracks the latest minor
        // floating tag (`v6 -> v7`); the SHA pin freezes to the
        // exact commit GitHub publishes for that tag (mitigates
        // tag-move attacks). Both target the same upstream release.
        if matches!(agg.pin_kind, PinKind::Tag) && sha_pin_proposals {
            let target_tag = pick_target_tag(
                client,
                &agg.owner,
                &agg.repo,
                &agg.current_ref,
                &release.tag_name,
            );
            proposals.push(build_sha_pin_proposal(&agg, &release, &target_tag, client));
        }
        let parts: ProposalParts = match agg.pin_kind {
            PinKind::Sha => {
                if release.commit_sha.eq_ignore_ascii_case(&agg.current_ref) {
                    continue;
                }
                // For SHA pins, the trailing `# v3.5.2` comment dictates
                // the operator's preferred granularity. Resolve the
                // target tag against that comment when present.
                let target_tag = match agg.current_tag.as_deref() {
                    Some(comment) => {
                        pick_target_tag(client, &agg.owner, &agg.repo, comment, &release.tag_name)
                    }
                    None => release.tag_name.clone(),
                };
                (
                    agg.current_ref.clone(),
                    release.commit_sha.clone(),
                    agg.current_tag.clone(),
                    short_sha(&release.commit_sha),
                )
                    // NB: target_tag flows into `notes` below; keep the
                    // existing 4-tuple shape for SHA pins.
                    .with_target_tag(target_tag)
            }
            PinKind::Tag => {
                let target_tag = pick_target_tag(
                    client,
                    &agg.owner,
                    &agg.repo,
                    &agg.current_ref,
                    &release.tag_name,
                );
                if agg.current_ref == target_tag {
                    continue;
                }
                (
                    agg.current_ref.clone(),
                    target_tag.clone(),
                    Some(agg.current_ref.clone()),
                    sanitize_id_segment(&target_tag),
                )
                    .with_target_tag(target_tag)
            }
        };
        let tier = classify_action_bump(parts.from_tag_for_tier.as_deref(), &release.tag_name);
        let subject = format!("{}/{}", agg.owner, agg.repo);
        let id = format!(
            "gha-{}-{}-{}",
            sanitize_id_segment(&agg.owner),
            sanitize_id_segment(&agg.repo),
            parts.id_segment,
        );
        let mut notes = vec![format!("tag:{}", parts.target_tag)];
        if client.is_offline() {
            notes.push(
                "source:offline-cache (latest release info read from .assay/actions/, may be stale)"
                    .to_string(),
            );
        }
        let classification = if client.is_offline() {
            // Offline reads from the action_store cache. Mark as
            // Simulated per the trait doc — the live registry may
            // have moved on since the cache was written.
            Classification::Simulated
        } else {
            Classification::Exact
        };
        proposals.push(Proposal {
            id,
            ecosystem: EcosystemName::GitHubActions.as_str().to_string(),
            kind: ProposalKind::ActionPin,
            subject,
            from: parts.from,
            to: parts.to,
            initial_classification: classification,
            manifest_paths: agg.manifest_paths,
            notes,
            bump_tier: tier,
            affected_consumers: Vec::new(),
            explanation: None,
            cohort: None,
        });
    }
    proposals
}

/// Carrier tuple for the per-proposal output of `build_action_proposals`.
/// Bundles `from`, `to`, the from-tag-for-tier (best-effort), the id
/// segment, and the resolved target-tag (used in the proposal's `notes`
/// for the applier's comment-rewrite). The previous code used a 4-tuple
/// then patched in the target tag — extracting it makes the
/// granularity-picker integration honest.
/// Build the "convert floating tag to SHA pin at <tag>" hardening
/// proposal. Emitted in addition to (not instead of) the tag-bump
/// proposal when an action is tag-pinned and `--no-sha-pin-proposals`
/// isn't set. The operator can pick which form they prefer — both
/// target the same upstream release.
///
/// Classifier verdict is always [`BumpTier::Compatible`] because
/// the bump is a manifest edit (operator opted into a different
/// pin form) but doesn't cross semver. The `notes` carry
/// `tag:<resolved-tag>` (so the applier can write the trailing
/// comment) and a `security:` note pointing the reader at the
/// supply-chain rationale. The `kind` stays [`ProposalKind::ActionPin`]
/// — there's only one kind for ref bumps.
fn build_sha_pin_proposal(
    agg: &ActionAggregate,
    release: &ReleaseInfo,
    target_tag: &str,
    client: &GitHubApiClient,
) -> Proposal {
    let subject = format!("{}/{}", agg.owner, agg.repo);
    let id = format!(
        "gha-{}-{}-sha-pin-{}",
        sanitize_id_segment(&agg.owner),
        sanitize_id_segment(&agg.repo),
        short_sha(&release.commit_sha),
    );
    let mut notes = vec![
        format!("tag:{target_tag}"),
        format!(
            "security: SHA pin replaces floating tag `{}` with commit `{}` at `{target_tag}` (mitigates tag-move attacks; see https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions)",
            agg.current_ref,
            short_sha(&release.commit_sha)
        ),
    ];
    if client.is_offline() {
        notes.push(
            "source:offline-cache (latest release info read from .assay/actions/, may be stale)"
                .to_string(),
        );
    }
    let classification = if client.is_offline() {
        Classification::Simulated
    } else {
        Classification::Exact
    };
    Proposal {
        id,
        ecosystem: EcosystemName::GitHubActions.as_str().to_string(),
        kind: ProposalKind::ActionPin,
        subject,
        from: agg.current_ref.clone(),
        to: release.commit_sha.clone(),
        initial_classification: classification,
        manifest_paths: agg.manifest_paths.clone(),
        notes,
        bump_tier: BumpTier::Compatible,
        affected_consumers: Vec::new(),
        explanation: Some(crate::model::BumpExplanation {
            summary: format!(
                "gha: SHA pin hardens the floating tag `{}` against tag-move attacks; \
                 commit `{}` resolves at tag `{target_tag}`",
                agg.current_ref,
                short_sha(&release.commit_sha),
            ),
            rule: "gha:tag-to-sha-pinning".into(),
            inputs: {
                let mut m = BTreeMap::new();
                m.insert("from_tag".into(), agg.current_ref.clone());
                m.insert("to_sha".into(), release.commit_sha.clone());
                m.insert("to_tag".into(), target_tag.to_string());
                m
            },
            decision: "compatible".into(),
        }),
        cohort: None,
    }
}

struct ProposalParts {
    from: String,
    to: String,
    from_tag_for_tier: Option<String>,
    id_segment: String,
    target_tag: String,
}

trait WithTargetTag {
    fn with_target_tag(self, target_tag: String) -> ProposalParts;
}

impl WithTargetTag for (String, String, Option<String>, String) {
    fn with_target_tag(self, target_tag: String) -> ProposalParts {
        ProposalParts {
            from: self.0,
            to: self.1,
            from_tag_for_tier: self.2,
            id_segment: self.3,
            target_tag,
        }
    }
}

/// Filter out proposals whose `subject` (`owner/repo`) appears in the
/// per-ecosystem ignore list from `.assay.toml`. The match is exact —
/// `actions/checkout` in the ignore list silences every workflow
/// referencing `actions/checkout` but leaves `actions/checkout-fork`
/// untouched. Glob support is a possible follow-up.
pub(crate) fn filter_ignored_actions(
    proposals: Vec<Proposal>,
    ignored: &[String],
) -> Vec<Proposal> {
    if ignored.is_empty() {
        return proposals;
    }
    proposals
        .into_iter()
        .filter(|p| !ignored.iter().any(|i| i == &p.subject))
        .collect()
}

/// Match the operator's tag granularity when picking a bump target.
///
/// Most workflow files pin actions at major-only floating tags
/// (`actions/checkout@v4`) because GitHub's documented examples do.
/// `releases/latest` returns the full version (`v6.0.2`). Naively using
/// the full version replaces the operator's intentional "track latest
/// in this major" pin with a frozen patch-level pin — a behavior
/// regression.
///
/// Strategy:
/// 1. Count numeric segments in current_ref (after stripping leading `v`).
///    `v4` = 1, `v4.1` = 2, `v4.1.2` = 3, anything unparseable = 0.
/// 2. If current segments == 0 OR current >= latest_segments, return
///    latest_tag verbatim.
/// 3. Otherwise build a truncated candidate (`v6.0.2` → `v6` for
///    segments=1, `v6.0` for segments=2) and probe upstream with
///    [`GitHubApiClient::tag_exists`].
/// 4. If the truncated tag exists upstream, use it. If not, fall back
///    to the full latest tag — the maintainer didn't publish the
///    major-only float, so we can't honor the operator's granularity
///    without breaking the pin.
fn pick_target_tag(
    client: &GitHubApiClient,
    owner: &str,
    repo: &str,
    current_tag: &str,
    latest_tag: &str,
) -> String {
    let current_segments = count_version_segments(current_tag);
    let latest_segments = count_version_segments(latest_tag);
    if current_segments == 0 || current_segments >= latest_segments {
        return latest_tag.to_string();
    }
    let candidate = match truncate_tag(latest_tag, current_segments) {
        Some(c) => c,
        None => return latest_tag.to_string(),
    };
    if candidate == latest_tag {
        return latest_tag.to_string();
    }
    if client.tag_exists(owner, repo, &candidate) {
        candidate
    } else {
        latest_tag.to_string()
    }
}

/// Classify the upgrade tier of a `from-tag` → `to-tag` action bump.
///
/// Mirrors cargo / npm's caret-compat groups:
/// - Both parseable, same major, target's pin shape is at least as
///   specific as the source → Compatible.
/// - Both parseable, target's pin shape LOOSER than source (full
///   `X.Y.Z` → major-only `X` etc.) → Breaking. The pin loosening
///   gives up supply-chain immutability and the operator should
///   review even when the major matches (dogfood-tour-2026-05-19
///   finding C).
/// - Both parseable, different major → Breaking.
/// - `from-tag` unknown (no `# vN.N.N` comment in the workflow) → Breaking,
///   conservatively. Caller may downgrade later when we add release-notes
///   parsing.
/// - Either tag unparseable as semver (date-based pins like `2024.01.05`,
///   `v3` shorthand) → Breaking.
pub(crate) fn classify_action_bump(from_tag: Option<&str>, to_tag: &str) -> BumpTier {
    let Some(from_tag) = from_tag else {
        return BumpTier::Breaking;
    };
    let Some(from_v) = parse_action_tag(from_tag) else {
        return BumpTier::Breaking;
    };
    let Some(to_v) = parse_action_tag(to_tag) else {
        return BumpTier::Breaking;
    };
    if from_v.major != to_v.major {
        return BumpTier::Breaking;
    }
    // Same major, both parseable. Detect ref-shape loosening — moving
    // from a fully-specified `X.Y.Z` (immutable) to a major-only `X`
    // (floating; whoever owns the action can rebase the tag at any
    // time). Loosening a pin is a supply-chain regression even when
    // the version line matches, so we surface it as Breaking.
    if tag_specificity(from_tag) > tag_specificity(to_tag) {
        return BumpTier::Breaking;
    }
    BumpTier::Compatible
}

/// Build a structured [`crate::model::BumpExplanation`] for a GHA
/// action-pin bump, paralleling [`classify_action_bump`]. Captures the
/// exact rule that fired (unknown-from / unparseable / major-bump /
/// ref-shape-loosening / same-major-compatible) and the inputs that
/// drove it.
pub(crate) fn explain_action_bump(
    from_tag: Option<&str>,
    to_tag: &str,
) -> crate::model::BumpExplanation {
    use crate::model::BumpExplanation;

    let mut inputs = BTreeMap::new();
    inputs.insert("to_tag".into(), to_tag.to_string());
    if let Some(f) = from_tag {
        inputs.insert("from_tag".into(), f.to_string());
    }

    let Some(from_tag) = from_tag else {
        return BumpExplanation {
            summary: format!(
                "gha: source pin is unknown (no `# vN.N.N` comment recorded in the workflow); \
                 cannot prove the bump is compatible, so {to_tag} is classified Breaking \
                 conservatively"
            ),
            rule: "gha:unknown-from".into(),
            inputs,
            decision: "breaking".into(),
        };
    };
    let from_parsed = parse_action_tag(from_tag);
    let to_parsed = parse_action_tag(to_tag);
    let (from_v, to_v) = match (from_parsed, to_parsed) {
        (Some(f), Some(t)) => (f, t),
        _ => {
            return BumpExplanation {
                summary: format!(
                    "gha: one or both tags unparseable as semver (`{from_tag}` -> `{to_tag}`); \
                     classified Breaking so the operator reviews"
                ),
                rule: "gha:unparseable-tag".into(),
                inputs,
                decision: "breaking".into(),
            };
        }
    };
    inputs.insert("from_major".into(), from_v.major.to_string());
    inputs.insert("to_major".into(), to_v.major.to_string());

    if from_v.major != to_v.major {
        return BumpExplanation {
            summary: format!(
                "gha: major version changed ({} -> {}); breaking-by-spec",
                from_v.major, to_v.major
            ),
            rule: "gha:major-bump".into(),
            inputs,
            decision: "breaking".into(),
        };
    }
    let from_spec = tag_specificity(from_tag);
    let to_spec = tag_specificity(to_tag);
    inputs.insert("from_specificity".into(), from_spec.to_string());
    inputs.insert("to_specificity".into(), to_spec.to_string());
    if from_spec > to_spec {
        return BumpExplanation {
            summary: format!(
                "gha: same major version ({}), but target pin shape is LESS specific than \
                 source (`{from_tag}` has {from_spec} numeric segment(s); `{to_tag}` has \
                 {to_spec}). Loosening an immutable pin gives up supply-chain immutability — \
                 classified Breaking so the operator reviews",
                from_v.major
            ),
            rule: "gha:ref-shape-loosening".into(),
            inputs,
            decision: "breaking".into(),
        };
    }
    BumpExplanation {
        summary: format!(
            "gha: same major version ({}), target pin shape at least as specific as source \
             — Compatible",
            from_v.major
        ),
        rule: "gha:same-major-compatible".into(),
        inputs,
        decision: "compatible".into(),
    }
}

fn sanitize_id_segment(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut last_dash = false;
    for ch in input.chars().flat_map(char::to_lowercase) {
        let mapped = if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            ch
        } else {
            '-'
        };
        if mapped == '-' {
            if !last_dash && !out.is_empty() {
                out.push(mapped);
                last_dash = true;
            }
        } else {
            out.push(mapped);
            last_dash = false;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

fn short_sha(sha: &str) -> String {
    sha.chars().take(7).collect()
}
