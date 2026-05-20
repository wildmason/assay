//! Bump-tier classification for npm proposals + the structured
//! `BumpExplanation` builders. npm shares cargo's caret-compat group
//! model, so the rules and rule-IDs mirror `crate::ecosystem::cargo::classify`
//! but stay in this module so the `npm:` rule prefix is consistent across
//! reports.

use std::collections::BTreeMap;

use crate::model::{BumpExplanation, BumpTier};

/// Classify an npm version bump into a [`BumpTier`].
///
/// npm uses the same compatibility-group concept as Cargo (caret matches
/// within the same significant segment), so the rules mirror
/// `classify_unchanged_bump` in `cargo`:
///
/// - `major >= 1`: same major group → Compatible.
/// - `0.y.z`: same minor group → Compatible.
/// - `0.0.z`: same patch group → Compatible (i.e. only identical bumps).
///
/// Defensive: unparseable input returns Breaking so the operator gets
/// a chance to look rather than a silent skip.
pub(crate) fn classify_npm_bump(from: &str, to: &str) -> BumpTier {
    let Ok(from_v) = semver::Version::parse(from) else {
        return BumpTier::Breaking;
    };
    let Ok(to_v) = semver::Version::parse(to) else {
        return BumpTier::Breaking;
    };
    if compat_group(&from_v) == compat_group(&to_v) {
        BumpTier::Compatible
    } else {
        BumpTier::Breaking
    }
}

fn compat_group(v: &semver::Version) -> (u64, u64, u64) {
    match (v.major, v.minor) {
        (0, 0) => (0, 0, v.patch),
        (0, _) => (0, v.minor, 0),
        _ => (v.major, 0, 0),
    }
}

/// Build a structured [`BumpExplanation`] for an npm
/// version bump, paralleling [`classify_npm_bump`]. npm and cargo
/// share the caret-compat model; the explanation mirrors the wording
/// the cargo explainer uses but flags the ecosystem as npm so the
/// report attribution is correct.
pub(crate) fn explain_npm_bump(from: &str, to: &str) -> BumpExplanation {
    let mut inputs = BTreeMap::new();
    inputs.insert("from".into(), from.to_string());
    inputs.insert("to".into(), to.to_string());

    let (from_v, to_v) = match (semver::Version::parse(from), semver::Version::parse(to)) {
        (Ok(f), Ok(t)) => (f, t),
        _ => {
            return BumpExplanation {
                summary: format!(
                    "npm: one or both versions unparseable as semver ({from} -> {to}); \
                     classified Breaking conservatively so the operator reviews"
                ),
                rule: "npm:unparseable-semver".into(),
                inputs,
                decision: "breaking".into(),
            };
        }
    };
    let from_group = compat_group(&from_v);
    let to_group = compat_group(&to_v);
    inputs.insert(
        "from_compat_group".into(),
        format!("{}.{}.{}", from_group.0, from_group.1, from_group.2),
    );
    inputs.insert(
        "to_compat_group".into(),
        format!("{}.{}.{}", to_group.0, to_group.1, to_group.2),
    );

    if from_group == to_group {
        let rule = match (from_v.major, from_v.minor) {
            (0, 0) => "npm:caret-0-0-x-same-patch",
            (0, _) => "npm:caret-0-x-same-minor",
            _ => "npm:caret-major-1-plus",
        };
        let summary = match (from_v.major, from_v.minor) {
            (0, 0) => format!(
                "npm: 0.0.x band — each patch is its own caret group; {from} and {to} share \
                 patch={}, so only the manifest pin keeps npm from bumping (Compatible)",
                from_v.patch
            ),
            (0, _) => format!(
                "npm: 0.x band — caret groups by minor; both versions share minor={}, so \
                 only the manifest pin keeps npm from bumping (Compatible)",
                from_v.minor
            ),
            _ => format!(
                "npm: 1.0+ band — caret groups by major; both versions share major={}, so \
                 only the manifest pin keeps npm from bumping (Compatible)",
                from_v.major
            ),
        };
        BumpExplanation {
            summary,
            rule: rule.into(),
            inputs,
            decision: "compatible".into(),
        }
    } else {
        let rule = match (from_v.major, from_v.minor) {
            (0, 0) => "npm:caret-0-0-x-patch-crossed",
            (0, _) if from_v.minor != to_v.minor => "npm:caret-0-x-minor-crossed",
            _ if from_v.major != to_v.major => "npm:caret-major-crossed",
            _ => "npm:caret-group-crossed",
        };
        // Each summary names the rule once and the input boundary
        // once — the previous form repeated both halves in slightly
        // different words (dogfood-flagged as stuttering). Each also
        // hints at the implied manifest edit the operator will need
        // to widen the caret constraint (`^{from} → ^{to}`).
        let summary = match (from_v.major, from_v.minor) {
            (0, 0) => format!(
                "npm: 0.0.x band — {from} -> {to} crosses a patch boundary (breaking-by-spec); \
                 widens `^{from}` -> `^{to}`"
            ),
            (0, _) if from_v.minor != to_v.minor => format!(
                "npm: 0.x band — {from} -> {to} crosses minor={}→{} (breaking-by-spec); \
                 widens `^{from}` -> `^{to}`",
                from_v.minor, to_v.minor
            ),
            _ if from_v.major != to_v.major => format!(
                "npm: 1.0+ band — {from} -> {to} crosses major={}→{} (breaking-by-spec); \
                 widens `^{from}` -> `^{to}`",
                from_v.major, to_v.major
            ),
            _ => format!(
                "npm: {from} -> {to} crosses a caret-compat group boundary; widens \
                 `^{from}` -> `^{to}` and merits review"
            ),
        };
        BumpExplanation {
            summary,
            rule: rule.into(),
            inputs,
            decision: "breaking".into(),
        }
    }
}

/// Build a `LockfileOnly` explanation — the new version satisfies the
/// existing constraint and only `package-lock.json` / `pnpm-lock.yaml`
/// / `yarn.lock` changes.
pub(crate) fn explain_npm_lockfile_only_bump(
    from: &str,
    to: &str,
    constraint: Option<&str>,
) -> BumpExplanation {
    let mut inputs = BTreeMap::new();
    inputs.insert("from".into(), from.to_string());
    inputs.insert("to".into(), to.to_string());
    if let Some(c) = constraint {
        inputs.insert("constraint".into(), c.to_string());
    }
    let summary = match constraint {
        Some(c) => format!(
            "npm: new version {to} satisfies the existing constraint `{c}`; only the \
             lockfile changes (no manifest edit required)"
        ),
        None => format!(
            "npm: new version {to} satisfies the existing constraint; only the lockfile \
             changes (no manifest edit required)"
        ),
    };
    BumpExplanation {
        summary,
        rule: "npm:lockfile-within-constraint".into(),
        inputs,
        decision: "lockfile-only".into(),
    }
}
