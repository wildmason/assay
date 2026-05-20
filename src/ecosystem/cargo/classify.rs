//! Bump-tier classification for cargo proposals.
//!
//! Cargo's compatibility model is subtler than plain semver — the band
//! depends on which leading segments are zero. These helpers wrap that
//! into two functions: [`classify_unchanged_bump`] returns the bare tier
//! verdict; [`explain_unchanged_bump`] returns the same verdict packaged
//! as a structured audit record for `--explain`.
//!
//! [`explain_lockfile_only_bump`] is the parallel for LockfileOnly bumps,
//! which always classify as `lockfile-within-constraint`.

use std::collections::BTreeMap;

use crate::model::{BumpExplanation, BumpTier};

/// Classify an `Unchanged X vFROM (available: vTO)` bump by impact tier,
/// using Cargo's compatibility groups (which are subtler than plain semver).
///
/// Compatibility groups per the [Cargo reference][1]:
/// - `major >= 1`: compatible within the same major (`^1.x.y`).
/// - `0.y.z` (minor >= 1): compatible within the same minor (`^0.y.z`).
/// - `0.0.z`: every patch is its own group — *no* `to` other than the same
///   `from` is compatible.
///
/// Returns [`BumpTier::Compatible`] when `from` and `to` live in the same
/// group (i.e. only a manifest-constraint pin keeps cargo from bumping
/// — non-breaking by Cargo's contract), [`BumpTier::Breaking`] otherwise.
/// Defensively returns `Breaking` for unparseable versions so the operator
/// gets a chance to look rather than silently skipping the upgrade.
///
/// [1]: https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#caret-requirements
pub fn classify_unchanged_bump(from: &str, to: &str) -> BumpTier {
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

/// Cargo's caret-compatibility group key. Two versions are caret-compatible
/// iff their group keys are equal. See [`classify_unchanged_bump`].
fn compat_group(v: &semver::Version) -> (u64, u64, u64) {
    match (v.major, v.minor) {
        (0, 0) => (0, 0, v.patch),
        (0, _) => (0, v.minor, 0),
        _ => (v.major, 0, 0),
    }
}

/// Build a structured `BumpExplanation` for a cargo manifest-edit
/// bump, paralleling [`classify_unchanged_bump`]. The returned
/// explanation captures the same decision logic in audit-friendly form:
/// caller passes `from` / `to` versions, the helper resolves the
/// compat-group rule that fired and packages the inputs so an operator
/// can read *why* the tier was assigned.
///
/// Used only when `--explain` is set on the CLI; the proposer attaches
/// the result to `Proposal::explanation`.
pub fn explain_unchanged_bump(from: &str, to: &str) -> BumpExplanation {
    let mut inputs = BTreeMap::new();
    inputs.insert("from".into(), from.to_string());
    inputs.insert("to".into(), to.to_string());

    let from_parsed = semver::Version::parse(from);
    let to_parsed = semver::Version::parse(to);
    let (from_v, to_v) = match (from_parsed, to_parsed) {
        (Ok(f), Ok(t)) => (f, t),
        _ => {
            return BumpExplanation {
                summary: format!(
                    "cargo: one or both versions unparseable as semver ({from} -> {to}); \
                     classified Breaking conservatively so the operator reviews"
                ),
                rule: "cargo:unparseable-semver".into(),
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
            (0, 0) => "cargo:caret-0-0-x-same-patch",
            (0, _) => "cargo:caret-0-x-same-minor",
            _ => "cargo:caret-major-1-plus",
        };
        let summary = match (from_v.major, from_v.minor) {
            (0, 0) => format!(
                "cargo: 0.0.x band — every patch is its own group; {from} and {to} share \
                 patch={}, so the bump stays caret-compatible and only the manifest pin keeps \
                 cargo from taking it",
                from_v.patch
            ),
            (0, _) => format!(
                "cargo: 0.x band — caret groups by minor; both versions share minor={}, so \
                 only the manifest pin keeps cargo from bumping (Compatible)",
                from_v.minor
            ),
            _ => format!(
                "cargo: 1.0+ band — caret groups by major; both versions share major={}, so \
                 only the manifest pin keeps cargo from bumping (Compatible)",
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
            (0, 0) => "cargo:caret-0-0-x-patch-crossed",
            (0, _) if from_v.minor != to_v.minor => "cargo:caret-0-x-minor-crossed",
            _ if from_v.major != to_v.major => "cargo:caret-major-crossed",
            _ => "cargo:caret-group-crossed",
        };
        let summary = match (from_v.major, from_v.minor) {
            (0, 0) => format!(
                "cargo: 0.0.x band — every patch is breaking-by-spec; {from} -> {to} crosses \
                 a patch boundary"
            ),
            (0, _) if from_v.minor != to_v.minor => format!(
                "cargo: 0.x band — minor bumps are breaking-by-spec; {from} -> {to} crosses \
                 minor={} -> minor={}",
                from_v.minor, to_v.minor
            ),
            _ if from_v.major != to_v.major => format!(
                "cargo: 1.0+ band — major bumps are breaking-by-spec; {from} -> {to} crosses \
                 major={} -> major={}",
                from_v.major, to_v.major
            ),
            _ => format!(
                "cargo: bump crosses a caret-compat group boundary; {from} -> {to} requires \
                 review"
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

/// Build a structured [`BumpExplanation`] for a
/// `LockfileOnly` cargo bump — one where the new version satisfies the
/// existing constraint and only the lockfile changes. Always returns
/// the `lockfile-within-constraint` rule, decision = `lockfile-only`.
pub fn explain_lockfile_only_bump(
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
            "cargo: new version {to} satisfies the existing constraint `{c}`; only \
             Cargo.lock changes (no manifest edit required)"
        ),
        None => format!(
            "cargo: new version {to} satisfies the existing constraint; only \
             Cargo.lock changes (no manifest edit required)"
        ),
    };
    BumpExplanation {
        summary,
        rule: "cargo:lockfile-within-constraint".into(),
        inputs,
        decision: "lockfile-only".into(),
    }
}
