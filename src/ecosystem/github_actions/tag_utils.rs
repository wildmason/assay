//! Pure helpers for parsing and classifying action version tags.
//!
//! Everything here is side-effect-free and network-free — no
//! [`super::GitHubApiClient`] use. Functions that need to consult the
//! GitHub API (e.g. `pick_target_tag`) live in [`super::propose`].

/// Returns 1 for major-only tags (`v1`), 2 for `vX.Y`, 3 for `vX.Y.Z`.
/// Falls back to 0 for anything else — those route to the `parse_action_tag`
/// caller's None/error path before reaching this function.
pub(super) fn tag_specificity(tag: &str) -> u8 {
    let stripped = tag
        .strip_prefix('v')
        .or_else(|| tag.strip_prefix('V'))
        .unwrap_or(tag);
    let core = stripped.split(['-', '+']).next().unwrap_or(stripped);
    let segments: Vec<&str> = core.split('.').collect();
    let mut count = 0u8;
    for seg in segments {
        if seg.parse::<u64>().is_ok() {
            count += 1;
        } else {
            break;
        }
    }
    count
}

/// Known shortcut refs that aren't version tags. Used by the proposer
/// to skip tag pins that signal "track upstream", not a fixed version.
///
/// Examples that should NOT produce a bump proposal:
/// - `dtolnay/rust-toolchain@stable` — the action's documented "track
///   latest stable rustc" alias.
/// - `actions/checkout@main` — branch-pin (rare but real).
/// - `pre-commit/action@latest` — the action author's recommended
///   floating tag for the README.
pub(super) fn is_shortcut_ref(git_ref: &str) -> bool {
    matches!(
        git_ref.to_ascii_lowercase().as_str(),
        "stable" | "nightly" | "beta" | "latest" | "main" | "master" | "head" | "default" | "trunk"
    )
}

/// Parse an action tag into a semver-like triple. Strips a leading `v`
/// or `V`. Accepts the standard `X.Y.Z` shape AND the truncated `X.Y`
/// (treats missing patch as 0) and `X` (treats missing minor + patch
/// as 0) shapes that action authors sometimes use (`v3` for example).
///
/// Returns `None` for tags that can't be coerced — date-based releases
/// (`2024.01.05`), commit-shaped pins, or anything with non-numeric
/// segments.
pub(super) fn parse_action_tag(tag: &str) -> Option<semver::Version> {
    let stripped = tag
        .strip_prefix('v')
        .or_else(|| tag.strip_prefix('V'))
        .unwrap_or(tag);
    // Try direct parse first (handles `1.2.3`, `1.2.3-alpha`).
    if let Ok(v) = semver::Version::parse(stripped) {
        return Some(v);
    }
    // Try padding `X` → `X.0.0` and `X.Y` → `X.Y.0`.
    let segments: Vec<&str> = stripped.split('.').collect();
    let major: u64 = segments.first()?.parse().ok()?;
    let minor: u64 = segments.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let patch: u64 = segments.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
    Some(semver::Version::new(major, minor, patch))
}

/// Count numeric segments in a version-like tag. Strips a leading `v`
/// or `V`. Stops at the first non-numeric segment (drops prerelease /
/// build metadata). Returns 0 for unparseable tags.
pub(super) fn count_version_segments(tag: &str) -> usize {
    let stripped = tag
        .strip_prefix('v')
        .or_else(|| tag.strip_prefix('V'))
        .unwrap_or(tag);
    let mut count = 0;
    for segment in stripped.split('.') {
        // Stop at the first segment that contains non-digits (e.g.
        // `0-rc.1`, `+build.5`). Prerelease segments don't count
        // toward "the operator wants this much granularity".
        let core = segment
            .split_once(['-', '+'])
            .map(|(before, _)| before)
            .unwrap_or(segment);
        if core.is_empty() || !core.chars().all(|c| c.is_ascii_digit()) {
            return count;
        }
        count += 1;
        // If the segment HAD a dash/plus, stop — the rest is metadata.
        if segment != core {
            return count;
        }
    }
    count
}

/// Truncate a version tag to `target_segments` numeric segments,
/// preserving the leading `v` if present and dropping any
/// prerelease/build metadata. Returns `None` when the tag has fewer
/// segments than requested (can't synthesize).
pub(super) fn truncate_tag(tag: &str, target_segments: usize) -> Option<String> {
    let leading_v = tag.starts_with('v') || tag.starts_with('V');
    let stripped = if leading_v { &tag[1..] } else { tag };
    let mut numeric_parts: Vec<&str> = Vec::new();
    for segment in stripped.split('.') {
        let core = segment
            .split_once(['-', '+'])
            .map(|(before, _)| before)
            .unwrap_or(segment);
        if !core.chars().all(|c| c.is_ascii_digit()) || core.is_empty() {
            break;
        }
        numeric_parts.push(core);
        if segment != core {
            break;
        }
    }
    if numeric_parts.len() < target_segments {
        return None;
    }
    let truncated: String = numeric_parts[..target_segments].join(".");
    Some(if leading_v {
        format!("v{truncated}")
    } else {
        truncated
    })
}

/// Heuristic: does `value` look like a git commit SHA? Used by
/// `rewrite_uses_in_workflow` to decide whether to auto-add a
/// `# <tag>` comment when transitioning from a tag-pinned ref to a
/// SHA-pinned one. Recognizes both full (40 char) and short (≥7 char)
/// SHAs of lowercase hex.
pub(super) fn is_likely_commit_sha(value: &str) -> bool {
    value.len() >= 7 && value.len() <= 40 && value.chars().all(|c| c.is_ascii_hexdigit())
}

pub(super) fn is_version_char(ch: char) -> bool {
    ch == 'v' || ch == 'V' || ch.is_ascii_digit()
}
