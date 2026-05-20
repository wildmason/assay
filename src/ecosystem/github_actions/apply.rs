//! Rewrite `uses: <subject>@<from>` lines in a workflow YAML file.
//!
//! Preserves all surrounding formatting (indentation, list-item dashes,
//! colon-spacing, inline comment whitespace) and updates the trailing
//! `# vX.Y.Z` comment when one is present and a `version_tag` is supplied.
//! The function refuses to rewrite when the current ref doesn't match
//! `from` exactly — that's the mid-flight-edit defense against double
//! application or stale proposals.

use crate::error::{Error, Result};

use super::tag_utils::{is_likely_commit_sha, is_version_char};

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
        // Auto-add a `# <tag>` comment when:
        //   - the original line had NO comment,
        //   - the new value looks like a commit SHA (40 hex chars), AND
        //   - the caller passed a version_tag.
        // This is the SHA-pin path: an operator who had
        // `actions/checkout@v6` (no comment) now gets
        // `actions/checkout@<sha> # v6.0.2`. Without the auto-comment
        // the SHA-pin form would lose all human-readable context.
        let final_comment = match new_comment {
            Some(c) => Some(c),
            None => {
                if let (Some(tag), true) = (version_tag, is_likely_commit_sha(to)) {
                    Some(format!("# {tag}"))
                } else {
                    None
                }
            }
        };
        if let Some(comment) = final_comment {
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
