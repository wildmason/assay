//! Sanitizer for upstream-supplied strings.
//!
//! Every string that originates outside the operator's trust boundary
//! (release notes, tag names, commit subjects, action descriptions) MUST
//! pass through this module before being embedded in:
//!
//! - commit messages
//! - PR titles or bodies
//! - log lines
//! - receipt fields
//!
//! Each function targets a specific per-field charset/length contract and
//! returns a `Result` so the caller can mark the proposal `Unsupported` if
//! the upstream value can't be safely embedded. The sanitizer never silently
//! transforms a value into something different; it either accepts it
//! verbatim, transforms it through a documented rule, or rejects it.

use thiserror::Error;

const TAG_PATTERN: &str = r"A-Za-z0-9._/+\-";
const TAG_MAX_LEN: usize = 255;
const BRANCH_SEGMENT_PATTERN: &str = r"a-z0-9\-";
const BRANCH_SEGMENT_MAX_LEN: usize = 64;
const RELEASE_NOTES_MAX_LEN: usize = 4096;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SanitizeError {
    #[error("value is empty")]
    Empty,
    #[error("value exceeds max length {max} ({actual} bytes)")]
    TooLong { max: usize, actual: usize },
    #[error("value contains disallowed byte at offset {offset}: 0x{byte:02x}")]
    DisallowedByte { offset: usize, byte: u8 },
    #[error("value contains embedded CR or LF (offset {offset})")]
    EmbeddedNewline { offset: usize },
    #[error("value contains a sequence the sanitizer rejects: {reason}")]
    Rejected { reason: &'static str },
}

/// Validates a git tag name. Accepts only `[A-Za-z0-9._/+-]` and forbids
/// `..` sequences (per git's own refname rules — `..` opens up
/// rev-parse ambiguity).
pub fn sanitize_tag(value: &str) -> Result<&str, SanitizeError> {
    if value.is_empty() {
        return Err(SanitizeError::Empty);
    }
    if value.len() > TAG_MAX_LEN {
        return Err(SanitizeError::TooLong {
            max: TAG_MAX_LEN,
            actual: value.len(),
        });
    }
    if value.contains("..") {
        return Err(SanitizeError::Rejected {
            reason: "git refnames cannot contain `..`",
        });
    }
    for (offset, byte) in value.bytes().enumerate() {
        if !is_tag_byte(byte) {
            return Err(SanitizeError::DisallowedByte { offset, byte });
        }
    }
    let _ = TAG_PATTERN; // referenced via doc comment
    Ok(value)
}

/// Validates a single branch-name segment. Used to construct
/// `assay/<ecosystem>/<short-hash>` deterministic branch names.
pub fn sanitize_branch_segment(value: &str) -> Result<&str, SanitizeError> {
    if value.is_empty() {
        return Err(SanitizeError::Empty);
    }
    if value.len() > BRANCH_SEGMENT_MAX_LEN {
        return Err(SanitizeError::TooLong {
            max: BRANCH_SEGMENT_MAX_LEN,
            actual: value.len(),
        });
    }
    for (offset, byte) in value.bytes().enumerate() {
        if !is_branch_segment_byte(byte) {
            return Err(SanitizeError::DisallowedByte { offset, byte });
        }
    }
    let _ = BRANCH_SEGMENT_PATTERN;
    Ok(value)
}

/// Validates a commit subject (the first line of a commit message). Forbids
/// embedded CR/LF (CWE-93 defense — a CRLF would let an upstream-supplied
/// tag name break out of the subject line and inject body content).
pub fn sanitize_commit_subject(value: &str) -> Result<&str, SanitizeError> {
    if value.is_empty() {
        return Err(SanitizeError::Empty);
    }
    if value.len() > 200 {
        return Err(SanitizeError::TooLong {
            max: 200,
            actual: value.len(),
        });
    }
    for (offset, byte) in value.bytes().enumerate() {
        if byte == b'\n' || byte == b'\r' {
            return Err(SanitizeError::EmbeddedNewline { offset });
        }
    }
    Ok(value)
}

/// Sanitizes a release-notes body for embedding inside a PR description.
/// Truncates to 4 KB, code-fences the entire block, and HTML-escapes any
/// content that GitHub might otherwise render as active markdown.
///
/// Returns an owned `String` because the transformation is non-trivial.
pub fn sanitize_release_notes(value: &str) -> String {
    let truncated = if value.len() > RELEASE_NOTES_MAX_LEN {
        let mut cut = RELEASE_NOTES_MAX_LEN;
        // Avoid splitting in the middle of a UTF-8 code point.
        while cut > 0 && !value.is_char_boundary(cut) {
            cut -= 1;
        }
        let mut s = value[..cut].to_string();
        s.push_str("\n…(truncated)");
        s
    } else {
        value.to_string()
    };
    let escaped = escape_html(&truncated);
    // Triple-backticks may appear in upstream notes. Use a fence that uses
    // four backticks so embedded triples don't break out of the block.
    format!("````\n{escaped}\n````")
}

fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

fn is_tag_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'+' | b'-')
}

fn is_branch_segment_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_tag_accepts_typical_release_tags() {
        for tag in ["v1.0.0", "1.2.3", "release/2026-05-16", "v2.0.0+build.5"] {
            assert!(sanitize_tag(tag).is_ok(), "tag should be accepted: {tag}");
        }
    }

    #[test]
    fn sanitize_tag_rejects_empty() {
        assert_eq!(sanitize_tag(""), Err(SanitizeError::Empty));
    }

    #[test]
    fn sanitize_tag_rejects_shell_metacharacters() {
        // The classic "tag name as shell injection" attack.
        let attempts = [
            "v1.0.0; rm -rf /",
            "$(curl evil)",
            "`whoami`",
            "v1\n--no-verify",
            "v1\0null",
            "v1 && echo pwn",
            "v1|cat",
        ];
        for hostile in attempts {
            let result = sanitize_tag(hostile);
            assert!(
                result.is_err(),
                "hostile tag must be rejected: {hostile:?} (got {result:?})"
            );
        }
    }

    #[test]
    fn sanitize_tag_rejects_dotdot() {
        assert!(matches!(
            sanitize_tag("v1..2"),
            Err(SanitizeError::Rejected { .. })
        ));
    }

    #[test]
    fn sanitize_tag_rejects_overlong() {
        let huge = "v".to_string() + &"a".repeat(TAG_MAX_LEN);
        match sanitize_tag(&huge) {
            Err(SanitizeError::TooLong { .. }) => {}
            other => panic!("expected TooLong, got {other:?}"),
        }
    }

    #[test]
    fn sanitize_branch_segment_accepts_kebab() {
        assert_eq!(
            sanitize_branch_segment("serde-1-0-215"),
            Ok("serde-1-0-215")
        );
    }

    #[test]
    fn sanitize_branch_segment_rejects_uppercase_and_slash() {
        assert!(sanitize_branch_segment("Serde").is_err());
        assert!(sanitize_branch_segment("a/b").is_err());
    }

    #[test]
    fn sanitize_commit_subject_rejects_crlf() {
        assert!(matches!(
            sanitize_commit_subject("subject\r\nBody"),
            Err(SanitizeError::EmbeddedNewline { .. })
        ));
        assert!(matches!(
            sanitize_commit_subject("subject\nmore"),
            Err(SanitizeError::EmbeddedNewline { .. })
        ));
    }

    #[test]
    fn release_notes_truncate_and_fence() {
        let huge = "x".repeat(RELEASE_NOTES_MAX_LEN + 100);
        let out = sanitize_release_notes(&huge);
        assert!(
            out.starts_with("````\n"),
            "must begin with fence: {out:.30}"
        );
        assert!(out.ends_with("\n````"), "must end with fence: {out:?}");
        assert!(
            out.contains("…(truncated)"),
            "must mark truncation: {out:.40}"
        );
    }

    #[test]
    fn release_notes_html_escape() {
        let hostile = r#"<img src=x onerror=alert(1)> & "quote""#;
        let out = sanitize_release_notes(hostile);
        assert!(out.contains("&lt;img"), "must escape < : {out}");
        assert!(out.contains("&amp;"), "must escape & : {out}");
        assert!(out.contains("&quot;"), "must escape \" : {out}");
        assert!(
            !out.contains("<img src"),
            "must not render raw < tag : {out}"
        );
    }

    #[test]
    fn release_notes_at_utf8_boundary() {
        // Construct a string where naive truncation would split a multi-byte
        // character. 'é' is two bytes (0xC3 0xA9). Pad with ASCII so length
        // crosses the limit mid-é.
        let mut s = "a".repeat(RELEASE_NOTES_MAX_LEN - 1);
        s.push('é');
        let out = sanitize_release_notes(&s);
        // The result must still be valid UTF-8 — `format!` would panic
        // otherwise. Asserting via `.chars().count()` confirms.
        let _ = out.chars().count();
    }
}
