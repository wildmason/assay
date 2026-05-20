//! Fallback parser for stderr that neither the cargo nor the npm
//! parsers recognized. Produces a `FailureContext` with
//! `rule:"generic:unstructured"`, the first non-empty stderr line as
//! summary, and no findings. This branch keeps the contract that
//! `parse` always returns *something* — the text reporter still
//! renders a one-line summary and the raw stderr appendix even when
//! we couldn't lift structure.

use crate::failure_context::FailureContext;

pub(super) fn parse_generic(stderr: &str) -> FailureContext {
    let summary = stderr
        .lines()
        .map(str::trim_end)
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
        .to_string();
    FailureContext::new("generic:unstructured", summary, Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_uses_first_nonempty_line_as_summary() {
        let stderr = "\n   \nactual first content line\nsecond line\n";
        let ctx = parse_generic(stderr);
        assert_eq!(ctx.rule, "generic:unstructured");
        assert_eq!(ctx.summary, "actual first content line");
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn generic_empty_stderr_produces_empty_summary() {
        let ctx = parse_generic("");
        assert_eq!(ctx.rule, "generic:unstructured");
        assert_eq!(ctx.summary, "");
        assert!(ctx.findings.is_empty());
        // Still a valid 16-char fingerprint — the empty-findings hash.
        assert_eq!(ctx.fingerprint.len(), 16);
    }

    #[test]
    fn generic_all_whitespace_stderr_produces_empty_summary() {
        let ctx = parse_generic("   \n\t\n  ");
        assert_eq!(ctx.summary, "");
    }
}
