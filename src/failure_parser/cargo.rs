//! Cargo / rustc stderr parser.
//!
//! Recognized patterns:
//!
//! - **rustc canonical error** —
//!   `error[E####]: <msg>` on one line, optionally followed by
//!   `  --> <file>:<line>:<column>` on the next non-empty line. Produces
//!   one `FailureFinding` per error block with `code:"E####"` and
//!   file/line/column populated when the location line is present.
//!   Rule: `"cargo:rustc-error"`.
//!
//! - **build-script failure** —
//!   `error: failed to run custom build command for \`<crate>\``.
//!   Produces a single finding with `code:"build-script"` and a
//!   synthesized message naming the crate. Rule:
//!   `"cargo:build-script-failure"`.
//!
//! - **linker error** —
//!   `error: linking with <linker> failed: exit code: <n>` (and the
//!   shorter `error: linking with <linker> failed` variant). Produces
//!   one finding with `code:"linker"`. Rule: `"cargo:linker-error"`.
//!
//! - **could-not-compile** —
//!   `error: could not compile \`<crate>\``. Falls under
//!   `"cargo:rustc-error"` and is used as a synthesized finding ONLY
//!   when no specific `error[E####]` line preceded it.
//!
//! - **bare cargo error** —
//!   `error: <msg>` without a code AND without a `-->` location.
//!   Produces a finding with `code:None`, file/line absent. Rule:
//!   `"cargo:rustc-error"`.
//!
//! All other stderr (warnings, infos, "Compiling foo v0.1.0" lines) is
//! ignored — the report's raw-log appendix still preserves it.

use regex::Regex;
use std::sync::OnceLock;

use crate::failure_context::{FailureContext, FailureFinding};

/// `error[E####]: <message>`
fn rustc_error_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^error\[(E\d{4})\]:\s*(.+?)\s*$").unwrap())
}

/// `--> <file>:<line>:<column>` (rustc location line, leading spaces tolerated).
fn rustc_loc_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^\s*-->\s+(.+?):(\d+):(\d+)\s*$").unwrap())
}

/// `error: failed to run custom build command for \`<crate>\``
fn build_script_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"^error:\s*failed to run custom build command for [`'](.+?)[`']").unwrap()
    })
}

/// `error: linking with <linker> failed[: exit code: <n>]`
fn linker_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"^error:\s*linking with [`']?(.+?)[`']? failed(?::\s*exit code:\s*(\S+))?")
            .unwrap()
    })
}

/// `error: could not compile \`<crate>\``
fn could_not_compile_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^error:\s*could not compile [`'](.+?)[`']").unwrap())
}

/// Bare `error: <message>` — used only when no other cargo pattern
/// matched the line. Captures the message verbatim.
fn bare_error_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^error:\s*(.+?)\s*$").unwrap())
}

/// Parse cargo stderr. Returns `None` if nothing matched — the caller
/// (`failure_parser::parse`) then falls back to the generic parser.
pub(super) fn parse_cargo(stderr: &str) -> Option<FailureContext> {
    let lines: Vec<&str> = stderr.lines().collect();

    // First pass: catch linker errors (the most ecosystem-specific
    // failure flavor, since rustc errors can show up in the same log
    // when both compilation and linking failed).
    let mut linker_finding: Option<FailureFinding> = None;
    for line in &lines {
        if let Some(caps) = linker_re().captures(line) {
            let linker = caps.get(1).map_or("", |m| m.as_str());
            let exit_label = caps.get(2).map(|m| m.as_str()).unwrap_or("?");
            linker_finding = Some(FailureFinding {
                code: Some("linker".into()),
                message: format!("linking with `{linker}` failed (exit {exit_label})"),
                file: None,
                line: None,
                column: None,
            });
            break;
        }
    }
    if let Some(f) = linker_finding {
        return Some(FailureContext::new(
            "cargo:linker-error",
            f.message.clone(),
            vec![f],
        ));
    }

    // Second pass: build-script failures.
    for line in &lines {
        if let Some(caps) = build_script_re().captures(line) {
            let krate = caps.get(1).map_or("", |m| m.as_str());
            let finding = FailureFinding {
                code: Some("build-script".into()),
                message: format!("{krate} custom build command failed"),
                file: None,
                line: None,
                column: None,
            };
            return Some(FailureContext::new(
                "cargo:build-script-failure",
                finding.message.clone(),
                vec![finding],
            ));
        }
    }

    // Third pass: rustc errors with codes, paired with optional --> location.
    let mut findings: Vec<FailureFinding> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if let Some(caps) = rustc_error_re().captures(line) {
            let code = caps.get(1).map_or("", |m| m.as_str()).to_string();
            let message = caps.get(2).map_or("", |m| m.as_str()).to_string();
            // Look ahead for the next non-empty line that matches `-->`.
            let mut location_line_idx = None;
            for (j, candidate) in lines.iter().enumerate().skip(i + 1).take(6) {
                if candidate.trim().is_empty() {
                    continue;
                }
                if rustc_loc_re().is_match(candidate) {
                    location_line_idx = Some(j);
                }
                break;
            }
            let (file, line_no, column) = match location_line_idx {
                Some(j) => {
                    let caps = rustc_loc_re().captures(lines[j]).expect("regex matched");
                    let file = caps.get(1).map(|m| m.as_str().to_string());
                    let line_no = caps.get(2).and_then(|m| m.as_str().parse::<u32>().ok());
                    let column = caps.get(3).and_then(|m| m.as_str().parse::<u32>().ok());
                    (file, line_no, column)
                }
                None => (None, None, None),
            };
            findings.push(FailureFinding {
                code: Some(code),
                message,
                file,
                line: line_no,
                column,
            });
        }
        i += 1;
    }

    if !findings.is_empty() {
        let summary = format_rustc_summary(&findings);
        return Some(FailureContext::new("cargo:rustc-error", summary, findings));
    }

    // Fourth pass: `could not compile` — a rustc-error rule but with
    // only a synthesized finding (no E#### present).
    for line in &lines {
        if let Some(caps) = could_not_compile_re().captures(line) {
            let krate = caps.get(1).map_or("", |m| m.as_str());
            let finding = FailureFinding {
                code: None,
                message: format!("could not compile `{krate}`"),
                file: None,
                line: None,
                column: None,
            };
            return Some(FailureContext::new(
                "cargo:rustc-error",
                finding.message.clone(),
                vec![finding],
            ));
        }
    }

    // Fifth pass: bare `error: ...` line — last resort under the
    // cargo rule. The summary echoes the message.
    for line in &lines {
        if let Some(caps) = bare_error_re().captures(line) {
            let message = caps.get(1).map_or("", |m| m.as_str()).to_string();
            // Skip the messages that other passes would have handled —
            // they're noise here (defensive: we matched them earlier
            // and returned, but if the regex ordering ever shifts
            // we want this to stay tight).
            if message.starts_with("failed to run custom build command")
                || message.starts_with("linking with")
                || message.starts_with("could not compile")
            {
                continue;
            }
            let finding = FailureFinding {
                code: None,
                message: message.clone(),
                file: None,
                line: None,
                column: None,
            };
            return Some(FailureContext::new(
                "cargo:rustc-error",
                message,
                vec![finding],
            ));
        }
    }

    None
}

fn format_rustc_summary(findings: &[FailureFinding]) -> String {
    let first = &findings[0];
    let code = first.code.as_deref().unwrap_or("rustc");
    let loc = match (&first.file, first.line) {
        (Some(f), Some(l)) => format!(" at {f}:{l}"),
        _ => String::new(),
    };
    if findings.len() == 1 {
        format!("{code}: {}{loc}", first.message)
    } else {
        format!(
            "{code}: {}{loc} (+{} more)",
            first.message,
            findings.len() - 1
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Canonical: error[E####]: msg with --> location
    // -------------------------------------------------------------------------

    #[test]
    fn parses_canonical_rustc_error_with_location() {
        let stderr = "\
   Compiling foo v0.1.0
error[E0277]: the trait `Send` is not implemented for `Bar`
  --> src/lib.rs:42:7
   |
42 |     spawn(bar);
   |     ----- ^^^ within `Bar`, the trait `Send` is not implemented
   |
error: aborting due to previous error
";
        let ctx = parse_cargo(stderr).expect("should parse");
        assert_eq!(ctx.rule, "cargo:rustc-error");
        assert_eq!(ctx.findings.len(), 1);
        let f = &ctx.findings[0];
        assert_eq!(f.code.as_deref(), Some("E0277"));
        assert_eq!(f.message, "the trait `Send` is not implemented for `Bar`");
        assert_eq!(f.file.as_deref(), Some("src/lib.rs"));
        assert_eq!(f.line, Some(42));
        assert_eq!(f.column, Some(7));
    }

    // -------------------------------------------------------------------------
    // Edge: multiple rustc errors in one stderr → multi-finding context
    // -------------------------------------------------------------------------

    #[test]
    fn parses_multiple_rustc_errors_into_multi_finding_context() {
        let stderr = "\
error[E0277]: the trait `Send` is not implemented for `Bar`
  --> src/lib.rs:42:7
error[E0308]: mismatched types
  --> src/other.rs:99:1
";
        let ctx = parse_cargo(stderr).expect("should parse");
        assert_eq!(ctx.rule, "cargo:rustc-error");
        assert_eq!(ctx.findings.len(), 2);
        assert_eq!(ctx.findings[0].code.as_deref(), Some("E0277"));
        assert_eq!(ctx.findings[1].code.as_deref(), Some("E0308"));
        assert_eq!(ctx.findings[1].file.as_deref(), Some("src/other.rs"));
        assert_eq!(ctx.findings[1].line, Some(99));
        // Summary should call out the first error and the "+1 more" tail.
        assert!(ctx.summary.contains("E0277"));
        assert!(ctx.summary.contains("+1 more"));
    }

    // -------------------------------------------------------------------------
    // Edge: error[E####] without a --> location stays code-only
    // -------------------------------------------------------------------------

    #[test]
    fn rustc_error_without_location_omits_file_line() {
        let stderr = "error[E0599]: no method named `foo` found\n";
        let ctx = parse_cargo(stderr).expect("should parse");
        assert_eq!(ctx.findings.len(), 1);
        let f = &ctx.findings[0];
        assert_eq!(f.code.as_deref(), Some("E0599"));
        assert!(f.file.is_none());
        assert!(f.line.is_none());
        assert!(f.column.is_none());
    }

    // -------------------------------------------------------------------------
    // Build-script
    // -------------------------------------------------------------------------

    #[test]
    fn parses_build_script_failure() {
        let stderr = "\
   Compiling openssl-sys v0.9.100
error: failed to run custom build command for `openssl-sys v0.9.100`

Caused by:
  process didn't exit successfully
";
        let ctx = parse_cargo(stderr).expect("should parse");
        assert_eq!(ctx.rule, "cargo:build-script-failure");
        assert_eq!(ctx.findings.len(), 1);
        let f = &ctx.findings[0];
        assert_eq!(f.code.as_deref(), Some("build-script"));
        assert!(f.message.contains("openssl-sys"));
    }

    // -------------------------------------------------------------------------
    // Linker error
    // -------------------------------------------------------------------------

    #[test]
    fn parses_linker_error_with_exit_code() {
        let stderr = "error: linking with `cc` failed: exit code: 1\n";
        let ctx = parse_cargo(stderr).expect("should parse");
        assert_eq!(ctx.rule, "cargo:linker-error");
        assert_eq!(ctx.findings.len(), 1);
        let f = &ctx.findings[0];
        assert_eq!(f.code.as_deref(), Some("linker"));
        assert!(f.message.contains("cc"));
        assert!(f.message.contains("1"));
    }

    #[test]
    fn linker_error_takes_precedence_over_rustc_errors_in_same_log() {
        // When both rustc errors AND a linker error appear (e.g.
        // dependency compiled fine but linking the binary failed),
        // the linker rule wins — that's the actionable signal.
        let stderr = "\
error[E0277]: trait not impl
  --> src/a.rs:1:1
error: linking with `link.exe` failed: exit code: 1181
";
        let ctx = parse_cargo(stderr).expect("should parse");
        assert_eq!(ctx.rule, "cargo:linker-error");
    }

    // -------------------------------------------------------------------------
    // could-not-compile fallback
    // -------------------------------------------------------------------------

    #[test]
    fn could_not_compile_synthesizes_finding_when_no_e_code_present() {
        let stderr = "\
warning: unused variable: `x`
error: could not compile `my-crate` (lib) due to 1 previous error
";
        let ctx = parse_cargo(stderr).expect("should parse");
        assert_eq!(ctx.rule, "cargo:rustc-error");
        assert_eq!(ctx.findings.len(), 1);
        let f = &ctx.findings[0];
        assert!(f.code.is_none(), "synthesized finding has no E#### code");
        assert!(f.message.contains("my-crate"));
    }

    // -------------------------------------------------------------------------
    // Bare error: <msg>
    // -------------------------------------------------------------------------

    #[test]
    fn parses_bare_error_line_without_code() {
        let stderr = "error: something arbitrary went wrong\n";
        let ctx = parse_cargo(stderr).expect("should parse");
        assert_eq!(ctx.rule, "cargo:rustc-error");
        assert_eq!(ctx.findings.len(), 1);
        let f = &ctx.findings[0];
        assert!(f.code.is_none());
        assert!(f.message.contains("something arbitrary"));
        assert!(f.file.is_none());
    }

    // -------------------------------------------------------------------------
    // Unparseable: cargo parser returns None and caller falls back
    // -------------------------------------------------------------------------

    #[test]
    fn unparseable_stderr_returns_none() {
        let stderr = "   Compiling foo v0.1.0\n    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.43s\n";
        assert!(parse_cargo(stderr).is_none());
    }
}
