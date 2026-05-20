//! npm / pnpm / yarn / tsc stderr parser.
//!
//! Recognized patterns:
//!
//! - **ERESOLVE block** — multi-line:
//!   ```text
//!   npm ERR! code ERESOLVE
//!   npm ERR! ERESOLVE <type>
//!   npm ERR! ...
//!   npm ERR! While resolving: <consumer>@<version>
//!   npm ERR! Found: <pkg>@<version>
//!   npm ERR! Could not resolve dependency: <required>
//!   ```
//!   Produces one finding per block, `code:"ERESOLVE"`, message
//!   synthesizes the `Found: X — Could not resolve: Y` pair. Rule:
//!   `"npm:eresolve"`.
//!
//! - **peer-dep missing** —
//!   `npm ERR! peer dep missing: <pkg>, required by <consumer>`
//!   Produces a finding with `code:"peer-dep-missing"` and a message
//!   that preserves both packages. Rule: `"npm:peer-dep-missing"`.
//!
//! - **tsc error (modern)** —
//!   `<path>:<line>:<col> - error TS####: <msg>` (tsc --pretty)
//!
//! - **tsc error (legacy)** —
//!   `<path>(<line>,<col>): error TS####: <msg>` (tsc default).
//!
//!   Both produce `code:"TS####"` with file/line/column populated.
//!   Rule: `"npm:tsc-error"`.
//!
//! - **bare `npm ERR! <msg>`** — last resort when nothing structured
//!   matched. Produces a finding with `code:None`. Rule: any matched
//!   npm ERR! line bumps us into `"npm:eresolve"` only if it's the
//!   ERESOLVE form; bare lines fall under `"npm:generic"`. We use
//!   `"npm:generic"` so the dashboard can still distinguish "we
//!   knew it was npm but couldn't classify further" from
//!   "couldn't tell what ecosystem".
//!
//! `npm WARN ERESOLVE` is explicitly skipped — that's a warning,
//! not an error.

use regex::Regex;
use std::sync::OnceLock;

use crate::failure_context::{FailureContext, FailureFinding};

/// Line prefix that marks an actual npm error (not a warn).
const NPM_ERR_PREFIX: &str = "npm ERR!";

/// `npm ERR! peer dep missing: <pkg>, required by <consumer>`
fn peer_dep_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"^\s*npm ERR!\s+peer dep missing:\s+(.+?)(?:,\s*required by\s+(.+?))?\s*$")
            .unwrap()
    })
}

/// tsc modern: `<path>:<line>:<col> - error TS####: <msg>`
fn tsc_modern_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^(.+?):(\d+):(\d+)\s*-\s*error\s+(TS\d+):\s*(.+?)\s*$").unwrap())
}

/// tsc legacy: `<path>(<line>,<col>): error TS####: <msg>`
fn tsc_legacy_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^(.+?)\((\d+),(\d+)\):\s*error\s+(TS\d+):\s*(.+?)\s*$").unwrap())
}

/// Parse npm/tsc-style stderr. Returns `None` if nothing matched.
pub(super) fn parse_npm(stderr: &str) -> Option<FailureContext> {
    let lines: Vec<&str> = stderr.lines().collect();

    // tsc errors — most actionable since they pin file+line. Check
    // before ERESOLVE so a tsc run with both kinds of output (tsc
    // emitting an ERESOLVE-shaped line through stdout, then erroring)
    // still surfaces the compiler errors as the primary signal.
    let mut tsc_findings: Vec<FailureFinding> = Vec::new();
    for line in &lines {
        let trimmed = line.trim_end();
        if let Some(caps) = tsc_modern_re().captures(trimmed) {
            tsc_findings.push(FailureFinding {
                code: caps.get(4).map(|m| m.as_str().to_string()),
                message: caps.get(5).map_or("", |m| m.as_str()).to_string(),
                file: caps.get(1).map(|m| m.as_str().to_string()),
                line: caps.get(2).and_then(|m| m.as_str().parse().ok()),
                column: caps.get(3).and_then(|m| m.as_str().parse().ok()),
            });
            continue;
        }
        if let Some(caps) = tsc_legacy_re().captures(trimmed) {
            tsc_findings.push(FailureFinding {
                code: caps.get(4).map(|m| m.as_str().to_string()),
                message: caps.get(5).map_or("", |m| m.as_str()).to_string(),
                file: caps.get(1).map(|m| m.as_str().to_string()),
                line: caps.get(2).and_then(|m| m.as_str().parse().ok()),
                column: caps.get(3).and_then(|m| m.as_str().parse().ok()),
            });
        }
    }
    if !tsc_findings.is_empty() {
        let summary = format_summary(&tsc_findings);
        return Some(FailureContext::new("npm:tsc-error", summary, tsc_findings));
    }

    // ERESOLVE blocks. We look for "npm ERR! code ERESOLVE" to mark a
    // block start, then collect Found:/Could not resolve: pairs until
    // the block ends (a non-npm-ERR! line or another "code ERESOLVE").
    let mut eresolve_findings: Vec<FailureFinding> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i];
        if matches_eresolve_start(l) {
            // Walk forward collecting Found:/Could not resolve.
            let mut found: Option<String> = None;
            let mut not_resolved: Option<String> = None;
            let mut while_resolving: Option<String> = None;
            let mut j = i + 1;
            while j < lines.len() {
                let next = lines[j].trim();
                if !next.starts_with(NPM_ERR_PREFIX) {
                    break;
                }
                let body = next[NPM_ERR_PREFIX.len()..].trim();
                if let Some(rest) = body.strip_prefix("Found:") {
                    found = Some(rest.trim().to_string());
                } else if let Some(rest) = body.strip_prefix("Could not resolve dependency:") {
                    not_resolved = Some(rest.trim().to_string());
                } else if let Some(rest) = body.strip_prefix("While resolving:") {
                    while_resolving = Some(rest.trim().to_string());
                } else if body.starts_with("code ERESOLVE") {
                    // start of another block — stop walking this one
                    break;
                }
                j += 1;
            }
            if found.is_some() || not_resolved.is_some() {
                let msg = match (&found, &not_resolved, &while_resolving) {
                    (Some(f), Some(nr), Some(wr)) => {
                        format!("while resolving {wr}: found {f}; could not resolve {nr}")
                    }
                    (Some(f), Some(nr), None) => format!("found {f}; could not resolve {nr}"),
                    (Some(f), None, _) => format!("found {f}"),
                    (None, Some(nr), _) => format!("could not resolve {nr}"),
                    _ => "ERESOLVE".to_string(),
                };
                eresolve_findings.push(FailureFinding {
                    code: Some("ERESOLVE".into()),
                    message: msg,
                    file: None,
                    line: None,
                    column: None,
                });
            }
            i = j;
            continue;
        }
        i += 1;
    }
    if !eresolve_findings.is_empty() {
        let summary = format_summary(&eresolve_findings);
        return Some(FailureContext::new(
            "npm:eresolve",
            summary,
            eresolve_findings,
        ));
    }

    // peer-dep missing — single-line pattern.
    let mut peer_findings: Vec<FailureFinding> = Vec::new();
    for line in &lines {
        if let Some(caps) = peer_dep_re().captures(line) {
            let pkg = caps.get(1).map_or("", |m| m.as_str()).trim();
            let by = caps.get(2).map(|m| m.as_str().trim()).unwrap_or("");
            let message = if by.is_empty() {
                format!("peer dep missing: {pkg}")
            } else {
                format!("peer dep missing: {pkg}, required by {by}")
            };
            peer_findings.push(FailureFinding {
                code: Some("peer-dep-missing".into()),
                message,
                file: None,
                line: None,
                column: None,
            });
        }
    }
    if !peer_findings.is_empty() {
        let summary = format_summary(&peer_findings);
        return Some(FailureContext::new(
            "npm:peer-dep-missing",
            summary,
            peer_findings,
        ));
    }

    // Bare `npm ERR! <msg>` — last resort. Filter out the noisy lines
    // npm prints around every error (the version/code header, the
    // log-file pointer at the end).
    let mut bare_msg: Option<String> = None;
    for line in &lines {
        let trimmed = line.trim();
        if !trimmed.starts_with(NPM_ERR_PREFIX) {
            continue;
        }
        let body = trimmed[NPM_ERR_PREFIX.len()..].trim();
        if body.is_empty()
            || body.starts_with("code ")
            || body.starts_with("A complete log of this run")
            || body.starts_with("This is a problem related to")
            || body == "ERESOLVE"
        {
            continue;
        }
        bare_msg = Some(body.to_string());
        break;
    }
    if let Some(message) = bare_msg {
        let finding = FailureFinding {
            code: None,
            message: message.clone(),
            file: None,
            line: None,
            column: None,
        };
        return Some(FailureContext::new("npm:generic", message, vec![finding]));
    }

    None
}

fn matches_eresolve_start(line: &str) -> bool {
    let t = line.trim();
    t.starts_with(NPM_ERR_PREFIX) && t.contains("code ERESOLVE")
}

fn format_summary(findings: &[FailureFinding]) -> String {
    let first = &findings[0];
    let code = first.code.as_deref().unwrap_or("npm");
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
    // Canonical: ERESOLVE block
    // -------------------------------------------------------------------------

    #[test]
    fn parses_canonical_eresolve_block() {
        let stderr = "\
npm ERR! code ERESOLVE
npm ERR! ERESOLVE unable to resolve dependency tree
npm ERR!
npm ERR! While resolving: app@1.0.0
npm ERR! Found: react@17.0.2
npm ERR! Could not resolve dependency:
npm ERR! peer react@\"^18.0.0\" from @some/lib@1.0.0
npm ERR!
npm ERR! A complete log of this run can be found in: /tmp/log
";
        let ctx = parse_npm(stderr).expect("should parse");
        assert_eq!(ctx.rule, "npm:eresolve");
        assert_eq!(ctx.findings.len(), 1);
        let f = &ctx.findings[0];
        assert_eq!(f.code.as_deref(), Some("ERESOLVE"));
        assert!(f.message.contains("react@17"));
        assert!(f.message.contains("app@1.0.0") || f.message.contains("resolving"));
    }

    // -------------------------------------------------------------------------
    // Edge: ERESOLVE WARN is NOT an error and must be skipped
    // -------------------------------------------------------------------------

    #[test]
    fn npm_warn_eresolve_is_not_an_error_and_does_not_match() {
        let stderr = "\
npm WARN ERESOLVE overriding peer dependency
npm WARN Found: react@17.0.2
npm WARN Could not resolve dependency: peer react@^18.0.0
";
        // No npm ERR! at all → npm parser should not match.
        assert!(parse_npm(stderr).is_none());
    }

    // -------------------------------------------------------------------------
    // Multi-finding: two ERESOLVE blocks in one log
    // -------------------------------------------------------------------------

    #[test]
    fn parses_multiple_eresolve_blocks_as_multi_finding() {
        let stderr = "\
npm ERR! code ERESOLVE
npm ERR! Found: react@17.0.2
npm ERR! Could not resolve dependency: react@^18.0.0
npm ERR! code ERESOLVE
npm ERR! Found: vue@2.6
npm ERR! Could not resolve dependency: vue@^3.0
";
        let ctx = parse_npm(stderr).expect("should parse");
        assert_eq!(ctx.findings.len(), 2);
        assert!(ctx.findings[0].message.contains("react"));
        assert!(ctx.findings[1].message.contains("vue"));
        assert!(ctx.summary.contains("+1 more"));
    }

    // -------------------------------------------------------------------------
    // peer-dep missing
    // -------------------------------------------------------------------------

    #[test]
    fn parses_peer_dep_missing() {
        let stderr = "npm ERR! peer dep missing: react@^18.0.0, required by @some/lib@1.0.0\n";
        let ctx = parse_npm(stderr).expect("should parse");
        assert_eq!(ctx.rule, "npm:peer-dep-missing");
        assert_eq!(ctx.findings.len(), 1);
        let f = &ctx.findings[0];
        assert_eq!(f.code.as_deref(), Some("peer-dep-missing"));
        assert!(f.message.contains("react@^18.0.0"));
        assert!(f.message.contains("@some/lib@1.0.0"));
    }

    // -------------------------------------------------------------------------
    // tsc modern
    // -------------------------------------------------------------------------

    #[test]
    fn parses_tsc_modern_error_with_location() {
        let stderr = "src/app.ts:12:5 - error TS2304: Cannot find name 'window'.\n";
        let ctx = parse_npm(stderr).expect("should parse");
        assert_eq!(ctx.rule, "npm:tsc-error");
        assert_eq!(ctx.findings.len(), 1);
        let f = &ctx.findings[0];
        assert_eq!(f.code.as_deref(), Some("TS2304"));
        assert_eq!(f.file.as_deref(), Some("src/app.ts"));
        assert_eq!(f.line, Some(12));
        assert_eq!(f.column, Some(5));
    }

    // -------------------------------------------------------------------------
    // tsc legacy
    // -------------------------------------------------------------------------

    #[test]
    fn parses_tsc_legacy_error_with_location() {
        let stderr = "src/app.ts(12,5): error TS2304: Cannot find name 'window'.\n";
        let ctx = parse_npm(stderr).expect("should parse");
        assert_eq!(ctx.rule, "npm:tsc-error");
        assert_eq!(ctx.findings.len(), 1);
        let f = &ctx.findings[0];
        assert_eq!(f.code.as_deref(), Some("TS2304"));
        assert_eq!(f.file.as_deref(), Some("src/app.ts"));
        assert_eq!(f.line, Some(12));
        assert_eq!(f.column, Some(5));
    }

    // -------------------------------------------------------------------------
    // Multi-finding tsc
    // -------------------------------------------------------------------------

    #[test]
    fn parses_multiple_tsc_errors() {
        let stderr = "\
src/a.ts:1:1 - error TS2304: Cannot find name 'foo'.
src/b.ts:10:5 - error TS2345: Argument type mismatch.
";
        let ctx = parse_npm(stderr).expect("should parse");
        assert_eq!(ctx.findings.len(), 2);
        assert!(ctx.summary.contains("+1 more"));
    }

    // -------------------------------------------------------------------------
    // Bare npm ERR!
    // -------------------------------------------------------------------------

    #[test]
    fn parses_bare_npm_err_line_when_no_structured_pattern_matched() {
        let stderr = "npm ERR! Could not write to lockfile\n";
        let ctx = parse_npm(stderr).expect("should parse");
        assert_eq!(ctx.rule, "npm:generic");
        assert_eq!(ctx.findings.len(), 1);
        assert!(ctx.findings[0].code.is_none());
        assert!(
            ctx.findings[0]
                .message
                .contains("Could not write to lockfile")
        );
    }

    // -------------------------------------------------------------------------
    // Unparseable
    // -------------------------------------------------------------------------

    #[test]
    fn unparseable_stderr_returns_none() {
        let stderr = "added 142 packages, and audited 143 packages in 3s\n";
        assert!(parse_npm(stderr).is_none());
    }
}
