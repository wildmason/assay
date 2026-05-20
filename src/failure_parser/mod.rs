//! Per-ecosystem stderr parsers that lift unstructured tail output
//! into the structured `FailureContext` shape rendered by the text
//! report and surfaced on the NDJSON event stream.
//!
//! Entry point: [`parse`]. The caller passes the captured stderr and
//! an [`EcosystemHint`] derived from which backend ran (Cargo for
//! `cargo build`/`cargo test`, Npm for `npm`/`pnpm`/`yarn`/`tsc`,
//! Auto for back-compat / unknown gates).
//!
//! Contract: `parse` ALWAYS returns a populated `FailureContext`,
//! never `None`. When no parser matches anything, the result carries
//! `rule:"generic:unstructured"`, the first non-empty stderr line as
//! the summary, an empty findings vector, and the empty-findings
//! fingerprint. This guarantees the text report and event stream
//! always have *something* to render under a red proposal, even if
//! it's just "we couldn't parse this — here's the raw log appendix".

use crate::failure_context::FailureContext;

mod cargo;
mod generic;
mod npm;

/// Which ecosystem's parsers to try, and in what order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcosystemHint {
    /// Try cargo patterns only. Used when the validator backend's
    /// command vector starts with `cargo`.
    Cargo,
    /// Try npm/tsc patterns only. Used when the command vector starts
    /// with `npm`/`pnpm`/`yarn`/`npx`/`tsc`.
    Npm,
    /// Try cargo first, then npm, falling back to generic. Used by
    /// `ForgeRunBackend` and `CustomBackend` which don't have a
    /// definitive ecosystem signal at parse time.
    Auto,
}

/// Lift unstructured stderr into a structured `FailureContext`.
/// ALWAYS returns a populated `FailureContext` — see module docs.
pub fn parse(stderr: &str, hint: EcosystemHint) -> FailureContext {
    match hint {
        EcosystemHint::Cargo => {
            cargo::parse_cargo(stderr).unwrap_or_else(|| generic::parse_generic(stderr))
        }
        EcosystemHint::Npm => {
            npm::parse_npm(stderr).unwrap_or_else(|| generic::parse_generic(stderr))
        }
        EcosystemHint::Auto => cargo::parse_cargo(stderr)
            .or_else(|| npm::parse_npm(stderr))
            .unwrap_or_else(|| generic::parse_generic(stderr)),
    }
}

/// Decide whether a command vector points at the cargo or npm
/// ecosystem. Used by `BuildTestBackend` and `CustomBackend` to
/// pick a hint from their stored argv.
pub fn hint_from_command(cmd: &[String]) -> EcosystemHint {
    let Some(bin) = cmd.first() else {
        return EcosystemHint::Auto;
    };
    // Strip a possible Windows ".exe" suffix and any directory prefix.
    let bin_lower = bin
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(bin)
        .trim_end_matches(".exe")
        .to_ascii_lowercase();
    match bin_lower.as_str() {
        "cargo" | "rustc" => EcosystemHint::Cargo,
        "npm" | "pnpm" | "yarn" | "npx" | "tsc" | "node" => EcosystemHint::Npm,
        _ => EcosystemHint::Auto,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_falls_through_to_generic_for_empty_stderr() {
        let ctx = parse("", EcosystemHint::Auto);
        assert_eq!(ctx.rule, "generic:unstructured");
        assert!(ctx.findings.is_empty());
        // Empty stderr → empty summary, but the fingerprint is still
        // the canonical empty-findings hash so unstructured failures
        // cluster together.
        assert_eq!(ctx.fingerprint.len(), 16);
    }

    #[test]
    fn auto_prefers_cargo_when_both_match() {
        // Stderr contains a cargo-style error — Auto should hit cargo
        // first and never fall through to npm.
        let stderr =
            "error[E0277]: the trait `Foo` is not implemented for `Bar`\n  --> src/lib.rs:42:7\n";
        let ctx = parse(stderr, EcosystemHint::Auto);
        assert_eq!(ctx.rule, "cargo:rustc-error");
    }

    #[test]
    fn hint_from_command_recognizes_cargo_and_npm_binaries() {
        assert_eq!(hint_from_command(&["cargo".into()]), EcosystemHint::Cargo);
        assert_eq!(hint_from_command(&["npm".into()]), EcosystemHint::Npm);
        assert_eq!(hint_from_command(&["pnpm".into()]), EcosystemHint::Npm);
        assert_eq!(hint_from_command(&["yarn".into()]), EcosystemHint::Npm);
        assert_eq!(hint_from_command(&["tsc".into()]), EcosystemHint::Npm);
        // Windows binary suffix is stripped.
        assert_eq!(
            hint_from_command(&["cargo.exe".into()]),
            EcosystemHint::Cargo
        );
        // Absolute path is reduced to the basename.
        assert_eq!(
            hint_from_command(&["/usr/bin/cargo".into()]),
            EcosystemHint::Cargo
        );
        assert_eq!(
            hint_from_command(&["C:\\path\\to\\npm.exe".into()]),
            EcosystemHint::Npm
        );
        // Unknown / empty → Auto.
        assert_eq!(
            hint_from_command(&["custom-script".into()]),
            EcosystemHint::Auto
        );
        assert_eq!(hint_from_command(&[]), EcosystemHint::Auto);
    }
}
