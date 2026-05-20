//! Structured failure-context extraction (shipped in 1.6.0).
//!
//! When a validator gate fails (e.g. `cargo test` errors after a
//! sandboxed bump), the text report historically rendered a 4 KB raw
//! stderr tail and the operator had to read that to understand why.
//! This module exposes the *parsed*, structured shape — `FailureContext`
//! — that the per-ecosystem parsers in [`crate::failure_parser`]
//! produce, plus a `FailureCluster` grouper so a run that turns 12
//! proposals red for the same root cause renders that fact once.
//!
//! ## Stability promise
//!
//! These types serialize into the run.json receipt and the NDJSON event
//! stream. Both are covered by the 1.0 stability promise: new fields
//! are additive minor changes (gated on `#[serde(default)]`); existing
//! fields don't change shape within a major version.
//!
//! The `fingerprint` is a SHA-256 truncated to 16 lowercase hex chars
//! over the canonicalized JSON of `findings` (with findings sorted by
//! `(code, message, file, line)` first). It's the *grouping key* — two
//! proposals failing for "the same reason" by this definition share a
//! fingerprint.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Parsed, structured replacement for the raw stderr-tail dump under a
/// failed proposal. Populated by [`crate::failure_parser::parse`] on
/// every Fail outcome — never `None` when a backend reports failure,
/// even for the unparseable case (which gets `rule:"generic:unstructured"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureContext {
    /// Per-ecosystem classifier rule. Canonical values:
    /// - `"cargo:rustc-error"` — rustc emitted `error[E####]: ...`
    /// - `"cargo:build-script-failure"` — a custom build.rs failed
    /// - `"cargo:linker-error"` — link step failed
    /// - `"npm:eresolve"` — npm ERESOLVE block
    /// - `"npm:peer-dep-missing"` — peer dep advertised as missing
    /// - `"npm:tsc-error"` — TypeScript compiler error (`error TS####`)
    /// - `"generic:unstructured"` — fallback when neither cargo nor
    ///   npm patterns matched; the report shows the first non-empty
    ///   stderr line and no findings.
    pub rule: String,
    /// One-line summary suitable for inline rendering under the
    /// "[REGRESSION]" header in the text report.
    pub summary: String,
    /// Structured findings extracted from stderr. Empty for the
    /// `generic:unstructured` fallback. Otherwise one entry per
    /// extracted error (rustc errors, ERESOLVE blocks, TS errors).
    pub findings: Vec<FailureFinding>,
    /// SHA-256 truncated to 16 lowercase hex chars over the canonicalized
    /// JSON of `findings` (sorted by `(code, message, file, line)`
    /// first). Same root cause → same fingerprint. Used by
    /// [`cluster_failures`] to group proposals failing for the same
    /// reason across a run.
    pub fingerprint: String,
}

/// One concrete error extracted from stderr.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureFinding {
    /// Error code when the ecosystem provides one (`E0277`, `TS2304`,
    /// `ERESOLVE`, `peer-dep-missing`, etc.). `None` for bare
    /// `error: ...` lines without a structured tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// One-line error message extracted from the stderr line.
    pub message: String,
    /// Source location when the parser could extract one (e.g.
    /// rustc's `--> src/lib.rs:42:7`, tsc's `path(line,col)`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
}

/// A group of proposals that failed for the same root cause (shared
/// fingerprint). Singletons are NOT clusters — a cluster of 1 is just a
/// regular failure, no need to surface it. Surfaced in the text report
/// under "Root-cause clusters" and in the NDJSON `run_completed` event
/// so the GUI can collapse 12 red rows into one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureCluster {
    /// Fingerprint shared across cluster members.
    pub fingerprint: String,
    /// Proposal IDs in cluster. Sorted lexicographically so the
    /// rendering is deterministic across runs.
    pub proposal_ids: Vec<String>,
    /// Representative `FailureContext` (use the first proposal's, by
    /// lex-smallest proposal id).
    pub representative: FailureContext,
}

impl FailureContext {
    /// Build a `FailureContext` from a rule + summary + findings,
    /// computing the fingerprint from the (sorted) findings. Parsers
    /// should construct via this helper rather than building the struct
    /// literally so the fingerprint stays in sync with the findings.
    pub fn new(
        rule: impl Into<String>,
        summary: impl Into<String>,
        findings: Vec<FailureFinding>,
    ) -> Self {
        let fingerprint = compute_fingerprint(&findings);
        Self {
            rule: rule.into(),
            summary: summary.into(),
            findings,
            fingerprint,
        }
    }
}

/// Compute the canonical fingerprint over a list of findings.
///
/// Process:
/// 1. Clone the findings and sort by `(code, message, file, line)`.
/// 2. Serialize the sorted list to canonical JSON.
/// 3. SHA-256 the JSON; take the first 16 hex chars (8 bytes) of the
///    lowercase hex digest.
///
/// The empty-findings case still produces a stable digest (the SHA-256
/// of `"[]"`), so `generic:unstructured` failures cluster together by
/// rule rather than every red proposal being its own cluster.
pub fn compute_fingerprint(findings: &[FailureFinding]) -> String {
    let mut sorted = findings.to_vec();
    sorted.sort_by(|a, b| {
        a.code
            .cmp(&b.code)
            .then_with(|| a.message.cmp(&b.message))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });
    // serde_json's default object/array serialization is deterministic
    // for `Vec<FailureFinding>` (no maps with non-deterministic key
    // ordering involved), so this canonicalization is enough.
    let json = serde_json::to_string(&sorted).unwrap_or_else(|_| "[]".to_string());
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Group failed proposals into clusters by shared fingerprint.
///
/// Singletons (fingerprints with only one proposal) are dropped — a
/// cluster of one is not a cluster, it's just a regular failure. The
/// returned vector is sorted by lex-smallest proposal id within each
/// cluster so successive runs produce byte-identical output.
pub fn cluster_failures(outcomes: &[(String, FailureContext)]) -> Vec<FailureCluster> {
    use std::collections::BTreeMap;
    let mut by_fingerprint: BTreeMap<String, Vec<(String, FailureContext)>> = BTreeMap::new();
    for (id, ctx) in outcomes {
        by_fingerprint
            .entry(ctx.fingerprint.clone())
            .or_default()
            .push((id.clone(), ctx.clone()));
    }
    let mut clusters: Vec<FailureCluster> = Vec::new();
    for (fingerprint, mut members) in by_fingerprint {
        if members.len() < 2 {
            continue;
        }
        // Sort cluster members by proposal id so the representative is
        // deterministically the lex-smallest, and proposal_ids are
        // stable across runs.
        members.sort_by(|a, b| a.0.cmp(&b.0));
        let representative = members[0].1.clone();
        let proposal_ids: Vec<String> = members.iter().map(|(id, _)| id.clone()).collect();
        clusters.push(FailureCluster {
            fingerprint,
            proposal_ids,
            representative,
        });
    }
    // Sort clusters by the lex-smallest proposal id within each so
    // the output is deterministic across runs.
    clusters.sort_by(|a, b| a.proposal_ids[0].cmp(&b.proposal_ids[0]));
    clusters
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(
        code: Option<&str>,
        message: &str,
        file: Option<&str>,
        line: Option<u32>,
    ) -> FailureFinding {
        FailureFinding {
            code: code.map(String::from),
            message: message.into(),
            file: file.map(String::from),
            line,
            column: None,
        }
    }

    // -------------------------------------------------------------------------
    // compute_fingerprint
    // -------------------------------------------------------------------------

    #[test]
    fn fingerprint_is_16_lowercase_hex_chars() {
        let findings = vec![finding(
            Some("E0277"),
            "trait not implemented",
            Some("src/lib.rs"),
            Some(42),
        )];
        let fp = compute_fingerprint(&findings);
        assert_eq!(fp.len(), 16, "fingerprint must be 16 chars; got {fp}");
        assert!(
            fp.chars()
                .all(|c| c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_ascii_lowercase())),
            "fingerprint must be lowercase hex; got {fp}"
        );
    }

    #[test]
    fn fingerprint_is_deterministic_across_finding_order() {
        // Same findings in different order MUST hash to the same
        // fingerprint — this is the core invariant of the grouper.
        let a = vec![
            finding(Some("E0277"), "trait", Some("src/lib.rs"), Some(42)),
            finding(
                Some("E0308"),
                "mismatched types",
                Some("src/lib.rs"),
                Some(99),
            ),
        ];
        let mut b = a.clone();
        b.reverse();
        assert_eq!(compute_fingerprint(&a), compute_fingerprint(&b));
    }

    #[test]
    fn fingerprint_differs_when_finding_content_differs() {
        let a = vec![finding(
            Some("E0277"),
            "trait X not impl",
            Some("src/lib.rs"),
            Some(42),
        )];
        let b = vec![finding(
            Some("E0277"),
            "trait Y not impl",
            Some("src/lib.rs"),
            Some(42),
        )];
        assert_ne!(compute_fingerprint(&a), compute_fingerprint(&b));
    }

    #[test]
    fn fingerprint_for_empty_findings_is_stable_and_nonempty() {
        // The `generic:unstructured` fallback uses empty findings —
        // every unstructured failure should still group under one
        // cluster (the empty-findings fingerprint), not be its own
        // singleton.
        let fp1 = compute_fingerprint(&[]);
        let fp2 = compute_fingerprint(&[]);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 16);
    }

    // -------------------------------------------------------------------------
    // FailureContext::new
    // -------------------------------------------------------------------------

    #[test]
    fn new_attaches_canonical_fingerprint() {
        let findings = vec![finding(
            Some("E0277"),
            "trait not impl",
            Some("src/a.rs"),
            Some(1),
        )];
        let ctx = FailureContext::new("cargo:rustc-error", "summary line", findings.clone());
        assert_eq!(ctx.fingerprint, compute_fingerprint(&findings));
    }

    // -------------------------------------------------------------------------
    // cluster_failures
    // -------------------------------------------------------------------------

    fn ctx_with_finding(code: &str, msg: &str) -> FailureContext {
        FailureContext::new(
            "cargo:rustc-error",
            format!("{code}: {msg}"),
            vec![finding(Some(code), msg, None, None)],
        )
    }

    #[test]
    fn cluster_failures_returns_empty_when_no_failures() {
        let out = cluster_failures(&[]);
        assert!(out.is_empty());
    }

    #[test]
    fn cluster_failures_drops_singletons() {
        // Three distinct failures → three singletons → zero clusters.
        let outcomes = vec![
            ("p-a".into(), ctx_with_finding("E0277", "a")),
            ("p-b".into(), ctx_with_finding("E0308", "b")),
            ("p-c".into(), ctx_with_finding("E0599", "c")),
        ];
        let out = cluster_failures(&outcomes);
        assert!(
            out.is_empty(),
            "singleton fingerprints must be dropped; got {out:?}"
        );
    }

    #[test]
    fn cluster_failures_groups_matching_fingerprints() {
        // Two proposals sharing the same root cause → one cluster
        // covering both. The third proposal has its own fingerprint
        // and must NOT appear (singletons dropped).
        let shared = ctx_with_finding("E0277", "trait not implemented");
        let outcomes = vec![
            ("p-1".into(), shared.clone()),
            ("p-2".into(), shared.clone()),
            ("p-3".into(), ctx_with_finding("E0308", "mismatched types")),
        ];
        let out = cluster_failures(&outcomes);
        assert_eq!(out.len(), 1, "expected exactly one cluster; got {out:?}");
        assert_eq!(out[0].proposal_ids, vec!["p-1", "p-2"]);
        assert_eq!(out[0].fingerprint, shared.fingerprint);
        assert_eq!(out[0].representative, shared);
    }

    #[test]
    fn cluster_failures_sorts_member_ids_and_clusters_deterministically() {
        // Two clusters, inserted in scrambled order. Output must be
        // sorted by the lex-smallest member id in each cluster, and
        // each cluster's members must be sorted.
        let alpha = ctx_with_finding("E0277", "alpha");
        let beta = ctx_with_finding("E0599", "beta");
        let outcomes = vec![
            ("z-9".into(), beta.clone()),
            ("a-1".into(), alpha.clone()),
            ("m-5".into(), beta.clone()),
            ("a-2".into(), alpha.clone()),
        ];
        let out = cluster_failures(&outcomes);
        assert_eq!(out.len(), 2);
        // First cluster (alpha) starts with the smaller id `a-1`,
        // so it comes before the beta cluster (starts at `m-5`).
        assert_eq!(out[0].proposal_ids, vec!["a-1", "a-2"]);
        assert_eq!(out[1].proposal_ids, vec!["m-5", "z-9"]);
    }

    #[test]
    fn cluster_failures_round_trips_through_serde() {
        let shared = ctx_with_finding("E0277", "trait not implemented");
        let outcomes = vec![
            ("p-1".into(), shared.clone()),
            ("p-2".into(), shared.clone()),
        ];
        let clusters = cluster_failures(&outcomes);
        let json = serde_json::to_string(&clusters).unwrap();
        let back: Vec<FailureCluster> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, clusters);
    }

    #[test]
    fn failure_finding_optional_fields_skip_when_none() {
        let f = finding(None, "bare error message", None, None);
        let json = serde_json::to_string(&f).unwrap();
        assert!(
            !json.contains("\"code\""),
            "code:None must not serialize; got {json}"
        );
        assert!(
            !json.contains("\"file\""),
            "file:None must not serialize; got {json}"
        );
        assert!(
            !json.contains("\"line\""),
            "line:None must not serialize; got {json}"
        );
        assert!(
            !json.contains("\"column\""),
            "column:None must not serialize; got {json}"
        );
    }
}
