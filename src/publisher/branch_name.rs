//! Deterministic, injective branch-name generation for assay PRs.
//!
//! Properties guaranteed:
//!
//! - **Deterministic** — same `Proposal` always produces the same branch
//!   name. Re-running the same scan against the same state hits the same
//!   branch and aborts cleanly via the publisher's "branch already exists"
//!   guard rather than opening duplicate PRs.
//!
//! - **Injective on the bump tuple** — two proposals that differ in any
//!   of (ecosystem, subject, from, to) produce different branch names.
//!   Tested directly.
//!
//! - **Charset-safe** — every output character is in `[a-z0-9/-]`. No
//!   special-character escape needed when interpolating into git
//!   commands or REST API calls.
//!
//! - **Length-bounded** — total length ≤ 250 bytes (under git's 255-byte
//!   ref-name cap). The hash suffix absorbs subject/version variation
//!   that would otherwise blow the limit.

use sha2::{Digest, Sha256};

/// Maximum total branch name length. Git's ref-name limit is 255 bytes;
/// we cap a bit shorter to leave room for remote-prefix conventions.
const MAX_BRANCH_LEN: usize = 250;

/// Length of the SHA-256-derived short hash suffix appended for
/// disambiguation.
const HASH_SUFFIX_LEN: usize = 12;

/// Build a deterministic, injective branch name for a bump proposal.
///
/// Shape: `assay/<ecosystem>/<safe-subject>-<short-version>-<hash>`
///
/// Example: `assay/cargo/serde-1-0-215-a3f9b2c41058`.
pub fn branch_name_for_bump(ecosystem: &str, subject: &str, from: &str, to: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"assay:v1:");
    hasher.update(ecosystem.as_bytes());
    hasher.update(b":");
    hasher.update(subject.as_bytes());
    hasher.update(b":");
    hasher.update(from.as_bytes());
    hasher.update(b":");
    hasher.update(to.as_bytes());
    let digest = hasher.finalize();
    let hash_hex = hex_lowercase(&digest[..6]); // 12 hex chars = 6 bytes
    debug_assert_eq!(hash_hex.len(), HASH_SUFFIX_LEN);

    let safe_eco = kebab_lowercase(ecosystem);
    let safe_subject = kebab_lowercase(subject);
    let safe_to = kebab_lowercase(to);

    // Compute the budget for the human-readable middle segment.
    let prefix = format!("assay/{safe_eco}/");
    let suffix = format!("-{hash_hex}");
    let middle_budget = MAX_BRANCH_LEN
        .saturating_sub(prefix.len())
        .saturating_sub(suffix.len());

    let mut middle = format!("{safe_subject}-{safe_to}");
    if middle.len() > middle_budget {
        // Truncate but keep enough subject to be human-readable. The
        // hash suffix preserves injectivity even when the middle is
        // truncated.
        middle.truncate(middle_budget);
        middle = middle.trim_end_matches('-').to_string();
    }
    format!("{prefix}{middle}{suffix}")
}

/// Lower-case kebab. Collapses runs of dashes; trims leading/trailing
/// dashes; replaces anything outside `[a-z0-9-]` with `-`.
fn kebab_lowercase(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut last_dash = true; // suppress leading dashes
    for ch in value.chars().flat_map(|c| c.to_lowercase()) {
        let safe = if ch.is_ascii_alphanumeric() { ch } else { '-' };
        if safe == '-' {
            if !last_dash {
                out.push('-');
            }
            last_dash = true;
        } else {
            out.push(safe);
            last_dash = false;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

fn hex_lowercase(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_name_for_typical_cargo_bump() {
        let name = branch_name_for_bump("cargo", "serde", "1.0.200", "1.0.215");
        assert!(name.starts_with("assay/cargo/serde-1-0-215-"));
        assert!(name.len() <= MAX_BRANCH_LEN);
    }

    #[test]
    fn branch_name_is_deterministic() {
        // Same inputs → identical outputs across multiple calls.
        let a = branch_name_for_bump("cargo", "serde", "1.0.200", "1.0.215");
        let b = branch_name_for_bump("cargo", "serde", "1.0.200", "1.0.215");
        assert_eq!(a, b);
    }

    #[test]
    fn branch_name_is_injective_on_subject() {
        let a = branch_name_for_bump("cargo", "serde", "1.0.200", "1.0.215");
        let b = branch_name_for_bump("cargo", "tokio", "1.0.200", "1.0.215");
        assert_ne!(a, b);
    }

    #[test]
    fn branch_name_is_injective_on_from() {
        let a = branch_name_for_bump("cargo", "serde", "1.0.200", "1.0.215");
        let b = branch_name_for_bump("cargo", "serde", "1.0.201", "1.0.215");
        assert_ne!(a, b);
    }

    #[test]
    fn branch_name_is_injective_on_to() {
        let a = branch_name_for_bump("cargo", "serde", "1.0.200", "1.0.215");
        let b = branch_name_for_bump("cargo", "serde", "1.0.200", "1.0.216");
        assert_ne!(a, b);
    }

    #[test]
    fn branch_name_is_injective_on_ecosystem() {
        let a = branch_name_for_bump("cargo", "actions/checkout", "x", "y");
        let b = branch_name_for_bump("github-actions", "actions/checkout", "x", "y");
        assert_ne!(a, b);
    }

    #[test]
    fn branch_name_charset_is_safe() {
        // Construct a hostile subject; the result must still be charset-safe.
        let name = branch_name_for_bump("cargo", "Some/Crate@with.dots", "1.0.0", "v2.0.0");
        for ch in name.chars() {
            assert!(
                ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '/'),
                "illegal char {ch:?} in branch name: {name}"
            );
        }
    }

    #[test]
    fn branch_name_never_double_dashes_or_trailing_dash() {
        let name = branch_name_for_bump(
            "cargo",
            "/--leading-and-trailing--/",
            "v---1",
            "---v2.0.0---",
        );
        assert!(!name.contains("--"));
        assert!(!name.contains("-/"));
        assert!(!name.contains("/-"));
        // Trailing-dash trim survives in the kebabed inputs.
        let middle_after_prefix = &name["assay/cargo/".len()..];
        assert!(
            !middle_after_prefix.starts_with('-'),
            "middle starts with dash: {name}"
        );
    }

    #[test]
    fn branch_name_respects_length_cap() {
        let huge_subject: String = "x".repeat(500);
        let huge_version: String = "9".repeat(200);
        let name = branch_name_for_bump("cargo", &huge_subject, "0.1.0", &huge_version);
        assert!(
            name.len() <= MAX_BRANCH_LEN,
            "name exceeded cap: {} bytes",
            name.len()
        );
        // Hash suffix is still present so injectivity survives truncation.
        assert!(name.contains('-'));
        let last_segment = name.rsplit_once('-').map(|(_, s)| s).unwrap();
        assert_eq!(last_segment.len(), HASH_SUFFIX_LEN);
    }

    #[test]
    fn branch_name_truncation_is_still_injective() {
        // Two long names that differ only past the truncation boundary
        // must still produce different branch names thanks to the hash.
        let mut subject_a = "x".repeat(300);
        let mut subject_b = "x".repeat(300);
        subject_a.push('a');
        subject_b.push('b');
        let a = branch_name_for_bump("cargo", &subject_a, "1", "2");
        let b = branch_name_for_bump("cargo", &subject_b, "1", "2");
        assert_ne!(a, b);
    }
}
