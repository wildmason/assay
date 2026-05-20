//! Two-layer redactor.
//!
//! Layer 1: explicit value registry. Mirrors ci-forge's existing redaction
//! shape (`crates/forge-cli/src/github.rs:1812`) — register known secret
//! values up front, then literal-string-replace them anywhere they appear
//! in output. Values must be at least 3 bytes to avoid mangling short
//! random matches.
//!
//! Layer 2: regex pre-filter. Catches GitHub token shapes (`ghs_*`,
//! `ghu_*`, `Bearer ...`) even when the specific value wasn't pre-
//! registered — defense in depth against forgetting to call `register`
//! after a fresh token mint. The two layers compose: the registry runs
//! first (so known values are scrubbed even inside Bearer headers), then
//! the regex pass replaces anything matching a token shape that survived.

use std::sync::{Arc, RwLock};

use regex::Regex;

/// Pluggable redactor. Cheap to clone (Arc internally) so it can be
/// stamped across stages of the pipeline without lifetime gymnastics.
#[derive(Clone)]
pub struct Redactor {
    inner: Arc<RwLock<Inner>>,
    token_regex: Arc<Regex>,
}

struct Inner {
    values: Vec<String>,
}

const MIN_LITERAL_LEN: usize = 3;
const REPLACEMENT: &str = "***";

// The regex deliberately accepts the full character set GitHub uses for
// these token shapes (alphanumerics + `_`/`-`/`.`/`/`). The exact length
// of installation tokens has shifted across GitHub Apps generations, so
// we accept 30+ rather than nailing a specific count and getting a CVE
// when the shape changes again.
const GITHUB_TOKEN_SHAPE: &str = r"\b(ghs|ghu|ghp|gho|ghr)_[A-Za-z0-9_]{30,}";
const BEARER_TOKEN_SHAPE: &str = r"(?i)\bBearer\s+[A-Za-z0-9._\-/+=]{16,}";
const AUTHORIZATION_HEADER_SHAPE: &str = r"(?i)Authorization:\s*[^\r\n]+";

impl Redactor {
    pub fn new() -> Self {
        // The compiled regex covers all three known shapes via alternation.
        // Compile errors here would be a static defect; unwrap is OK.
        let combined =
            format!("({GITHUB_TOKEN_SHAPE})|({BEARER_TOKEN_SHAPE})|({AUTHORIZATION_HEADER_SHAPE})");
        let token_regex = Regex::new(&combined).expect("token regex must compile");
        Self {
            inner: Arc::new(RwLock::new(Inner { values: Vec::new() })),
            token_regex: Arc::new(token_regex),
        }
    }

    /// Register a secret value to be scrubbed on every future `redact`
    /// call. Values shorter than `MIN_LITERAL_LEN` are silently dropped
    /// because replacing very short strings has more false-positive risk
    /// than masking value.
    pub fn register(&self, value: impl Into<String>) {
        let v = value.into();
        if v.len() < MIN_LITERAL_LEN {
            return;
        }
        let mut inner = self.inner.write().expect("redactor lock poisoned");
        if !inner.values.iter().any(|existing| existing == &v) {
            inner.values.push(v);
            // Sort longest-first so when one value is a substring of
            // another, the longer one gets matched first and the shorter
            // doesn't leave dangling fragments.
            inner.values.sort_by_key(|v| std::cmp::Reverse(v.len()));
        }
    }

    /// Apply both layers (value-registry then regex shape) to a string.
    /// Returns the redacted string. Operates on owned String so callers
    /// can chain easily.
    pub fn redact(&self, input: &str) -> String {
        let mut out = input.to_string();
        // Layer 1: registered values.
        {
            let inner = self.inner.read().expect("redactor lock poisoned");
            for value in &inner.values {
                if !value.is_empty() {
                    out = out.replace(value.as_str(), REPLACEMENT);
                }
            }
        }
        // Layer 2: token-shape regex.
        out = self.token_regex.replace_all(&out, REPLACEMENT).into_owned();
        out
    }

    /// Number of currently registered values. Test-only inspection.
    #[cfg(test)]
    pub fn registered_count(&self) -> usize {
        self.inner
            .read()
            .expect("redactor lock poisoned")
            .values
            .len()
    }
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.read().map_err(|_| std::fmt::Error)?;
        f.debug_struct("Redactor")
            .field("registered_values_count", &inner.values.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_replaces_known_value() {
        let r = Redactor::new();
        r.register("hunter2-secret-password");
        let out = r.redact("logging in with hunter2-secret-password right now");
        assert_eq!(out, "logging in with *** right now");
    }

    #[test]
    fn registry_ignores_too_short_values() {
        let r = Redactor::new();
        r.register("a");
        r.register("ab");
        assert_eq!(r.registered_count(), 0);
    }

    #[test]
    fn registry_handles_overlapping_values_longest_first() {
        let r = Redactor::new();
        r.register("token-abc");
        r.register("token-abc-extended");
        // Both registered; the longer one must be replaced first so the
        // shorter doesn't leave a `-extended` fragment behind.
        let out = r.redact("see token-abc-extended in log");
        assert_eq!(out, "see *** in log");
    }

    #[test]
    fn regex_layer_catches_unregistered_ghs_token() {
        // 36-char installation token shape — never registered with the
        // redactor, but caught by the regex pre-filter.
        let r = Redactor::new();
        let token = "ghs_abcdefghijklmnopqrstuvwxyz0123456789AB";
        let out = r.redact(&format!("Authorization: token {token}"));
        assert!(!out.contains(token), "raw token leaked: {out}");
        assert!(out.contains("***"), "expected replacement marker: {out}");
    }

    #[test]
    fn regex_layer_catches_unregistered_ghu_token() {
        let r = Redactor::new();
        let token = "ghu_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxAB";
        let out = r.redact(token);
        assert!(!out.contains(token));
        assert!(out.contains("***"));
    }

    #[test]
    fn regex_layer_catches_bearer_header() {
        let r = Redactor::new();
        let line = "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.payload.signature";
        let out = r.redact(line);
        // The whole `Authorization:` header pattern matches first,
        // collapsing to a single replacement.
        assert!(!out.contains("eyJ"), "JWT payload leaked: {out}");
        assert!(out.contains("***"));
    }

    #[test]
    fn regex_layer_does_not_corrupt_normal_log_lines() {
        let r = Redactor::new();
        let line = "starting cargo update --workspace at 12:00:00";
        assert_eq!(r.redact(line), line);
    }

    #[test]
    fn registry_and_regex_compose() {
        let r = Redactor::new();
        // Register a value that's NOT a github token shape.
        r.register("private-key-fingerprint-abc");
        // Pass a string with both: a registered value AND a github token.
        let line = "fingerprint=private-key-fingerprint-abc, token=ghs_abcdefghijklmnopqrstuvwxyz0123456789AB";
        let out = r.redact(line);
        assert!(!out.contains("private-key-fingerprint-abc"));
        assert!(!out.contains("ghs_"));
    }

    #[test]
    fn redactor_is_thread_safe_clonable() {
        let r = Redactor::new();
        r.register("shared-secret");
        let r2 = r.clone();
        // Both handles see the same registered value.
        assert_eq!(r2.redact("shared-secret leaked"), "*** leaked");
    }

    #[test]
    fn registering_same_value_twice_is_idempotent() {
        let r = Redactor::new();
        r.register("token-once");
        r.register("token-once");
        assert_eq!(r.registered_count(), 1);
    }

    #[test]
    fn debug_does_not_print_registered_values() {
        let r = Redactor::new();
        r.register("super-secret-value");
        let s = format!("{r:?}");
        assert!(!s.contains("super-secret-value"));
        assert!(s.contains("registered_values_count"));
    }
}
