//! Verdict cache — content-addressed reuse of validator outcomes.
//!
//! Validator runs the project's full GHA gate workflow (or
//! manifest-inferred build+test, or operator-supplied `--gate-cmd`) for
//! every (proposal, workflow) pair. When multiple proposals produce
//! byte-identical post-apply lockfile state — common in Cargo workspaces
//! where transitive bumps converge — the validator re-pays the same CI
//! cost N times.
//!
//! The cache short-circuits that. The key is a SHA-256 over
//! `(schema_version, backend_name, event, workspace_fingerprint,
//! workflow_fingerprint)` where the two fingerprints are themselves
//! SHA-256 over the post-apply manifest+lockfile contents and the
//! workflow file content (or the canonicalized backend command list for
//! tree-mode backends). On hit the cached outcome is rendered into a
//! `WorkflowOutcome` and tagged `cached_at` so the report can surface it.
//!
//! Only deterministic verdicts (`Pass` and `Regression`) are cached.
//! `SetupFailure` and `Timeout` are environment-dependent and a re-run
//! may legitimately produce a different verdict, so they are never
//! written and the call site must filter them out before write.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Bump when the on-disk shape of [`CacheEntry`] changes. Old entries
/// will be ignored as cache misses (the schema_version is embedded in
/// the key, so old entries land at different filenames anyway).
pub const CACHE_SCHEMA_VERSION: u32 = 1;

/// Default TTL for cache entries (7 days).
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Inputs that derive a [`CacheKey`]. Caller is responsible for hashing
/// the manifest+lockfile contents into `workspace_fingerprint` and the
/// workflow file content (or backend command signature) into
/// `workflow_fingerprint` first.
#[derive(Debug, Clone)]
pub struct CacheKeyInputs<'a> {
    pub workspace_fingerprint: &'a str,
    pub workflow_fingerprint: &'a str,
    pub backend_name: &'a str,
    pub event: &'a str,
    pub schema_version: u32,
}

/// Content-addressed cache key. The hex string is filesystem-safe and
/// suitable for direct use as a filename.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheKey(String);

impl CacheKey {
    /// Pure derivation: same inputs → same key, regardless of host.
    pub fn compute(inputs: &CacheKeyInputs<'_>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(inputs.schema_version.to_le_bytes());
        hasher.update([0u8]);
        hasher.update(inputs.backend_name.as_bytes());
        hasher.update([0u8]);
        hasher.update(inputs.event.as_bytes());
        hasher.update([0u8]);
        hasher.update(inputs.workspace_fingerprint.as_bytes());
        hasher.update([0u8]);
        hasher.update(inputs.workflow_fingerprint.as_bytes());
        let digest = hasher.finalize();
        Self(hex_encode(&digest))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Path to the on-disk cache file for this key inside `cache_dir`.
    pub fn file_in(&self, cache_dir: &Path) -> PathBuf {
        cache_dir.join(format!("{}.json", self.0))
    }
}

/// Deterministic verdict shape. Only `Pass` and `Regression` outcomes
/// are persisted — `SetupFailure` and `Timeout` are not (they're
/// environment-dependent and re-running may produce a different result).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CachedVerdict {
    Pass,
    Regression { details: String },
}

/// Echo of the inputs that produced this entry's key. Stored on disk so
/// `assay` can audit cache hits and so a future `--explain-cache` can
/// render the chain of fingerprints that justified the verdict reuse.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CachedInputs {
    pub workspace_fingerprint: String,
    pub workflow_fingerprint: String,
    pub backend_name: String,
    pub event: String,
}

/// A single cached validator outcome.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheEntry {
    pub schema_version: u32,
    pub cache_key: String,
    pub verdict: CachedVerdict,
    pub forge_run_id: Option<String>,
    pub log_path: Option<PathBuf>,
    pub duration_ms: u128,
    pub stderr_tail: String,
    pub backend: String,
    pub cached_at_unix_secs: u64,
    pub inputs: CachedInputs,
}

impl CacheEntry {
    /// `true` when `now - cached_at_unix_secs > ttl`. A negative skew
    /// (cached_at in the future) is treated as fresh — clock drift
    /// shouldn't invalidate an entry that was just written by the same
    /// host.
    pub fn is_stale(&self, ttl: Duration, now: SystemTime) -> bool {
        let now_unix = now
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let age = now_unix.saturating_sub(self.cached_at_unix_secs);
        age > ttl.as_secs()
    }
}

/// Filesystem-backed verdict cache.
#[derive(Debug, Clone)]
pub struct VerdictCache {
    cache_dir: PathBuf,
    ttl: Duration,
}

impl VerdictCache {
    pub fn new(cache_dir: PathBuf, ttl: Duration) -> Self {
        Self { cache_dir, ttl }
    }

    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Look up `key`. Returns:
    /// - `Some(entry)` on a fresh, well-formed hit.
    /// - `None` on cache miss, stale entry, or malformed entry (with a
    ///   one-line stderr warning so the user can see something was
    ///   skipped without poisoning the run).
    pub fn read(&self, key: &CacheKey, now: SystemTime) -> Option<CacheEntry> {
        let path = key.file_in(&self.cache_dir);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
            Err(err) => {
                eprintln!(
                    "[verdict-cache] could not read `{}`: {} (treating as miss)",
                    path.display(),
                    err
                );
                return None;
            }
        };
        let entry: CacheEntry = match serde_json::from_slice(&bytes) {
            Ok(e) => e,
            Err(err) => {
                eprintln!(
                    "[verdict-cache] malformed entry at `{}` ({err}); treating as miss",
                    path.display()
                );
                return None;
            }
        };
        if entry.schema_version != CACHE_SCHEMA_VERSION {
            return None;
        }
        if entry.cache_key != key.as_str() {
            eprintln!(
                "[verdict-cache] key mismatch at `{}` (entry: {}, expected: {}); treating as miss",
                path.display(),
                entry.cache_key,
                key.as_str()
            );
            return None;
        }
        if entry.is_stale(self.ttl, now) {
            return None;
        }
        Some(entry)
    }

    /// Persist `entry` atomically: write to `<key>.json.tmp` then
    /// rename onto `<key>.json`. On Windows the rename overwrites the
    /// destination if present.
    pub fn write(&self, key: &CacheKey, entry: &CacheEntry) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.cache_dir)?;
        let dest = key.file_in(&self.cache_dir);
        let tmp = dest.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(entry).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("serialize cache entry: {e}"),
            )
        })?;
        std::fs::write(&tmp, &bytes)?;
        // Windows rename overwrites; Unix rename is atomic. On Windows
        // if the destination exists fs::rename returns AlreadyExists on
        // some older toolchains — guard by removing first.
        if dest.exists() {
            let _ = std::fs::remove_file(&dest);
        }
        std::fs::rename(&tmp, &dest)?;
        Ok(())
    }
}

/// Lowercase hex encoder for SHA-256 digests. Avoids pulling in the
/// `hex` crate for a 30-line function.
fn hex_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(ALPHABET[(b >> 4) as usize] as char);
        out.push(ALPHABET[(b & 0x0f) as usize] as char);
    }
    out
}

/// SHA-256 fingerprint of the post-apply workspace state — manifest
/// and lockfile contents in the order they're provided. Files that
/// don't exist contribute an empty section, so a missing lockfile
/// produces a stable (different) fingerprint from a present-but-empty
/// one.
///
/// IMPORTANT: only the *basename* of each path is mixed into the hash,
/// not the full path. Sandbox locations (`.assay/runs/<id>/work/...`)
/// differ between runs by run-id; if the full path were hashed, the
/// fingerprint would change every invocation and the cache would never
/// hit. Ordering of the input slice is significant — callers must
/// supply files in a stable order across runs (the validator uses the
/// `WORKSPACE_FINGERPRINT_FILES` constant).
pub fn fingerprint_workspace_files(files: &[&Path]) -> String {
    let mut hasher = Sha256::new();
    for file in files {
        let basename = file
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        hasher.update(basename.as_bytes());
        hasher.update([0u8]);
        match std::fs::read(file) {
            Ok(bytes) => {
                hasher.update((bytes.len() as u64).to_le_bytes());
                hasher.update(&bytes);
            }
            Err(_) => {
                hasher.update(b"<missing>");
            }
        }
        hasher.update([0u8]);
    }
    hex_encode(&hasher.finalize())
}

/// SHA-256 fingerprint of a single file's contents. Returns the
/// literal string `"<missing>"`-prefixed digest when the file doesn't
/// exist so the key still derives, but is distinct from any real
/// content.
pub fn fingerprint_file(path: &Path) -> String {
    let mut hasher = Sha256::new();
    match std::fs::read(path) {
        Ok(bytes) => {
            hasher.update(b"file:");
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(&bytes);
        }
        Err(_) => {
            hasher.update(b"missing:");
            hasher.update(path.to_string_lossy().as_bytes());
        }
    }
    hex_encode(&hasher.finalize())
}

/// SHA-256 fingerprint of a canonicalized command list — used for
/// tree-mode backends (`BuildTest`, `Custom`) where the "workflow"
/// identity is the command sequence the backend runs, not a file on
/// disk.
pub fn fingerprint_commands(commands: &[Vec<String>]) -> String {
    let mut hasher = Sha256::new();
    hasher.update((commands.len() as u64).to_le_bytes());
    for cmd in commands {
        hasher.update((cmd.len() as u64).to_le_bytes());
        for arg in cmd {
            hasher.update((arg.len() as u64).to_le_bytes());
            hasher.update(arg.as_bytes());
        }
    }
    hex_encode(&hasher.finalize())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_inputs<'a>() -> CacheKeyInputs<'a> {
        CacheKeyInputs {
            workspace_fingerprint: "ws-fp-abc",
            workflow_fingerprint: "wf-fp-xyz",
            backend_name: "forge-run",
            event: "push",
            schema_version: CACHE_SCHEMA_VERSION,
        }
    }

    fn sample_entry(key: &CacheKey) -> CacheEntry {
        CacheEntry {
            schema_version: CACHE_SCHEMA_VERSION,
            cache_key: key.as_str().to_string(),
            verdict: CachedVerdict::Pass,
            forge_run_id: Some("forge-1".into()),
            log_path: Some(PathBuf::from(".assay/runs/r1/logs/x.log")),
            duration_ms: 42,
            stderr_tail: String::new(),
            backend: "forge-run".into(),
            cached_at_unix_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            inputs: CachedInputs {
                workspace_fingerprint: "ws-fp-abc".into(),
                workflow_fingerprint: "wf-fp-xyz".into(),
                backend_name: "forge-run".into(),
                event: "push".into(),
            },
        }
    }

    #[test]
    fn cache_key_is_pure_and_stable() {
        let inputs = sample_inputs();
        let k1 = CacheKey::compute(&inputs);
        let k2 = CacheKey::compute(&inputs);
        assert_eq!(k1, k2);
        assert_eq!(k1.as_str().len(), 64);
        assert!(k1.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn cache_key_changes_with_any_input() {
        let base = CacheKey::compute(&sample_inputs());

        let mut a = sample_inputs();
        a.workspace_fingerprint = "ws-fp-DIFFERENT";
        assert_ne!(base, CacheKey::compute(&a));

        let mut b = sample_inputs();
        b.workflow_fingerprint = "wf-fp-DIFFERENT";
        assert_ne!(base, CacheKey::compute(&b));

        let mut c = sample_inputs();
        c.backend_name = "build-test-cargo";
        assert_ne!(base, CacheKey::compute(&c));

        let mut d = sample_inputs();
        d.event = "pull_request";
        assert_ne!(base, CacheKey::compute(&d));

        let mut e = sample_inputs();
        e.schema_version = CACHE_SCHEMA_VERSION + 1;
        assert_ne!(base, CacheKey::compute(&e));
    }

    #[test]
    fn round_trip_write_then_read() {
        let dir = TempDir::new().unwrap();
        let cache = VerdictCache::new(dir.path().to_path_buf(), DEFAULT_CACHE_TTL);
        let key = CacheKey::compute(&sample_inputs());
        let entry = sample_entry(&key);
        cache.write(&key, &entry).unwrap();
        let read = cache.read(&key, SystemTime::now()).unwrap();
        assert_eq!(read, entry);
    }

    #[test]
    fn miss_when_file_absent() {
        let dir = TempDir::new().unwrap();
        let cache = VerdictCache::new(dir.path().to_path_buf(), DEFAULT_CACHE_TTL);
        let key = CacheKey::compute(&sample_inputs());
        assert!(cache.read(&key, SystemTime::now()).is_none());
    }

    #[test]
    fn miss_when_entry_is_stale() {
        let dir = TempDir::new().unwrap();
        let cache = VerdictCache::new(dir.path().to_path_buf(), Duration::from_secs(60));
        let key = CacheKey::compute(&sample_inputs());
        let mut entry = sample_entry(&key);
        // 1 hour in the past — past a 60-second TTL.
        entry.cached_at_unix_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3600;
        cache.write(&key, &entry).unwrap();
        assert!(cache.read(&key, SystemTime::now()).is_none());
    }

    #[test]
    fn miss_when_entry_is_malformed_json() {
        let dir = TempDir::new().unwrap();
        let cache = VerdictCache::new(dir.path().to_path_buf(), DEFAULT_CACHE_TTL);
        let key = CacheKey::compute(&sample_inputs());
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(key.file_in(dir.path()), b"not valid json").unwrap();
        assert!(cache.read(&key, SystemTime::now()).is_none());
    }

    #[test]
    fn miss_when_entry_has_wrong_schema_version() {
        let dir = TempDir::new().unwrap();
        let cache = VerdictCache::new(dir.path().to_path_buf(), DEFAULT_CACHE_TTL);
        let key = CacheKey::compute(&sample_inputs());
        let mut entry = sample_entry(&key);
        entry.schema_version = CACHE_SCHEMA_VERSION + 99;
        cache.write(&key, &entry).unwrap();
        assert!(cache.read(&key, SystemTime::now()).is_none());
    }

    #[test]
    fn miss_when_key_mismatches() {
        let dir = TempDir::new().unwrap();
        let cache = VerdictCache::new(dir.path().to_path_buf(), DEFAULT_CACHE_TTL);
        let key = CacheKey::compute(&sample_inputs());
        let mut entry = sample_entry(&key);
        entry.cache_key = "deadbeef".into();
        cache.write(&key, &entry).unwrap();
        assert!(cache.read(&key, SystemTime::now()).is_none());
    }

    #[test]
    fn round_trip_regression_verdict() {
        let dir = TempDir::new().unwrap();
        let cache = VerdictCache::new(dir.path().to_path_buf(), DEFAULT_CACHE_TTL);
        let key = CacheKey::compute(&sample_inputs());
        let mut entry = sample_entry(&key);
        entry.verdict = CachedVerdict::Regression {
            details: "conclusion: failure".into(),
        };
        cache.write(&key, &entry).unwrap();
        let read = cache.read(&key, SystemTime::now()).unwrap();
        assert_eq!(read.verdict, entry.verdict);
    }

    #[test]
    fn write_then_overwrite_does_not_corrupt() {
        let dir = TempDir::new().unwrap();
        let cache = VerdictCache::new(dir.path().to_path_buf(), DEFAULT_CACHE_TTL);
        let key = CacheKey::compute(&sample_inputs());
        let mut entry = sample_entry(&key);
        cache.write(&key, &entry).unwrap();
        entry.duration_ms = 999;
        cache.write(&key, &entry).unwrap();
        let read = cache.read(&key, SystemTime::now()).unwrap();
        assert_eq!(read.duration_ms, 999);
    }

    #[test]
    fn fingerprint_workspace_files_changes_with_content() {
        let dir = TempDir::new().unwrap();
        let manifest = dir.path().join("Cargo.toml");
        let lockfile = dir.path().join("Cargo.lock");
        std::fs::write(&manifest, b"[package]\nname = \"a\"\n").unwrap();
        std::fs::write(&lockfile, b"# initial\n").unwrap();
        let fp1 = fingerprint_workspace_files(&[&manifest, &lockfile]);

        std::fs::write(&lockfile, b"# bumped\n").unwrap();
        let fp2 = fingerprint_workspace_files(&[&manifest, &lockfile]);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn fingerprint_workspace_files_stable_across_calls() {
        let dir = TempDir::new().unwrap();
        let manifest = dir.path().join("Cargo.toml");
        std::fs::write(&manifest, b"contents").unwrap();
        let fp1 = fingerprint_workspace_files(&[&manifest]);
        let fp2 = fingerprint_workspace_files(&[&manifest]);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint_workspace_files_handles_missing() {
        let dir = TempDir::new().unwrap();
        let present = dir.path().join("present");
        let missing = dir.path().join("missing");
        std::fs::write(&present, b"x").unwrap();
        let fp_both = fingerprint_workspace_files(&[&present, &missing]);
        let fp_present_only = fingerprint_workspace_files(&[&present]);
        assert_ne!(fp_both, fp_present_only);
    }

    #[test]
    fn fingerprint_file_distinguishes_missing_from_empty() {
        let dir = TempDir::new().unwrap();
        let empty = dir.path().join("empty");
        let missing = dir.path().join("missing");
        std::fs::write(&empty, b"").unwrap();
        assert_ne!(fingerprint_file(&empty), fingerprint_file(&missing));
    }

    #[test]
    fn fingerprint_commands_changes_with_args() {
        let a = fingerprint_commands(&[vec!["cargo".into(), "test".into()]]);
        let b = fingerprint_commands(&[vec!["cargo".into(), "build".into()]]);
        assert_ne!(a, b);
    }

    #[test]
    fn fingerprint_commands_is_order_sensitive() {
        let a = fingerprint_commands(&[
            vec!["cargo".into(), "build".into()],
            vec!["cargo".into(), "test".into()],
        ]);
        let b = fingerprint_commands(&[
            vec!["cargo".into(), "test".into()],
            vec!["cargo".into(), "build".into()],
        ]);
        assert_ne!(a, b);
    }

    #[test]
    fn hex_encode_lowercase_pads() {
        assert_eq!(hex_encode(&[0x00, 0x01, 0xab, 0xff]), "0001abff");
    }

    #[test]
    fn is_stale_at_exactly_ttl_is_fresh() {
        let key = CacheKey::compute(&sample_inputs());
        let mut entry = sample_entry(&key);
        let now = SystemTime::now();
        let now_unix = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
        let ttl = Duration::from_secs(100);
        entry.cached_at_unix_secs = now_unix - 100;
        // age == ttl ⇒ not stale (strict > comparison)
        assert!(!entry.is_stale(ttl, now));
        entry.cached_at_unix_secs = now_unix - 101;
        assert!(entry.is_stale(ttl, now));
    }

    #[test]
    fn future_cached_at_is_not_stale() {
        let key = CacheKey::compute(&sample_inputs());
        let mut entry = sample_entry(&key);
        let now = SystemTime::now();
        let now_unix = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
        entry.cached_at_unix_secs = now_unix + 3600;
        assert!(!entry.is_stale(Duration::from_secs(60), now));
    }
}
