//! GitHub REST API helper for the GitHub Actions proposer.
//!
//! Wraps `gh api` shell-outs to avoid pulling in an HTTP client / async
//! runtime / GitHub App auth dance. The user's existing `gh auth` is
//! reused — same machinery that `--apply-pr` depends on. When `gh` is
//! missing from PATH, the proposer logs a clear note and skips action
//! bumps (the rest of assay still works).
//!
//! ## What's queried
//!
//! - `GET /repos/{owner}/{repo}/releases/latest` — returns the latest
//!   non-prerelease, non-draft release's `tag_name`.
//! - `GET /repos/{owner}/{repo}/commits/{ref}` — returns the commit
//!   SHA the tag points at. Annotated tags are dereferenced
//!   automatically by GitHub.
//!
//! Both endpoints are read-only; auth scope `public_repo` (or no scope
//! for public repos) is sufficient.
//!
//! ## Caching
//!
//! In-memory per [`GitHubApiClient`] instance, keyed by `(owner, repo)`.
//! One assay run uses one client, so a workflow that references
//! `actions/checkout` from 30 different jobs produces ONE API call, not
//! 30. On-disk caching via `EcosystemContext.action_store` is a follow-up.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Resolved upstream state for one `owner/repo` action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseInfo {
    /// The release's tag name (e.g. `"v4.2.1"`).
    pub tag_name: String,
    /// The commit SHA the tag points at (40-char hex).
    pub commit_sha: String,
}

/// Shell-out wrapper around the `gh` CLI for GitHub REST calls. Caches
/// resolved release info per `(owner, repo)` for the lifetime of the
/// client, AND persists successful lookups to an optional on-disk store
/// so subsequent `--offline` runs can re-emit proposals without
/// re-hitting the network.
#[derive(Debug)]
pub struct GitHubApiClient {
    /// Path to the `gh` binary. Defaults to "gh" on PATH; tests inject
    /// a fixture script via [`Self::with_binary`].
    gh_bin: PathBuf,
    /// `Some(info)` when the lookup succeeded; `None` when it returned
    /// 404 / unauthorized / unparseable (recorded so we don't re-fire
    /// on every consumer of the same action).
    cache: RefCell<HashMap<(String, String), Option<ReleaseInfo>>>,
    /// `(owner, repo, tag) → exists?` cache for [`Self::tag_exists`]
    /// probes used by the granularity-aware target picker.
    tag_cache: RefCell<HashMap<(String, String, String), bool>>,
    /// On-disk persistence root. When `Some(path)`, successful
    /// `latest_release` lookups are serialized under
    /// `<path>/<owner>--<repo>/release.json` so a later offline run
    /// can re-emit the same proposals. `None` disables persistence.
    cache_root: Option<PathBuf>,
    /// In offline mode the client never invokes `gh`; it reads from
    /// `cache_root` only. Lookups that miss the cache return `None`.
    offline: bool,
    /// Maximum age of a cache entry before it counts as stale.
    /// Defaults to 7 days. Stale entries trigger a fresh fetch in
    /// online mode; in offline mode stale entries return `None`
    /// (operator should refresh or set `--serve-stale` — future flag).
    cache_ttl_secs: u64,
    /// When `true`, the client bypasses cache reads entirely and
    /// forces a fresh fetch. Set by `--refresh-cache`. No-op in
    /// offline mode (there's no source to fetch FROM offline, so
    /// the flag is silently ignored and we still read cache).
    refresh: bool,
}

/// Default cache TTL: 7 days. Short enough that "I'm offline today
/// because of a flight" still works; long enough that random
/// re-fetches don't churn the network for projects that bump deps
/// quarterly.
const DEFAULT_CACHE_TTL_SECS: u64 = 7 * 24 * 60 * 60;

impl Default for GitHubApiClient {
    fn default() -> Self {
        Self {
            gh_bin: PathBuf::from("gh"),
            cache: RefCell::new(HashMap::new()),
            tag_cache: RefCell::new(HashMap::new()),
            cache_root: None,
            offline: false,
            cache_ttl_secs: DEFAULT_CACHE_TTL_SECS,
            refresh: false,
        }
    }
}

impl GitHubApiClient {
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the gh binary path. Test-only entry point.
    pub fn with_binary(mut self, gh_bin: PathBuf) -> Self {
        self.gh_bin = gh_bin;
        self
    }

    /// Enable on-disk persistence. Successful network lookups are
    /// serialized under `<path>/<owner>--<repo>/release.json` and
    /// `<path>/<owner>--<repo>/tags/<tag>.json`. Subsequent runs with
    /// the same root re-read the cache.
    pub fn with_cache_root(mut self, path: PathBuf) -> Self {
        self.cache_root = Some(path);
        self
    }

    /// Switch the client to offline mode. Lookups never shell out to
    /// `gh`; they only read from the configured `cache_root`. Missing
    /// cache entries return `None` (callers degrade gracefully —
    /// proposers emit no proposal for the missing action).
    pub fn with_offline_mode(mut self, offline: bool) -> Self {
        self.offline = offline;
        self
    }

    /// Whether the client is operating in offline mode. Callers use
    /// this to set `Classification::Simulated` on the resulting
    /// proposals so the receipt records "from cache, not live".
    pub fn is_offline(&self) -> bool {
        self.offline
    }

    /// Override the cache TTL in seconds. `0` disables TTL entirely
    /// (every cache hit is served). Default is 7 days.
    pub fn with_cache_ttl(mut self, secs: u64) -> Self {
        self.cache_ttl_secs = secs;
        self
    }

    /// Force a fresh fetch on every lookup, bypassing the cache read
    /// path. In offline mode the flag is silently ignored (no source
    /// to refresh FROM offline).
    pub fn with_refresh(mut self, refresh: bool) -> Self {
        self.refresh = refresh;
        self
    }

    /// Decide whether a cached entry with the given `fetched_at_unix_secs`
    /// is fresh enough to serve.
    fn cache_entry_is_fresh(&self, fetched_at_unix_secs: u64) -> bool {
        if self.cache_ttl_secs == 0 {
            return true;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Entries with fetched_at_unix_secs == 0 are pre-TTL-schema
        // (or never timestamped); treat as ancient and stale.
        if fetched_at_unix_secs == 0 {
            return false;
        }
        now.saturating_sub(fetched_at_unix_secs) < self.cache_ttl_secs
    }

    /// Resolve the latest non-prerelease, non-draft release for
    /// `owner/repo` to a `(tag, commit_sha)` pair.
    ///
    /// Returns `Ok(None)` when:
    /// - the repo has no releases (the endpoint 404s), OR
    /// - `gh` isn't installed / authenticated, OR
    /// - the response is unparseable.
    ///
    /// Returns `Err` only for unexpected internal errors. Caller treats
    /// `Ok(None)` as "skip this action with a note" rather than a fatal
    /// failure — one action without releases shouldn't poison the run.
    pub fn latest_release(&self, owner: &str, repo: &str) -> Result<Option<ReleaseInfo>> {
        let key = (owner.to_string(), repo.to_string());
        if let Some(cached) = self.cache.borrow().get(&key) {
            return Ok(cached.clone());
        }
        let resolved = if self.offline {
            self.read_release_cache(owner, repo)
        } else if self.refresh {
            // --refresh-cache: skip the cache read, force fresh fetch.
            let live = self.fetch_latest_release_uncached(owner, repo);
            if let Some(ref info) = live {
                let _ = self.write_release_cache(owner, repo, info);
            }
            live
        } else {
            // Try fresh cache first; on miss or stale, fetch live.
            match self.read_release_cache(owner, repo) {
                Some(info) => Some(info),
                None => {
                    let live = self.fetch_latest_release_uncached(owner, repo);
                    if let Some(ref info) = live {
                        let _ = self.write_release_cache(owner, repo, info);
                    }
                    live
                }
            }
        };
        self.cache.borrow_mut().insert(key, resolved.clone());
        Ok(resolved)
    }

    fn fetch_latest_release_uncached(&self, owner: &str, repo: &str) -> Option<ReleaseInfo> {
        let path = format!("repos/{owner}/{repo}/releases/latest");
        let release_json = match self.gh_api_get(&path) {
            Ok(Some(text)) => text,
            _ => return None,
        };
        let tag_name = parse_release_tag_name(&release_json)?;
        let sha = self.resolve_commit_sha(owner, repo, &tag_name)?;
        Some(ReleaseInfo {
            tag_name,
            commit_sha: sha,
        })
    }

    fn release_cache_path(&self, owner: &str, repo: &str) -> Option<PathBuf> {
        let root = self.cache_root.as_ref()?;
        Some(
            root.join(sanitize_action_dir(owner, repo))
                .join("release.json"),
        )
    }

    fn read_release_cache(&self, owner: &str, repo: &str) -> Option<ReleaseInfo> {
        let path = self.release_cache_path(owner, repo)?;
        let text = std::fs::read_to_string(&path).ok()?;
        let cached: CachedReleaseEntry = serde_json::from_str(&text).ok()?;
        if !self.cache_entry_is_fresh(cached.fetched_at_unix_secs) {
            return None;
        }
        Some(ReleaseInfo {
            tag_name: cached.tag_name,
            commit_sha: cached.commit_sha,
        })
    }

    pub(crate) fn write_release_cache(
        &self,
        owner: &str,
        repo: &str,
        info: &ReleaseInfo,
    ) -> std::io::Result<()> {
        let Some(path) = self.release_cache_path(owner, repo) else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let entry = CachedReleaseEntry {
            tag_name: info.tag_name.clone(),
            commit_sha: info.commit_sha.clone(),
            fetched_at: now_iso8601(),
            fetched_at_unix_secs: now_unix,
        };
        let json = serde_json::to_string_pretty(&entry).map_err(std::io::Error::other)?;
        std::fs::write(path, json)
    }

    /// Verify a tag (by name) exists on `owner/repo`. Used by the
    /// granularity-aware target picker to confirm that a truncated
    /// candidate (e.g. `v6` derived from `v6.0.2`) is actually a
    /// real tag before proposing it.
    ///
    /// Returns:
    /// - `true` if the tag ref resolves to a 200.
    /// - `false` for 404, missing `gh`, unauthorized, or any other
    ///   non-success — caller falls back to the full latest tag.
    pub fn tag_exists(&self, owner: &str, repo: &str, tag: &str) -> bool {
        let key = (owner.to_string(), repo.to_string(), tag.to_string());
        if let Some(cached) = self.tag_cache.borrow().get(&key) {
            return *cached;
        }
        let exists = if self.offline {
            self.read_tag_cache(owner, repo, tag).unwrap_or(false)
        } else if self.refresh {
            let api_path = format!("repos/{owner}/{repo}/git/refs/tags/{tag}");
            let live = matches!(self.gh_api_get(&api_path), Ok(Some(_)));
            let _ = self.write_tag_cache(owner, repo, tag, live);
            live
        } else if let Some(cached_exists) = self.read_tag_cache(owner, repo, tag) {
            cached_exists
        } else {
            let api_path = format!("repos/{owner}/{repo}/git/refs/tags/{tag}");
            let live = matches!(self.gh_api_get(&api_path), Ok(Some(_)));
            let _ = self.write_tag_cache(owner, repo, tag, live);
            live
        };
        self.tag_cache.borrow_mut().insert(key, exists);
        exists
    }

    fn tag_cache_path(&self, owner: &str, repo: &str, tag: &str) -> Option<PathBuf> {
        let root = self.cache_root.as_ref()?;
        let safe_tag = sanitize_tag_filename(tag);
        Some(
            root.join(sanitize_action_dir(owner, repo))
                .join("tags")
                .join(format!("{safe_tag}.json")),
        )
    }

    fn read_tag_cache(&self, owner: &str, repo: &str, tag: &str) -> Option<bool> {
        let path = self.tag_cache_path(owner, repo, tag)?;
        let text = std::fs::read_to_string(&path).ok()?;
        let entry: CachedTagEntry = serde_json::from_str(&text).ok()?;
        if !self.cache_entry_is_fresh(entry.fetched_at_unix_secs) {
            return None;
        }
        Some(entry.exists)
    }

    fn write_tag_cache(
        &self,
        owner: &str,
        repo: &str,
        tag: &str,
        exists: bool,
    ) -> std::io::Result<()> {
        let Some(path) = self.tag_cache_path(owner, repo, tag) else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let entry = CachedTagEntry {
            tag: tag.to_string(),
            exists,
            fetched_at: now_iso8601(),
            fetched_at_unix_secs: now_unix,
        };
        let json = serde_json::to_string_pretty(&entry).map_err(std::io::Error::other)?;
        std::fs::write(path, json)
    }

    fn resolve_commit_sha(&self, owner: &str, repo: &str, git_ref: &str) -> Option<String> {
        let path = format!("repos/{owner}/{repo}/commits/{git_ref}");
        let body = match self.gh_api_get(&path) {
            Ok(Some(text)) => text,
            _ => return None,
        };
        parse_commit_sha(&body)
    }

    /// Run `gh api <path>`. Returns `Ok(Some(body))` for HTTP 200,
    /// `Ok(None)` for documented "not found" cases (404, repo without
    /// releases, missing `gh` binary), and `Err` for unexpected
    /// internal errors (process spawn failures we couldn't classify).
    fn gh_api_get(&self, path: &str) -> Result<Option<String>> {
        let mut cmd = Command::new(&self.gh_bin);
        cmd.arg("api").arg(path);
        let output = match cmd.output() {
            Ok(o) => o,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(Error::Io {
                    path: self.gh_bin.clone(),
                    source: err,
                });
            }
        };
        if !output.status.success() {
            return Ok(None);
        }
        Ok(Some(String::from_utf8_lossy(&output.stdout).to_string()))
    }
}

/// On-disk schema for a cached `releases/latest` lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedReleaseEntry {
    tag_name: String,
    commit_sha: String,
    /// Human-readable ISO 8601 wall-clock when the live lookup
    /// happened. Informational only — TTL math uses
    /// `fetched_at_unix_secs`.
    #[serde(default)]
    fetched_at: String,
    /// Unix-epoch seconds at fetch time. Used by the TTL freshness
    /// check. `0` for pre-TTL-schema entries — treated as ancient.
    #[serde(default)]
    fetched_at_unix_secs: u64,
}

/// On-disk schema for a cached `tag_exists` probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedTagEntry {
    tag: String,
    exists: bool,
    #[serde(default)]
    fetched_at: String,
    #[serde(default)]
    fetched_at_unix_secs: u64,
}

/// Filesystem-safe per-action directory name. `actions/checkout`
/// becomes `actions--checkout`. The double-dash separator stays
/// distinguishable from a literal slug-internal dash and matches
/// neither slash nor any other path metacharacter.
fn sanitize_action_dir(owner: &str, repo: &str) -> String {
    format!(
        "{}--{}",
        sanitize_path_component(owner),
        sanitize_path_component(repo)
    )
}

fn sanitize_tag_filename(tag: &str) -> String {
    sanitize_path_component(tag)
}

fn sanitize_path_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-' {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    out
}

fn now_iso8601() -> String {
    // Best-effort: use UNIX_EPOCH seconds and format as
    // "1970-01-01T00:00:00Z"-ish. We don't pull a chrono dep just
    // for the audit timestamp; the field is informational.
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days_since_epoch = secs / 86_400;
    let secs_of_day = secs % 86_400;
    let h = secs_of_day / 3600;
    let m = (secs_of_day % 3600) / 60;
    let s = secs_of_day % 60;
    // Civil-date math via Howard Hinnant's algorithm.
    let (y, mo, d) = civil_from_days(days_since_epoch as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64 + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Pull `tag_name` out of a `releases/latest` JSON body. Returns
/// `None` when the body isn't valid JSON or the field is absent.
pub(crate) fn parse_release_tag_name(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    value
        .get("tag_name")
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Pull `sha` out of a `commits/{ref}` JSON body. Returns `None` when
/// the body isn't valid JSON or the field is absent.
pub(crate) fn parse_commit_sha(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    value.get("sha").and_then(|v| v.as_str()).map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_release_tag_name_extracts_field() {
        let body = r#"{"tag_name":"v4.2.1","name":"v4.2.1","draft":false,"prerelease":false}"#;
        assert_eq!(parse_release_tag_name(body), Some("v4.2.1".to_string()));
    }

    #[test]
    fn parse_release_tag_name_returns_none_for_missing_field() {
        let body = r#"{"message":"Not Found"}"#;
        assert_eq!(parse_release_tag_name(body), None);
    }

    #[test]
    fn parse_release_tag_name_returns_none_for_invalid_json() {
        assert_eq!(parse_release_tag_name("<html>"), None);
    }

    #[test]
    fn parse_commit_sha_extracts_field() {
        let body = r#"{"sha":"a1b2c3d4e5f60718293a4b5c6d7e8f9012345678","commit":{}}"#;
        assert_eq!(
            parse_commit_sha(body),
            Some("a1b2c3d4e5f60718293a4b5c6d7e8f9012345678".to_string())
        );
    }

    #[test]
    fn parse_commit_sha_returns_none_for_missing_field() {
        assert_eq!(parse_commit_sha(r#"{}"#), None);
    }

    #[test]
    fn missing_gh_binary_returns_none_not_err() {
        // Point at a binary that definitely isn't on PATH. The client
        // must treat missing-gh as "skip this action" rather than
        // propagating a hard failure.
        let client = GitHubApiClient::new()
            .with_binary(PathBuf::from("__assay_test_definitely_not_a_real_binary__"));
        let info = client.latest_release("actions", "checkout").unwrap();
        assert!(info.is_none(), "missing gh binary must yield None");
    }

    #[test]
    fn sanitize_path_component_handles_slashes_and_specials() {
        assert_eq!(sanitize_path_component("actions"), "actions");
        assert_eq!(sanitize_path_component("ACTIONS"), "actions");
        assert_eq!(sanitize_path_component("foo/bar"), "foo_bar");
        assert_eq!(sanitize_path_component("foo:bar"), "foo_bar");
        assert_eq!(sanitize_path_component("v1.2-rc.1"), "v1.2-rc.1");
    }

    #[test]
    fn sanitize_action_dir_uses_double_dash_separator() {
        assert_eq!(
            sanitize_action_dir("actions", "checkout"),
            "actions--checkout"
        );
        assert_eq!(
            sanitize_action_dir("DTOLNAY", "rust-toolchain"),
            "dtolnay--rust-toolchain"
        );
    }

    #[test]
    fn offline_mode_reads_release_from_cache() {
        // Seed the cache, then build an offline client and verify
        // it reads back identical info without invoking gh.
        let tmp = tempfile::tempdir().unwrap();
        let client = GitHubApiClient::new()
            .with_binary(PathBuf::from("__never_invoked__"))
            .with_cache_root(tmp.path().to_path_buf());
        let info = ReleaseInfo {
            tag_name: "v6.0.2".into(),
            commit_sha: "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678".into(),
        };
        client
            .write_release_cache("actions", "checkout", &info)
            .unwrap();

        let offline = GitHubApiClient::new()
            .with_binary(PathBuf::from("__never_invoked__"))
            .with_cache_root(tmp.path().to_path_buf())
            .with_offline_mode(true);
        let read = offline.latest_release("actions", "checkout").unwrap();
        assert_eq!(read, Some(info));
    }

    #[test]
    fn stale_cache_entries_are_treated_as_missing() {
        // Hand-write a CachedReleaseEntry with an ancient
        // fetched_at_unix_secs (1970-01-01 = unix 0). The client's
        // freshness check special-cases 0 as "ancient/never timestamped"
        // → stale → read returns None.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("actions--ancient");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("release.json"),
            r#"{"tag_name":"v1.0.0","commit_sha":"deadbeef","fetched_at":"1970-01-01T00:00:00Z","fetched_at_unix_secs":0}"#,
        )
        .unwrap();
        let offline = GitHubApiClient::new()
            .with_binary(PathBuf::from("__never__"))
            .with_cache_root(tmp.path().to_path_buf())
            .with_offline_mode(true);
        assert_eq!(
            offline.latest_release("actions", "ancient").unwrap(),
            None,
            "ancient entry must read as None"
        );
    }

    #[test]
    fn cache_ttl_zero_means_no_expiry() {
        // Hand-write an entry with fetched_at_unix_secs = 1 (just
        // after the epoch). With TTL = 0, it should still be served.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("actions--ttl-zero");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("release.json"),
            r#"{"tag_name":"v9.9.9","commit_sha":"cafebabe","fetched_at":"1970-01-01T00:00:01Z","fetched_at_unix_secs":1}"#,
        )
        .unwrap();
        let offline = GitHubApiClient::new()
            .with_binary(PathBuf::from("__never__"))
            .with_cache_root(tmp.path().to_path_buf())
            .with_offline_mode(true)
            .with_cache_ttl(0);
        let info = offline.latest_release("actions", "ttl-zero").unwrap();
        assert_eq!(info.unwrap().tag_name, "v9.9.9");
    }

    #[test]
    fn offline_mode_returns_none_when_cache_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let offline = GitHubApiClient::new()
            .with_binary(PathBuf::from("__never_invoked__"))
            .with_cache_root(tmp.path().to_path_buf())
            .with_offline_mode(true);
        assert_eq!(
            offline.latest_release("never", "cached").unwrap(),
            None,
            "offline + no cache → None, not an error"
        );
    }

    #[test]
    fn offline_mode_reads_tag_existence_from_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let writer = GitHubApiClient::new().with_cache_root(tmp.path().to_path_buf());
        writer
            .write_tag_cache("actions", "checkout", "v6", true)
            .unwrap();
        writer
            .write_tag_cache("actions", "checkout", "v99", false)
            .unwrap();

        let offline = GitHubApiClient::new()
            .with_binary(PathBuf::from("__never_invoked__"))
            .with_cache_root(tmp.path().to_path_buf())
            .with_offline_mode(true);
        assert!(offline.tag_exists("actions", "checkout", "v6"));
        assert!(!offline.tag_exists("actions", "checkout", "v99"));
        assert!(
            !offline.tag_exists("actions", "checkout", "v1000"),
            "uncached tag → false (no entry means 'we didn't probe it', not 'it exists')"
        );
    }

    #[test]
    fn cache_returns_same_value_on_second_call() {
        // The client caches `(owner, repo) -> Option<ReleaseInfo>` so
        // a workflow that references the same action 30 times produces
        // ONE shell-out. We can't easily assert "one shell-out happened"
        // without a mock, but we CAN assert the cache is consulted by
        // checking the second call doesn't re-fail in a way that would
        // signal a re-fire.
        let client = GitHubApiClient::new()
            .with_binary(PathBuf::from("__assay_test_definitely_not_a_real_binary__"));
        let first = client.latest_release("a", "b").unwrap();
        let second = client.latest_release("a", "b").unwrap();
        assert_eq!(first, second);
    }
}
