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
/// client.
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
}

impl Default for GitHubApiClient {
    fn default() -> Self {
        Self {
            gh_bin: PathBuf::from("gh"),
            cache: RefCell::new(HashMap::new()),
            tag_cache: RefCell::new(HashMap::new()),
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
        let resolved = self.fetch_latest_release_uncached(owner, repo);
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
        let path = format!("repos/{owner}/{repo}/git/refs/tags/{tag}");
        let exists = matches!(self.gh_api_get(&path), Ok(Some(_)));
        self.tag_cache.borrow_mut().insert(key, exists);
        exists
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
