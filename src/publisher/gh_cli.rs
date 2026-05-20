//! `gh` CLI-backed [`PullRequestBackend`].
//!
//! Implements PR opening + branch metadata lookup by shelling out to the
//! operator's own `gh` binary. Auth is whatever `gh auth status` is
//! currently set to — assay does not handle tokens directly. The
//! `$GH_TOKEN` environment variable is honored automatically by `gh`.
//!
//! ## Design
//!
//! - `gh_bin: PathBuf` — defaults to "gh" on PATH; tests inject a
//!   fixture script that records its argv.
//! - All argv goes through `Command::new(&gh_bin).arg(...)` — no shell
//!   interpolation; branch/repo names are validated upstream.
//! - Output parsing: `gh api` returns JSON; `gh pr create` writes the
//!   PR URL to stdout.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::{
    BackendError, BranchMetadata, PullRequestBackend, PullRequestRequest, PullRequestResponse,
};

/// `gh`-backed PullRequestBackend.
#[derive(Debug, Clone)]
pub struct GhCliBackend {
    /// Path to the `gh` binary. Defaults to `PathBuf::from("gh")`,
    /// resolved through `PATH`. Tests override to point at a fixture
    /// script.
    pub gh_bin: PathBuf,
}

impl Default for GhCliBackend {
    fn default() -> Self {
        Self {
            gh_bin: PathBuf::from("gh"),
        }
    }
}

impl GhCliBackend {
    pub fn new(gh_bin: PathBuf) -> Self {
        Self { gh_bin }
    }

    /// Best-effort auth check. Runs `gh auth status` and considers the
    /// operator authenticated when the call succeeds AND the `repo`
    /// scope appears in the output.
    ///
    /// Imperfect — `gh auth status`'s output format isn't a stable
    /// contract — but good enough as a pre-push guard; the real
    /// authoritative check is the `gh pr create` call itself, which
    /// surfaces server-side errors verbatim.
    pub fn check_auth(&self) -> Result<(), BackendError> {
        let output = Command::new(&self.gh_bin)
            .arg("auth")
            .arg("status")
            .output()
            .map_err(|err| {
                BackendError::Auth(format!(
                    "couldn't execute `{} auth status`: {err}. \
                     Install gh (https://cli.github.com/) or pass --no-pr.",
                    self.gh_bin.display()
                ))
            })?;
        if !output.status.success() {
            return Err(BackendError::Auth(format!(
                "`gh auth status` exited non-zero — run `gh auth login` then retry. \
                 stderr: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if !combined.contains("repo") {
            return Err(BackendError::Auth(
                "gh CLI is authenticated but the token lacks `repo` scope. \
                 Run `gh auth refresh -s repo` and retry."
                    .into(),
            ));
        }
        Ok(())
    }
}

impl PullRequestBackend for GhCliBackend {
    fn fetch_branch_metadata(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
    ) -> Result<BranchMetadata, BackendError> {
        // Resolve the repo's default branch first — we need this so the
        // protected-branch check can also catch "branch == default".
        let default_branch = fetch_default_branch(&self.gh_bin, owner, repo)?;

        // Try to fetch the named branch. If it returns 404 the branch
        // doesn't exist yet (which is the common case — we're about to
        // push a fresh branch), so synthesize a clean BranchMetadata.
        let output = Command::new(&self.gh_bin)
            .arg("api")
            .arg(format!("repos/{owner}/{repo}/branches/{branch}"))
            .output()
            .map_err(|err| {
                BackendError::Network(format!(
                    "couldn't execute `gh api`: {err}; gh CLI must be installed and on PATH"
                ))
            })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // 404 → branch doesn't exist yet. Treat as a fresh branch
            // that's never been pushed. We still need to make sure the
            // *name* doesn't collide with the default branch.
            if stderr.contains("Not Found") || stderr.contains("HTTP 404") {
                return Ok(BranchMetadata {
                    name: branch.to_string(),
                    is_default: branch == default_branch,
                    is_protected: false,
                });
            }
            return Err(BackendError::Network(format!(
                "`gh api` failed for branch lookup: {}",
                stderr.trim()
            )));
        }
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|err| {
            BackendError::Network(format!(
                "couldn't parse `gh api` JSON for branch metadata: {err}"
            ))
        })?;
        let is_protected = json
            .get("protected")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        Ok(BranchMetadata {
            name: branch.to_string(),
            is_default: branch == default_branch,
            is_protected,
        })
    }

    fn list_collaborators(&self, owner: &str, repo: &str) -> Result<Vec<String>, BackendError> {
        // `gh api repos/<owner>/<repo>/collaborators --paginate --jq '.[].login'`
        // returns one login per line. `--paginate` because GitHub caps
        // the per-page response at 30.
        let output = Command::new(&self.gh_bin)
            .arg("api")
            .arg(format!("repos/{owner}/{repo}/collaborators"))
            .arg("--paginate")
            .arg("--jq")
            .arg(".[].login")
            .output()
            .map_err(|err| {
                BackendError::Network(format!(
                    "couldn't execute `gh api` for collaborator list: {err}; gh CLI must be installed"
                ))
            })?;
        if !output.status.success() {
            return Err(BackendError::Network(format!(
                "`gh api` for collaborator list failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect())
    }

    fn list_labels(&self, owner: &str, repo: &str) -> Result<Vec<String>, BackendError> {
        // `gh api repos/<owner>/<repo>/labels --paginate --jq '.[].name'`
        // returns one label name per line. `--paginate` is important
        // because GitHub caps the response at 30 labels by default.
        let output = Command::new(&self.gh_bin)
            .arg("api")
            .arg(format!("repos/{owner}/{repo}/labels"))
            .arg("--paginate")
            .arg("--jq")
            .arg(".[].name")
            .output()
            .map_err(|err| {
                BackendError::Network(format!(
                    "couldn't execute `gh api` for label list: {err}; gh CLI must be installed"
                ))
            })?;
        if !output.status.success() {
            return Err(BackendError::Network(format!(
                "`gh api` for label list failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect())
    }

    fn create_label(&self, owner: &str, repo: &str, name: &str) -> Result<(), BackendError> {
        // `--force` makes the call idempotent: existing labels with the
        // same name are updated (color/description refreshed) rather
        // than erroring. The publisher always filters by `list_labels`
        // first so this is only invoked for missing labels, but `--force`
        // also covers the small race window where a label was created
        // between the list and the create.
        let output = Command::new(&self.gh_bin)
            .arg("label")
            .arg("create")
            .arg(name)
            .arg("--repo")
            .arg(format!("{owner}/{repo}"))
            .arg("--color")
            .arg("ededed")
            .arg("--description")
            .arg("Bumped via assay")
            .arg("--force")
            .output()
            .map_err(|err| {
                BackendError::Network(format!(
                    "couldn't execute `gh label create`: {err}; gh CLI must be installed"
                ))
            })?;
        if !output.status.success() {
            return Err(BackendError::Rejected(format!(
                "`gh label create {name}` exited non-zero: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }

    fn open_pull_request(
        &self,
        request: &PullRequestRequest,
    ) -> Result<PullRequestResponse, BackendError> {
        let mut cmd = Command::new(&self.gh_bin);
        cmd.arg("pr").arg("create");
        cmd.arg("--repo")
            .arg(format!("{}/{}", request.owner, request.repo));
        cmd.arg("--base").arg(&request.base);
        cmd.arg("--head").arg(&request.branch);
        cmd.arg("--title").arg(&request.title);
        cmd.arg("--body").arg(&request.body);
        if request.draft {
            cmd.arg("--draft");
        }
        for label in &request.labels {
            cmd.arg("--label").arg(label);
        }
        for reviewer in &request.reviewers {
            cmd.arg("--reviewer").arg(reviewer);
        }
        let output = cmd.output().map_err(|err| {
            BackendError::Network(format!(
                "couldn't execute `gh pr create`: {err}; gh CLI must be installed"
            ))
        })?;
        if !output.status.success() {
            return Err(BackendError::Rejected(format!(
                "`gh pr create` exited non-zero: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let url = stdout
            .lines()
            .find(|l| l.contains("/pull/"))
            .map(str::trim)
            .map(str::to_string)
            .ok_or_else(|| {
                BackendError::Rejected(format!(
                    "`gh pr create` succeeded but stdout had no PR URL: {stdout}"
                ))
            })?;
        let number = extract_pr_number(&url).ok_or_else(|| {
            BackendError::Rejected(format!("couldn't extract PR number from `{url}`"))
        })?;
        Ok(PullRequestResponse { url, number })
    }
}

/// Fetch the repository's default branch. Output of `gh api repos/o/r`
/// includes `default_branch: "main"` (or similar).
fn fetch_default_branch(gh_bin: &Path, owner: &str, repo: &str) -> Result<String, BackendError> {
    let output = Command::new(gh_bin)
        .arg("api")
        .arg(format!("repos/{owner}/{repo}"))
        .output()
        .map_err(|err| {
            BackendError::Network(format!(
                "couldn't execute `gh api` for repo metadata: {err}"
            ))
        })?;
    if !output.status.success() {
        return Err(BackendError::Network(format!(
            "`gh api` for repo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|err| {
        BackendError::Network(format!(
            "couldn't parse `gh api` JSON for repo metadata: {err}"
        ))
    })?;
    json.get("default_branch")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| {
            BackendError::Network("`gh api repos/o/r` returned no `default_branch` field".into())
        })
}

fn extract_pr_number(url: &str) -> Option<u64> {
    let after = url.rsplit_once("/pull/").map(|(_, after)| after)?;
    let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Parse `owner/repo` out of a git remote URL.
///
/// Accepts both HTTPS (`https://github.com/owner/repo`) and SSH
/// (`git@github.com:owner/repo.git`) shapes. The `.git` suffix is
/// stripped if present.
pub fn parse_owner_repo_from_url(remote_url: &str) -> Option<(String, String)> {
    let trimmed = remote_url.trim().trim_end_matches('/');
    let stem = trimmed.strip_suffix(".git").unwrap_or(trimmed);

    // SSH form: `git@host:owner/repo` — the URL has a `:` but no `://`.
    if !stem.contains("://")
        && let Some((_, after)) = stem.split_once(':')
        && let Some((owner, repo)) = after.rsplit_once('/')
        && !owner.is_empty()
        && !repo.is_empty()
    {
        return Some((owner.to_string(), repo.to_string()));
    }

    // URL form (https://, ssh://, git://): take the last two `/`-separated
    // segments after the scheme.
    let mut iter = stem.rsplit('/');
    let repo = iter.next()?;
    let owner = iter.next()?;
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    // `https://github.com` (no path) → rsplit gives ("github.com", "")
    // — we caught empty owner above. Defend against owner == "https:"
    // (rsplit of `https://owner`) too.
    if owner.contains(':') {
        return None;
    }
    Some((owner.to_string(), repo.to_string()))
}

/// Run `git remote get-url <remote>` in `repo` and parse owner/repo.
pub fn parse_owner_repo_from_origin(
    repo: &Path,
    remote: &str,
) -> Result<(String, String), BackendError> {
    let output = Command::new("git")
        .arg("remote")
        .arg("get-url")
        .arg(remote)
        .current_dir(repo)
        .output()
        .map_err(|err| {
            BackendError::NotConfigured(format!(
                "couldn't run `git remote get-url {remote}`: {err}"
            ))
        })?;
    if !output.status.success() {
        return Err(BackendError::NotConfigured(format!(
            "no `{remote}` remote configured: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let url = stdout.trim();
    parse_owner_repo_from_url(url).ok_or_else(|| {
        BackendError::NotConfigured(format!("couldn't parse owner/repo from remote URL `{url}`"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_owner_repo_handles_https_url() {
        let (owner, repo) =
            parse_owner_repo_from_url("https://github.com/wildmason/assay").unwrap();
        assert_eq!(owner, "wildmason");
        assert_eq!(repo, "assay");
    }

    #[test]
    fn parse_owner_repo_strips_git_suffix() {
        let (owner, repo) =
            parse_owner_repo_from_url("https://github.com/wildmason/assay.git").unwrap();
        assert_eq!(owner, "wildmason");
        assert_eq!(repo, "assay");
    }

    #[test]
    fn parse_owner_repo_strips_trailing_slash() {
        let (owner, repo) =
            parse_owner_repo_from_url("https://github.com/wildmason/assay/").unwrap();
        assert_eq!(owner, "wildmason");
        assert_eq!(repo, "assay");
    }

    #[test]
    fn parse_owner_repo_handles_ssh_url() {
        let (owner, repo) =
            parse_owner_repo_from_url("git@github.com:wildmason/assay.git").unwrap();
        assert_eq!(owner, "wildmason");
        assert_eq!(repo, "assay");
    }

    #[test]
    fn parse_owner_repo_returns_none_for_malformed_url() {
        assert!(parse_owner_repo_from_url("https://github.com").is_none());
        assert!(parse_owner_repo_from_url("").is_none());
    }

    #[test]
    fn extract_pr_number_from_canonical_url() {
        let n = extract_pr_number("https://github.com/wildmason/assay/pull/42").unwrap();
        assert_eq!(n, 42);
    }

    #[test]
    fn extract_pr_number_handles_trailing_junk() {
        let n = extract_pr_number("https://github.com/owner/repo/pull/123\n").unwrap();
        assert_eq!(n, 123);
    }

    #[test]
    fn extract_pr_number_returns_none_for_non_pr_url() {
        assert!(extract_pr_number("https://github.com/owner/repo").is_none());
    }

    // The Command-shelling integration tests live in fixture-binary
    // form below — they require a `gh` substitute on PATH.
    fn fixture_gh_script(tmp: &Path, response: &str) -> PathBuf {
        // Cross-platform fixture: on Unix write a shell script that
        // echoes `response`; on Windows write a `.cmd`.
        //
        // The Unix path uses explicit `File::create` + `write_all` +
        // `sync_all` + drop instead of `std::fs::write` because under
        // heavy parallel test load on Linux CI runners, executing a
        // file that was just written can race against the kernel's
        // `ETXTBSY` guard (`Text file busy` errno 26). `sync_all`
        // forces a write barrier so the file descriptor is fully
        // closed before exec; an empirical fix from the gh_cli test
        // flake on the v1.1.0 release CI run.
        if cfg!(windows) {
            let path = tmp.join("gh.cmd");
            std::fs::write(&path, format!("@echo off\necho {response}\nexit /b 0\n")).unwrap();
            path
        } else {
            let path = tmp.join("gh");
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::fs::PermissionsExt;
                {
                    let mut file = std::fs::File::create(&path).unwrap();
                    file.write_all(
                        format!("#!/bin/sh\nprintf '%s\\n' '{response}'\nexit 0\n").as_bytes(),
                    )
                    .unwrap();
                    file.sync_all().unwrap();
                }
                let mut perms = std::fs::metadata(&path).unwrap().permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&path, perms).unwrap();
            }
            #[cfg(not(unix))]
            {
                std::fs::write(
                    &path,
                    format!("#!/bin/sh\nprintf '%s\\n' '{response}'\nexit 0\n"),
                )
                .unwrap();
            }
            path
        }
    }

    #[test]
    fn fetch_branch_metadata_treats_404_as_fresh_branch() {
        let tmp = tempfile::tempdir().unwrap();
        // Fixture: first call (repo metadata) returns default_branch=main.
        // Second call (branch lookup) returns Not Found — emulated by
        // writing a smart script that branches on argv.
        let gh_path = if cfg!(windows) {
            let path = tmp.path().join("gh.cmd");
            std::fs::write(
                &path,
                "@echo off\r\nif \"%2\"==\"repos/o/r\" (echo {\"default_branch\":\"main\"}\r\nexit /b 0)\r\necho HTTP 404: Not Found 1>&2\r\nexit /b 1\r\n",
            )
            .unwrap();
            path
        } else {
            let path = tmp.path().join("gh");
            std::fs::write(
                &path,
                "#!/bin/sh\nif [ \"$2\" = \"repos/o/r\" ]; then\n  echo '{\"default_branch\":\"main\"}'\n  exit 0\nfi\necho 'HTTP 404: Not Found' 1>&2\nexit 1\n",
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&path).unwrap().permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&path, perms).unwrap();
            }
            path
        };
        let backend = GhCliBackend::new(gh_path);
        let meta = backend
            .fetch_branch_metadata("o", "r", "assay/cargo/serde-abc")
            .expect("404 should resolve to a fresh-branch metadata");
        assert_eq!(meta.name, "assay/cargo/serde-abc");
        assert!(!meta.is_default);
        assert!(!meta.is_protected);
    }

    #[test]
    fn fetch_branch_metadata_marks_default_branch_correctly() {
        let tmp = tempfile::tempdir().unwrap();
        // Fixture returns default_branch=main and the branch JSON
        // (any successful 200 OK) with protected=false.
        let gh_path = if cfg!(windows) {
            let path = tmp.path().join("gh.cmd");
            std::fs::write(
                &path,
                "@echo off\r\nif \"%2\"==\"repos/o/r\" (echo {\"default_branch\":\"main\"}\r\nexit /b 0)\r\necho {\"name\":\"main\",\"protected\":false}\r\nexit /b 0\r\n",
            )
            .unwrap();
            path
        } else {
            let path = tmp.path().join("gh");
            std::fs::write(
                &path,
                "#!/bin/sh\nif [ \"$2\" = \"repos/o/r\" ]; then\n  echo '{\"default_branch\":\"main\"}'\n  exit 0\nfi\necho '{\"name\":\"main\",\"protected\":false}'\nexit 0\n",
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&path).unwrap().permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&path, perms).unwrap();
            }
            path
        };
        let backend = GhCliBackend::new(gh_path);
        let meta = backend
            .fetch_branch_metadata("o", "r", "main")
            .expect("main-as-target should resolve");
        assert!(meta.is_default, "expected `main` flagged as default");
    }

    #[test]
    fn open_pull_request_parses_url_from_stdout() {
        let tmp = tempfile::tempdir().unwrap();
        let gh_path = fixture_gh_script(tmp.path(), "https://github.com/o/r/pull/77");
        let backend = GhCliBackend::new(gh_path);
        let request = PullRequestRequest {
            owner: "o".into(),
            repo: "r".into(),
            branch: "assay/cargo/x".into(),
            base: "main".into(),
            title: "Bump x".into(),
            body: "body".into(),
            labels: vec![],
            reviewers: vec![],
            draft: false,
        };
        let resp = backend
            .open_pull_request(&request)
            .expect("PR open should succeed");
        assert_eq!(resp.number, 77);
        assert!(resp.url.contains("/pull/77"));
    }

    #[test]
    fn check_auth_passes_when_repo_scope_present() {
        let tmp = tempfile::tempdir().unwrap();
        let gh_path = fixture_gh_script(tmp.path(), "Token scopes: 'repo', 'workflow'");
        let backend = GhCliBackend::new(gh_path);
        backend.check_auth().expect("repo scope should be detected");
    }

    #[test]
    fn check_auth_fails_when_repo_scope_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let gh_path = fixture_gh_script(tmp.path(), "Token scopes: 'gist'");
        let backend = GhCliBackend::new(gh_path);
        let err = backend
            .check_auth()
            .expect_err("missing repo scope should error");
        assert!(
            matches!(err, BackendError::Auth(ref msg) if msg.contains("repo")),
            "error should remediate missing `repo` scope: {err:?}"
        );
    }
}
