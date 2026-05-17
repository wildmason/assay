//! Publisher — the `--apply-remote` slice.
//!
//! v1 exposes the testable building blocks (deterministic branch names,
//! sanitized PR body rendering, charset-safe git argv construction,
//! three independent push-target guards). The actual HTTP exchange with
//! GitHub (installation-token mint, branch creation, PR opening) lives
//! behind the [`PullRequestBackend`] trait so unit tests can drive it
//! with a deterministic mock; the live Octocrab-backed impl lights up
//! once the operator has registered a `assay-bot` GitHub App.
//!
//! Per plan §A.5: there is NO trait until a second impl materializes —
//! [`PullRequestBackend`] is allowed only because its `Mock` impl in
//! tests counts as the second impl.

use std::path::PathBuf;

pub mod branch_name;
pub mod git_push;
pub mod guards;
pub mod pr_body;

pub use branch_name::branch_name_for_bump;
pub use git_push::{
    GitPushError, build_push_argv, push_branch, validate_branch_name, validate_remote_name,
};
pub use guards::{BranchMetadata, PushTargetError, guard_push_target};
pub use pr_body::{PrBodyContext, render_pr_body};

/// Request shape for opening a pull request.
#[derive(Debug, Clone)]
pub struct PullRequestRequest {
    pub owner: String,
    pub repo: String,
    pub branch: String,
    pub base: String,
    pub title: String,
    pub body: String,
    pub labels: Vec<String>,
    pub reviewers: Vec<String>,
    pub draft: bool,
}

/// Response shape — what the backend returns after opening the PR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullRequestResponse {
    pub url: String,
    pub number: u64,
}

/// Pluggable backend so tests can run without GitHub. The live Octocrab
/// impl will land when the GitHub App is registered; until then only the
/// mock is wired up.
pub trait PullRequestBackend: Send + Sync {
    fn fetch_branch_metadata(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
    ) -> Result<BranchMetadata, BackendError>;

    fn open_pull_request(
        &self,
        request: &PullRequestRequest,
    ) -> Result<PullRequestResponse, BackendError>;
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("backend not configured: {0}")]
    NotConfigured(String),
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("forge rejected the request: {0}")]
    Rejected(String),
}

/// Stub backend used until the GitHub App is registered. Every operation
/// returns `BackendError::NotConfigured`, which the publisher surfaces
/// to the operator with a clear remediation message.
pub struct UnconfiguredBackend;

impl PullRequestBackend for UnconfiguredBackend {
    fn fetch_branch_metadata(
        &self,
        _owner: &str,
        _repo: &str,
        _branch: &str,
    ) -> Result<BranchMetadata, BackendError> {
        Err(BackendError::NotConfigured(
            "no GitHub App secrets file passed to --secret-file; \
             run `assay init github-app` and retry"
                .into(),
        ))
    }

    fn open_pull_request(
        &self,
        _request: &PullRequestRequest,
    ) -> Result<PullRequestResponse, BackendError> {
        Err(BackendError::NotConfigured(
            "no GitHub App secrets file passed to --secret-file".into(),
        ))
    }
}

/// Inputs to [`build_pull_request_request`]. Groups the params so the
/// builder stays under clippy's `too_many_arguments` threshold while the
/// call sites stay legible.
#[derive(Debug, Clone)]
pub struct PullRequestParams<'a> {
    pub owner: &'a str,
    pub repo: &'a str,
    pub branch: &'a str,
    pub base: &'a str,
    pub subject: &'a str,
    pub body: String,
    pub labels: Vec<String>,
    pub reviewers: Vec<String>,
    pub draft: bool,
}

/// Compose a `PullRequestRequest` from a proposal + validation outcome.
/// Caller is responsible for: branch already pushed, branch metadata
/// fetched + guarded, body sanitized (use [`render_pr_body`]).
pub fn build_pull_request_request(params: PullRequestParams<'_>) -> PullRequestRequest {
    PullRequestRequest {
        owner: params.owner.into(),
        repo: params.repo.into(),
        branch: params.branch.into(),
        base: params.base.into(),
        title: format!("Bump {}", params.subject),
        body: params.body,
        labels: params.labels,
        reviewers: params.reviewers,
        draft: params.draft,
    }
}

/// Path the publisher writes its stage receipt to (for the run receiptor).
pub fn publisher_receipt_path(run_id: &str, proposal_id: &str) -> PathBuf {
    PathBuf::from(format!("publisher-{proposal_id}.json"))
        .with_file_name(format!("publisher-{run_id}-{proposal_id}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingBackend {
        opened: std::sync::Mutex<Vec<PullRequestRequest>>,
        branch_response: BranchMetadata,
    }

    impl PullRequestBackend for RecordingBackend {
        fn fetch_branch_metadata(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<BranchMetadata, BackendError> {
            Ok(self.branch_response.clone())
        }

        fn open_pull_request(
            &self,
            request: &PullRequestRequest,
        ) -> Result<PullRequestResponse, BackendError> {
            self.opened.lock().unwrap().push(request.clone());
            Ok(PullRequestResponse {
                url: "https://github.com/owner/repo/pull/42".into(),
                number: 42,
            })
        }
    }

    #[test]
    fn unconfigured_backend_returns_not_configured_for_both_methods() {
        let backend = UnconfiguredBackend;
        let m = backend.fetch_branch_metadata("o", "r", "b").unwrap_err();
        assert!(matches!(m, BackendError::NotConfigured(_)));
        let req = build_pull_request_request(PullRequestParams {
            owner: "o",
            repo: "r",
            branch: "assay/cargo/serde-abc",
            base: "main",
            subject: "serde",
            body: "body".into(),
            labels: vec![],
            reviewers: vec![],
            draft: false,
        });
        let p = backend.open_pull_request(&req).unwrap_err();
        assert!(matches!(p, BackendError::NotConfigured(_)));
    }

    #[test]
    fn build_pull_request_request_sets_title_from_subject() {
        let req = build_pull_request_request(PullRequestParams {
            owner: "o",
            repo: "r",
            branch: "assay/cargo/serde-abc",
            base: "main",
            subject: "serde",
            body: "body".into(),
            labels: vec!["assay".into()],
            reviewers: vec![],
            draft: false,
        });
        assert_eq!(req.title, "Bump serde");
    }

    #[test]
    fn recording_backend_captures_open_request() {
        let backend = RecordingBackend {
            opened: std::sync::Mutex::new(Vec::new()),
            branch_response: BranchMetadata {
                name: "assay/cargo/serde-abc".into(),
                is_default: false,
                is_protected: false,
            },
        };
        let req = build_pull_request_request(PullRequestParams {
            owner: "o",
            repo: "r",
            branch: "assay/cargo/serde-abc",
            base: "main",
            subject: "serde",
            body: "body".into(),
            labels: vec![],
            reviewers: vec![],
            draft: false,
        });
        let resp = backend.open_pull_request(&req).unwrap();
        assert_eq!(resp.number, 42);
        assert_eq!(backend.opened.lock().unwrap().len(), 1);
    }

    #[test]
    fn publisher_pipeline_smoke_against_mock_backend() {
        // Build a fake PR end-to-end against a mock backend. Demonstrates
        // the composable shape works without GitHub.
        let backend = RecordingBackend {
            opened: std::sync::Mutex::new(Vec::new()),
            branch_response: BranchMetadata {
                name: "assay/cargo/serde-abc".into(),
                is_default: false,
                is_protected: false,
            },
        };
        // 1. Fetch branch metadata + guard.
        let meta = backend
            .fetch_branch_metadata("o", "r", "assay/cargo/serde-abc")
            .unwrap();
        guard_push_target("assay/cargo/serde-abc", &meta).unwrap();
        // 2. Build PR request.
        let req = build_pull_request_request(PullRequestParams {
            owner: "o",
            repo: "r",
            branch: "assay/cargo/serde-abc",
            base: "main",
            subject: "serde",
            body: "body".into(),
            labels: vec!["assay".into()],
            reviewers: vec![],
            draft: false,
        });
        // 3. Open.
        let resp = backend.open_pull_request(&req).unwrap();
        assert_eq!(resp.number, 42);
    }
}
