#![forbid(unsafe_code)]

//! assay — dependency upgrade impact analyzer.
//!
//! See `docs/assay-plan.md` for the design document this crate implements.

pub mod apply_merger;
pub mod cli;
pub mod config;
pub mod ecosystem;
pub mod error;
pub mod external_deps;
pub mod member_gate;
pub mod model;
pub mod process_runner;
pub mod publisher;
pub mod receipt;
pub mod redact;
pub mod sanitize;
pub mod validator;
pub mod verdict_cache;
pub mod worker_pool;
pub mod workflow_filter;

pub use cli::{AnalyzeArgs, Cli, Command, parse_cli};
pub use ecosystem::{
    DependencyEcosystem, EcosystemContext, EcosystemName, cargo::CargoEcosystem,
    github_actions::GitHubActionsEcosystem,
};
pub use error::{Error, Result};
pub use model::{
    AssayRunReceipt, Classification, Manifest, ManifestKind, Proposal, ProposalKind,
    ValidationOutcome,
};
pub use receipt::write_run_receipt;
pub use sanitize::{SanitizeError, sanitize_branch_segment, sanitize_release_notes, sanitize_tag};
