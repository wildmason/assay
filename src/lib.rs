// `deny` rather than `forbid` so the single documented unsafe block in
// `process_runner.rs::kill_child_tree` (unix process-group signaling)
// can opt in via `#[allow(unsafe_code)]`. Every other unsafe block in
// the crate stays a hard error.
#![deny(unsafe_code)]

//! # assay — dependency upgrade impact analyzer
//!
//! Test dependency upgrades against your projects' real CI before
//! you adopt them. See the crate's [README] and [CHANGELOG] for the
//! tagline + feature surface.
//!
//! [README]: https://github.com/wildmason/assay/blob/main/README.md
//! [CHANGELOG]: https://github.com/wildmason/assay/blob/main/CHANGELOG.md
//!
//! ## Stability promise (1.0)
//!
//! Starting at 1.0, the following surfaces follow [SemVer 2.0]:
//!
//! - **CLI:** every documented flag in `assay analyze --help` is
//!   stable; subcommands and their flags will not be removed or
//!   semantically repurposed within a major version. New flags may
//!   be added in minor releases. Exit codes are stable (`0` success,
//!   non-zero error).
//! - **Receipt schema:** the JSON shape under
//!   `.assay/runs/<run-id>/run.json` (rooted at [`AssayRunReceipt`])
//!   carries `schema_version` and is forward-compatible within a
//!   major version. New fields are additive with `#[serde(default)]`;
//!   existing fields don't change shape or semantic.
//! - **Public Rust API:** the types re-exported below ([`Proposal`],
//!   [`Manifest`], [`ManifestKind`], [`Classification`],
//!   [`ProposalKind`], [`ValidationOutcome`], [`AssayRunReceipt`],
//!   [`Error`], [`Result`], [`AnalyzeArgs`], [`DependencyEcosystem`],
//!   [`EcosystemContext`], [`EcosystemName`]) follow SemVer. Adding
//!   variants to enums in this set is a minor change; removing or
//!   renaming variants is a major change.
//!
//! Modules NOT listed below (e.g. `apply_merger`, `worker_pool`,
//! `validator`, `verdict_cache`, `workflow_filter`, `process_runner`,
//! `redact`, `external_deps`, `member_gate`, `publisher`,
//! `sanitize`, `config`) are exposed as `pub` for the binary's use
//! but are NOT covered by the stability promise. Treat them as
//! implementation detail; their signatures may change in any
//! minor release. They're marked `#[doc(hidden)]` so they don't
//! appear on docs.rs.
//!
//! [SemVer 2.0]: https://semver.org/spec/v2.0.0.html

#[doc(hidden)]
pub mod apply_merger;
pub mod cli;
#[doc(hidden)]
pub mod config;
pub mod ecosystem;
pub mod error;
pub mod events;
#[doc(hidden)]
pub mod external_deps;
pub mod failure_context;
#[doc(hidden)]
pub mod failure_parser;
#[doc(hidden)]
pub mod member_gate;
pub mod model;
#[doc(hidden)]
pub mod process_runner;
#[doc(hidden)]
pub mod publisher;
pub mod receipt;
#[doc(hidden)]
pub mod redact;
#[doc(hidden)]
pub mod sanitize;
#[doc(hidden)]
pub mod validator;
#[doc(hidden)]
pub mod verdict_cache;
#[doc(hidden)]
pub mod worker_pool;
#[doc(hidden)]
pub mod workflow_filter;

pub use cli::{AnalyzeArgs, Cli, Command, parse_cli};
pub use ecosystem::{
    DependencyEcosystem, EcosystemContext, EcosystemName, cargo::CargoEcosystem,
    github_actions::GitHubActionsEcosystem,
};
pub use error::{Error, Result};
pub use failure_context::{FailureCluster, FailureContext, FailureFinding, cluster_failures};
pub use model::{
    AssayRunReceipt, Classification, Manifest, ManifestKind, Proposal, ProposalKind,
    ValidationOutcome,
};
pub use receipt::write_run_receipt;
#[doc(hidden)]
pub use sanitize::{SanitizeError, sanitize_branch_segment, sanitize_release_notes, sanitize_tag};
