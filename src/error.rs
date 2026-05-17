use std::io;
use std::path::PathBuf;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("io error: {0}")]
    PlainIo(#[from] io::Error),

    #[error("repository path {0} does not exist or is not a directory")]
    RepoNotFound(PathBuf),

    #[error("invalid config at {path}: {message}")]
    InvalidConfig { path: PathBuf, message: String },

    #[error("invalid manifest at {path}: {message}")]
    InvalidManifest { path: PathBuf, message: String },

    #[error("cargo update failed: {message}")]
    CargoUpdate { message: String },

    #[error("cargo update parser disagreed with lockfile diff: {message}")]
    CargoParserMismatch { message: String },

    #[error("sanitizer rejected upstream value: {0}")]
    Sanitize(#[from] crate::sanitize::SanitizeError),

    #[error("yaml parse error at {path}: {source}")]
    Yaml {
        path: PathBuf,
        #[source]
        source: serde_yml::Error,
    },

    #[error("yaml error: {0}")]
    PlainYaml(#[from] serde_yml::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("toml error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn other(msg: impl Into<String>) -> Self {
        Error::Other(msg.into())
    }
}
