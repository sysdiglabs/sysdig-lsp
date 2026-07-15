use std::{
    error::Error,
    path::{Path, PathBuf},
};

use thiserror::Error;
use tower_lsp::lsp_types::Url;

use crate::domain::iacscanresult::iac_scan_result::IacScanResult;

/// Scope of an IaC scan. Makes invalid states (e.g. a recursive scan of a single file)
/// unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IacScanScope {
    /// Scan a single IaC file. Keeps the original client URI so diagnostics are
    /// published under the exact URI the editor opened the document with
    /// (a path→URI round-trip is not guaranteed to be byte-identical).
    File { uri: Url, path: PathBuf },
    /// Scan a directory recursively.
    Directory(PathBuf),
}

impl IacScanScope {
    pub fn path(&self) -> &Path {
        match self {
            IacScanScope::File { path, .. } => path,
            IacScanScope::Directory(path) => path,
        }
    }
}

#[async_trait::async_trait]
pub trait IacScanner {
    async fn scan_iac(&self, scope: &IacScanScope) -> Result<IacScanResult, IacScanError>;
}

#[derive(Error, Debug)]
pub enum IacScanError {
    #[error("invalid configuration for the IaC scanner, check the API URL and token: {0}")]
    InvalidConfiguration(String),

    #[error("error in the internal IaC scanner execution: {0}")]
    InternalScannerError(Box<dyn Error + Send + Sync>),
}
