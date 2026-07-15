use std::{path::PathBuf, sync::Arc};

use thiserror::Error;
use tokio::{process::Command, sync::Mutex};

use crate::{
    app::{IacScanError, IacScanScope, IacScanner},
    domain::iacscanresult::iac_scan_result::IacScanResult,
};

use super::{
    scanner_binary_manager::{
        SCANNER_EXIT_CODE_INTERNAL_ERROR, SCANNER_EXIT_CODE_INVALID_PARAMS, ScannerBinaryManager,
        ScannerBinaryManagerError,
    },
    sysdig_iac_scanner_json_result_v1::JsonIacScanResultV1,
    sysdig_image_scanner::SysdigAPIToken,
};

const MAX_LOGGED_REPORT_BYTES: usize = 2048;

pub struct SysdigIacScanner {
    url: String,
    api_token: SysdigAPIToken,
    scanner_binary_manager: Arc<Mutex<ScannerBinaryManager>>,
}

#[derive(Error, Debug)]
pub(in crate::infra) enum SysdigIacScannerError {
    #[error("scanner binary manager error: {0}")]
    ScannerBinaryManager(#[from] ScannerBinaryManagerError),

    #[error("error executing the command: {0}")]
    CommandExecution(#[from] std::io::Error),

    #[error("error reading the IaC report at {path}: {source}")]
    ReportRead {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("error deserializing the IaC report: {0}")]
    ReportDeserialization(#[from] serde_json::Error),

    #[error("invalid parameters provided to the IaC scanner, check the URL and API Token: {0:?}")]
    InvalidParametersProvided(String),

    #[error("internal scanner execution error, this is commonly a bug in the CLI scanner: {0:?}")]
    InternalScannerExecutionError(String),
}

impl From<SysdigIacScannerError> for IacScanError {
    fn from(value: SysdigIacScannerError) -> Self {
        match value {
            SysdigIacScannerError::InvalidParametersProvided(stderr) => {
                IacScanError::InvalidConfiguration(stderr)
            }
            other => IacScanError::InternalScannerError(Box::new(other)),
        }
    }
}

impl SysdigIacScanner {
    pub(super) fn new(
        url: String,
        api_token: SysdigAPIToken,
        scanner_binary_manager: Arc<Mutex<ScannerBinaryManager>>,
    ) -> Self {
        Self {
            url,
            api_token,
            scanner_binary_manager,
        }
    }

    async fn scan(
        &self,
        scope: &IacScanScope,
    ) -> Result<JsonIacScanResultV1, SysdigIacScannerError> {
        let path_to_cli = self
            .scanner_binary_manager
            .lock()
            .await
            .install_expected_version_if_not_present()
            .await?;

        // Created with O_EXCL by tempfile (no predictable-path attacks) and
        // removed on drop, so failed scans don't leak files in the temp dir.
        let output_file = tempfile::Builder::new()
            .prefix("sysdig-lsp-iac-")
            .suffix(".json")
            .tempfile()?;

        let mut command = Command::new(path_to_cli);
        command.arg("--iac").arg("--apiurl").arg(&self.url);
        if matches!(scope, IacScanScope::Directory(_)) {
            command.arg("--recursive");
        }
        command
            .arg("--severity-threshold")
            .arg("never")
            .arg("--output-json")
            .arg(output_file.path())
            .arg(scope.path())
            .env("SECURE_API_TOKEN", self.api_token.0.as_str())
            // Don't leave the scanner running if the LSP request is cancelled.
            .kill_on_drop(true);

        let output = command.output().await?;

        match output.status.code() {
            Some(SCANNER_EXIT_CODE_INVALID_PARAMS) => {
                return Err(SysdigIacScannerError::InvalidParametersProvided(
                    String::from_utf8_lossy(&output.stderr).to_string(),
                ));
            }
            Some(SCANNER_EXIT_CODE_INTERNAL_ERROR) => {
                return Err(SysdigIacScannerError::InternalScannerExecutionError(
                    String::from_utf8_lossy(&output.stderr).to_string(),
                ));
            }
            None => {
                return Err(SysdigIacScannerError::InternalScannerExecutionError(
                    format!(
                        "scanner terminated by a signal: {}",
                        String::from_utf8_lossy(&output.stderr)
                    ),
                ));
            }
            _ => {}
        };

        let report_bytes = match tokio::fs::read(output_file.path()).await {
            Ok(bytes) => bytes,
            Err(e) => {
                return if output.status.success() {
                    Err(SysdigIacScannerError::ReportRead {
                        path: output_file.path().to_path_buf(),
                        source: e,
                    })
                } else {
                    Err(SysdigIacScannerError::InternalScannerExecutionError(
                        String::from_utf8_lossy(&output.stderr).to_string(),
                    ))
                };
            }
        };

        deserialize_with_debug(&report_bytes)
    }
}

#[async_trait::async_trait]
impl IacScanner for SysdigIacScanner {
    async fn scan_iac(&self, scope: &IacScanScope) -> Result<IacScanResult, IacScanError> {
        let scan = self.scan(scope).await?;
        Ok(scan.into_scan_result(scope))
    }
}

fn deserialize_with_debug(json_bytes: &[u8]) -> Result<JsonIacScanResultV1, SysdigIacScannerError> {
    serde_json::from_slice(json_bytes).map_err(|e| {
        let truncated =
            String::from_utf8_lossy(&json_bytes[..json_bytes.len().min(MAX_LOGGED_REPORT_BYTES)]);
        tracing::error!(
            "Failed to deserialize IaC scanner output. Raw JSON (truncated): {}",
            truncated
        );
        SysdigIacScannerError::ReportDeserialization(e)
    })
}
