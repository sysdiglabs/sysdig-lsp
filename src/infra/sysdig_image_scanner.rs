#![allow(dead_code)]

use std::{fmt::Display, sync::Arc};

use serde::Deserialize;
use thiserror::Error;
use tokio::{process::Command, sync::Mutex};

use crate::{
    app::{ImageScanError, ImageScanner},
    domain::scanresult::scan_result::ScanResult,
};

use super::{
    scanner_binary_manager::{ScannerBinaryManager, ScannerBinaryManagerError},
    sysdig_image_scanner_json_scan_result_v1::JsonScanResultV1,
};

#[derive(Clone)]
pub struct SysdigImageScanner {
    url: String,
    api_token: SysdigAPIToken,
    scanner_binary_manager: Arc<Mutex<ScannerBinaryManager>>,
}

#[derive(Clone, Deserialize)]
pub struct SysdigAPIToken(pub String);

impl std::fmt::Debug for SysdigAPIToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

impl Display for SysdigAPIToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

#[derive(Error, Debug)]
pub(in crate::infra) enum SysdigImageScannerError {
    #[error("scanner binary manager error: {0}")]
    ScannerBinaryManager(#[from] ScannerBinaryManagerError),

    #[error("error executing the command: {0}")]
    CommandExecution(#[from] std::io::Error),

    #[error("error deserializing the report: {0}")]
    ReportDeserialization(#[from] serde_json::Error),

    #[error("invalid parameters provided to the image scanner, check the URL and API Token: {0:?}")]
    InvalidParametersProvided(String),

    #[error("internal scanner execution error, this is commonly a bug in the CLI scanner: {0:?}")]
    InternalScannerExecutionError(String),
}

impl From<SysdigImageScannerError> for ImageScanError {
    fn from(value: SysdigImageScannerError) -> Self {
        ImageScanError::InternalScannerError(Box::new(value))
    }
}

impl SysdigImageScanner {
    pub fn new(url: String, api_token: SysdigAPIToken) -> Self {
        Self {
            url,
            api_token,
            scanner_binary_manager: Default::default(),
        }
    }

    async fn scan(
        &self,
        image_pull_string: &str,
    ) -> Result<JsonScanResultV1, SysdigImageScannerError> {
        let path_to_cli = self
            .scanner_binary_manager
            .lock()
            .await
            .install_expected_version_if_not_present()
            .await?;

        let args = [
            image_pull_string,
            "--no-cache", // needed for concurrent scanning execution
            "--output=json",
            "--output-schema=v1",
            "--separate-by-layer",
            "--console-log",
            "--skipupload",
            "--apiurl",
            self.url.as_str(),
        ];

        let env_vars = [("SECURE_API_TOKEN", self.api_token.0.as_str())];

        let output = Command::new(path_to_cli)
            .args(args)
            .envs(env_vars)
            .output()
            .await?;

        match output.status.code().unwrap_or(0) {
            2 => {
                return Err(SysdigImageScannerError::InvalidParametersProvided(
                    String::from_utf8_lossy(&output.stderr).to_string(),
                ));
            }
            3 => {
                return Err(SysdigImageScannerError::InternalScannerExecutionError(
                    String::from_utf8_lossy(&output.stderr).to_string(),
                ));
            }
            _ => {}
        };

        deserialize_with_debug(&output.stdout)
    }
}

#[async_trait::async_trait]
impl ImageScanner for SysdigImageScanner {
    async fn scan_image(&self, image_pull_string: &str) -> Result<ScanResult, ImageScanError> {
        let scan = self.scan(image_pull_string).await?;
        Ok(ScanResult::from(scan))
    }
}

fn deserialize_with_debug(json_bytes: &[u8]) -> Result<JsonScanResultV1, SysdigImageScannerError> {
    let output_json = String::from_utf8_lossy(json_bytes);
    serde_json::from_str(&output_json).map_err(|e| {
        tracing::error!(
            "Failed to deserialize scanner output. Raw JSON: {}",
            output_json
        );
        SysdigImageScannerError::ReportDeserialization(e)
    })
}

#[cfg(test)]
#[serial_test::file_serial]
mod tests {
    use crate::infra::sysdig_image_scanner::deserialize_with_debug;
    use lazy_static::lazy_static;

    use tracing_test::traced_test;

    use crate::app::ImageScanner;

    use super::{SysdigAPIToken, SysdigImageScanner};

    lazy_static! {
        static ref SYSDIG_SECURE_URL: String =
            std::env::var("SECURE_API_URL").expect("SECURE_API_URL env var not set");
        static ref SYSDIG_SECURE_TOKEN: SysdigAPIToken =
            SysdigAPIToken(std::env::var("SECURE_API_TOKEN").expect("SECURE_API_TOKEN not set"));
    }

    #[tokio::test]
    async fn it_retrieves_the_scanner_from_the_specified_version() {
        let scanner =
            SysdigImageScanner::new(SYSDIG_SECURE_URL.clone(), SYSDIG_SECURE_TOKEN.clone());

        let report = scanner.scan("ubuntu:22.04").await.unwrap();

        assert_eq!(report.scanner.name, "sysdig-cli-scanner");
        assert_eq!(report.result.metadata.pull_string, "ubuntu:22.04");
    }

    #[tokio::test]
    async fn it_scans_the_ubuntu_image_correctly() {
        let scanner =
            SysdigImageScanner::new(SYSDIG_SECURE_URL.clone(), SYSDIG_SECURE_TOKEN.clone());

        let report = scanner
            .scan_image(
                "ubuntu@sha256:a76d0e9d99f0e91640e35824a6259c93156f0f07b7778ba05808c750e7fa6e68",
            )
            .await
            .unwrap();

        assert_eq!(
            report.metadata().pull_string(),
            "ubuntu@sha256:a76d0e9d99f0e91640e35824a6259c93156f0f07b7778ba05808c750e7fa6e68"
        );

        assert!(!report.layers().is_empty());
        assert!(!report.vulnerabilities().is_empty());
        assert!(!report.packages().is_empty());
        assert!(report.evaluation_result().is_failed());
    }

    #[test]
    #[traced_test]
    fn it_logs_invalid_json_on_deserialization_error() {
        let invalid_json = b"{\"foo\": \"bar\"}";

        let result = deserialize_with_debug(invalid_json);
        assert!(result.is_err());
        assert!(logs_contain(
            "Failed to deserialize scanner output. Raw JSON: {\"foo\": \"bar\"}"
        ));
    }
}
