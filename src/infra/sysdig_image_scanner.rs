#![allow(dead_code)]

use std::{fmt::Display, sync::Arc};

use serde::Deserialize;
use thiserror::Error;
use tokio::{process::Command, sync::Mutex};

use crate::app::{ImageScanError, ImageScanResult, ImageScanner};

use super::{
    scanner_binary_manager::{ScannerBinaryManager, ScannerBinaryManagerError},
    sysdig_image_scanner_result::SysdigImageScannerReport,
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
    ) -> Result<SysdigImageScannerReport, SysdigImageScannerError> {
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

        let report: SysdigImageScannerReport = serde_json::from_slice(&output.stdout)?;

        Ok(report)
    }
}

#[async_trait::async_trait]
impl ImageScanner for SysdigImageScanner {
    async fn scan_image(&self, image_pull_string: &str) -> Result<ImageScanResult, ImageScanError> {
        Ok(self.scan(image_pull_string).await?.into())
    }
}

#[cfg(test)]
#[serial_test::file_serial]
mod tests {
    use lazy_static::lazy_static;

    use crate::app::{ImageScanner, VulnSeverity};

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

        assert!(report.info.is_some());
        assert!(report.scanner.is_some());
        assert!(report.result.is_some());
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

        assert!(report.count_vulns_of_severity(VulnSeverity::Critical) == 0);
        assert!(report.count_vulns_of_severity(VulnSeverity::High) == 0);
        assert!(report.count_vulns_of_severity(VulnSeverity::Medium) > 0);
        assert!(report.count_vulns_of_severity(VulnSeverity::Low) > 0);
        assert!(report.count_vulns_of_severity(VulnSeverity::Negligible) > 0);
        assert!(!report.is_compliant);
    }
}
