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
mod tests {
    use super::*;
    use crate::infra::sysdig_image_scanner;
    use rstest::*;
    use tracing_test::traced_test;

    #[test]
    #[traced_test]
    fn it_logs_invalid_json_on_deserialization_error() {
        let invalid_json = b"{\"foo\": \"bar\"}";

        let result = sysdig_image_scanner::deserialize_with_debug(invalid_json);
        assert!(result.is_err());
        assert!(logs_contain(
            "Failed to deserialize scanner output. Raw JSON: {\"foo\": \"bar\"}"
        ));
    }

    #[fixture]
    fn scanner() -> SysdigImageScanner {
        let sysdig_secure_url: String =
            std::env::var("SECURE_API_URL").expect("SECURE_API_URL env var not set");
        let sysdig_secure_token: SysdigAPIToken =
            SysdigAPIToken(std::env::var("SECURE_API_TOKEN").expect("SECURE_API_TOKEN not set"));
        SysdigImageScanner::new(sysdig_secure_url.clone(), sysdig_secure_token.clone())
    }

    #[rstest]
    #[case("ubuntu:22.04")]
    #[case("ubuntu@sha256:a76d0e9d99f0e91640e35824a6259c93156f0f07b7778ba05808c750e7fa6e68")]
    #[case("debian:11")]
    #[case("alpine:3.16")]
    #[case("centos:7")]
    #[case("nginx:1.23")]
    #[case("postgres:14")]
    #[case("mysql:8.0")]
    #[case("node:18")]
    #[case("python:3.13")]
    #[case("golang:1.25")]
    #[case("rust:1.88")]
    #[case("quay.io/prometheus/prometheus:v2.40.1")]
    #[case("registry.access.redhat.com/ubi8/ubi:latest")]
    #[case("gcr.io/distroless/static-debian12")]
    #[case("gcr.io/distroless/base-debian12")]
    #[case("amazonlinux:2")]
    #[case("mongo:5.0")]
    #[case("quay.io/sysdig/agent-slim:latest")]
    #[case("openjdk:26-ea-slim")]
    #[case("quay.io/sysdig/sysdig-ubi9:1")]
    #[serial_test::file_serial(scanner)]
    #[tokio::test]
    async fn it_scans_popular_images_correctly_test(
        scanner: SysdigImageScanner,
        #[case] image_to_scan: &str,
    ) {
        use crate::app::ImageScanner;

        let report = scanner.scan_image(image_to_scan).await.unwrap();

        assert_eq!(report.metadata().pull_string(), image_to_scan);
        assert!(!report.packages().is_empty());
        assert!(!report.layers().is_empty());
    }
}
