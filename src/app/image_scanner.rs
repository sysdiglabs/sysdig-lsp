use std::error::Error;

use thiserror::Error;
use tracing::info;

use crate::domain::scanresult::scan_result::ScanResult;

#[async_trait::async_trait]
pub trait ImageScanner {
    async fn scan_image(&self, image_pull_string: &str) -> Result<ScanResult, ImageScanError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Vulnerabilities {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub negligible: usize,
}

impl From<ScanResult> for Vulnerabilities {
    fn from(value: ScanResult) -> Self {
        value
            .vulnerabilities()
            .into_iter()
            .fold(Self::default(), |mut acc, v| {
                use crate::domain::scanresult::severity::Severity;
                match v.severity() {
                    Severity::Critical => acc.critical += 1,
                    Severity::High => acc.high += 1,
                    Severity::Medium => acc.medium += 1,
                    Severity::Low => acc.low += 1,
                    Severity::Negligible => acc.negligible += 1,
                    Severity::Unknown => {
                        info!("unknown severity {:?}", v)
                    }
                }
                acc
            })
    }
}

#[derive(Error, Debug)]
pub enum ImageScanError {
    #[error("error in the internal scanner execution: {0}")]
    InternalScannerError(Box<dyn Error>),
}
