use std::error::Error;

use thiserror::Error;

use crate::domain::scanresult::scan_result::ScanResult;

#[async_trait::async_trait]
pub trait ImageScanner {
    async fn scan_image(&self, image_pull_string: &str) -> Result<ScanResult, ImageScanError>;
}

#[derive(Error, Debug)]
pub enum ImageScanError {
    #[error("error in the internal scanner execution: {0}")]
    InternalScannerError(Box<dyn Error>),
}
