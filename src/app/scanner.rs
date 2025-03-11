use thiserror::Error;

#[async_trait::async_trait]
pub trait ImageScanner {
    async fn scan_image(
        &mut self,
        image_pull_string: &str,
    ) -> Result<ImageScanResult, ImageScanError>;
}

#[derive(Clone, Copy, Debug)]
pub struct ImageScanResult {
    pub vulnerabilities: Vulnerabilities,
    pub is_compliant: bool,
}

impl ImageScanResult {
    pub fn has_vulnerabilities(&self) -> bool {
        let v = &self.vulnerabilities;
        v.critical > 0 || v.high > 0 || v.medium > 0 || v.low > 0 || v.negligible > 0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Vulnerabilities {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub negligible: usize,
}

#[derive(Error, Debug)]
pub enum ImageScanError {
    #[error("unknown error")]
    Unknown = 0,
}
