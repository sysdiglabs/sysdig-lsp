use std::error::Error;

use thiserror::Error;

#[async_trait::async_trait]
pub trait ImageScanner {
    async fn scan_image(&self, image_pull_string: &str) -> Result<ImageScanResult, ImageScanError>;
}

#[derive(Clone, Debug)]
pub struct ImageScanResult {
    pub vulnerabilities: Vec<VulnerabilityEntry>,
    pub is_compliant: bool,
    pub layers: Vec<LayerScanResult>,
}

impl ImageScanResult {
    pub fn count_vulns_of_severity(&self, severity: VulnSeverity) -> usize {
        self.vulnerabilities
            .iter()
            .filter(|v| v.severity == severity)
            .count()
    }

    pub fn has_vulnerabilities(&self) -> bool {
        !self.vulnerabilities.is_empty()
    }
}

#[derive(Clone, Debug)]
pub struct VulnerabilityEntry {
    pub id: String,
    pub severity: VulnSeverity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VulnSeverity {
    Critical,
    High,
    Medium,
    Low,
    Negligible,
}

#[derive(Clone, Debug)]
pub struct LayerScanResult {
    pub layer_instruction: String,
    pub layer_text: String,
    pub vulnerabilities: Vec<VulnerabilityEntry>,
}

impl LayerScanResult {
    pub fn count_vulns_of_severity(&self, severity: VulnSeverity) -> usize {
        self.vulnerabilities
            .iter()
            .filter(|v| v.severity == severity)
            .count()
    }

    pub fn has_vulnerabilities(&self) -> bool {
        !self.vulnerabilities.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Vulnerabilities {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub negligible: usize,
}

#[derive(Error, Debug)]
pub enum ImageScanError {
    #[error("error in the internal scanner execution: {0}")]
    InternalScannerError(Box<dyn Error>),
}
