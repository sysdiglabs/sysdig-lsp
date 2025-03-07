use crate::app::{ImageScanError, ImageScanResult, ImageScanner};

#[derive(Clone, Default)]
pub struct SysdigImageScanner {}

impl SysdigImageScanner {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait::async_trait]
impl ImageScanner for SysdigImageScanner {
    async fn scan_image(
        &self,
        _image_pull_string: &str,
    ) -> Result<ImageScanResult, ImageScanError> {
        unimplemented!();
    }
}
