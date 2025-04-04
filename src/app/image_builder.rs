use std::{error::Error, path::Path};

use thiserror::Error;

#[async_trait::async_trait]
pub trait ImageBuilder {
    async fn build_image(&self, containerfile: &Path) -> Result<ImageBuildResult, ImageBuildError>;
}

pub struct ImageBuildResult {
    pub image_id: String,
    pub image_name: String,
}

#[derive(Error, Debug)]
pub enum ImageBuildError {
    #[error("image builder error: {0}")]
    ImageBuilderError(#[from] Box<dyn Error>),
}
