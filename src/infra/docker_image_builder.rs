use std::path::Path;

use bollard::{Docker, image::BuildImageOptions, secret::BuildInfo};
use bytes::Bytes;
use futures::StreamExt;
use thiserror::Error;
use tracing::info;

use crate::app::{ImageBuildError, ImageBuildResult, ImageBuilder};

#[derive(Error, Debug)]
pub(in crate::infra) enum DockerImageBuilderError {
    #[error("internal tokio join error: {0}")]
    TokioJoin(#[from] tokio::task::JoinError),

    #[error("internal io error: {0}")]
    IO(#[from] std::io::Error),

    #[error("internal docker client error: {0:?}")]
    Docker(#[from] bollard::errors::Error),

    #[error("internal generic error: {0}")]
    Generic(String),
}

impl From<DockerImageBuilderError> for ImageBuildError {
    fn from(value: DockerImageBuilderError) -> Self {
        ImageBuildError::ImageBuilderError(Box::new(value))
    }
}

#[derive(Clone)]
pub struct DockerImageBuilder {
    docker_client: Docker,
}

impl DockerImageBuilder {
    pub fn new(docker_client: Docker) -> Self {
        Self { docker_client }
    }

    async fn build_image_from_dockerfile(
        &self,
        containerfile: &Path,
    ) -> Result<ImageBuildResult, DockerImageBuilderError> {
        let tar_contents = self
            .pack_containerfile_dir_into_a_tar(containerfile)
            .await?;

        let image_name = format!("sysdig-lsp-image-build-{}", rand::random::<u8>());
        let mut results = self.docker_client.build_image(
            BuildImageOptions {
                dockerfile: containerfile
                    .file_name()
                    .and_then(|osstr| osstr.to_str())
                    .unwrap(),
                t: image_name.as_str(),
                rm: true,
                ..Default::default()
            },
            None,
            Some(Bytes::from_owner(tar_contents)),
        );

        while let Some(result) = results.next().await {
            println!("{:?}", result);
            match result {
                Ok(BuildInfo { aux, .. }) if aux.is_some() => {
                    let image_id = aux.unwrap().id.unwrap();
                    info!("image built: {}", &image_id);
                    return Ok(ImageBuildResult {
                        image_name,
                        image_id,
                    });
                }
                Ok(BuildInfo { stream, .. }) if stream.is_some() => {
                    info!("build status: {}", stream.unwrap())
                }
                Err(error) => return Err(DockerImageBuilderError::Docker(error)),
                _ => {}
            }
        }

        Err(DockerImageBuilderError::Generic(
            "image was built, but no id was detected, this should have never happened".to_string(),
        ))
    }

    async fn pack_containerfile_dir_into_a_tar(
        &self,
        containerfile: &Path,
    ) -> Result<Vec<u8>, DockerImageBuilderError> {
        let Some(parent) = containerfile.parent() else {
            return Err(DockerImageBuilderError::Generic(
                "unable to find parent for provided containerfile".to_string(),
            ));
        };
        let parent = parent.to_owned();

        tokio::task::spawn_blocking(move || -> Result<Vec<u8>, DockerImageBuilderError> {
            let mut tar_builder = tar::Builder::new(Vec::new());

            tar_builder.append_dir_all(".", parent)?;
            tar_builder.finish()?;

            Ok(tar_builder.into_inner()?)
        })
        .await?
    }
}

#[async_trait::async_trait]
impl ImageBuilder for DockerImageBuilder {
    async fn build_image(&self, containerfile: &Path) -> Result<ImageBuildResult, ImageBuildError> {
        Ok(self.build_image_from_dockerfile(containerfile).await?)
    }
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, str::FromStr};

    use bollard::Docker;

    use crate::{
        app::{ImageBuildError, ImageBuilder},
        infra::DockerImageBuilder,
    };

    #[tokio::test]
    async fn it_builds_a_dockerfile() {
        let docker_client = Docker::connect_with_local_defaults().unwrap();
        let image_builder = DockerImageBuilder::new(docker_client);

        let image_built = image_builder
            .build_image(&PathBuf::from_str("tests/fixtures/Dockerfile").unwrap())
            .await
            .unwrap();

        assert!(
            image_built
                .image_name
                .starts_with("sysdig-lsp-image-build-")
        );
        assert!(!image_built.image_id.is_empty());
    }

    #[tokio::test]
    async fn it_builds_a_containerfile() {
        let docker_client = Docker::connect_with_local_defaults().unwrap();
        let image_builder = DockerImageBuilder::new(docker_client);

        let image_built = image_builder
            .build_image(&PathBuf::from_str("tests/fixtures/Containerfile").unwrap())
            .await
            .unwrap();

        assert!(
            image_built
                .image_name
                .starts_with("sysdig-lsp-image-build-")
        );
        assert!(!image_built.image_id.is_empty());
    }

    #[tokio::test]
    async fn it_fails_to_build_non_existent_dockerfile() {
        let docker_client = Docker::connect_with_local_defaults().unwrap();
        let image_builder = DockerImageBuilder::new(docker_client);

        let image_built = image_builder
            .build_image(&PathBuf::from_str("tests/fixtures/Nonexistent.dockerfile").unwrap())
            .await;

        assert!(image_built.is_err());
        assert_eq!(
            image_built.err().unwrap().to_string(),
            "image builder error: internal docker client error: DockerResponseServerError { status_code: 500, message: \"Cannot locate specified Dockerfile: Nonexistent.dockerfile\" }"
        );
    }

    #[tokio::test]
    async fn it_builds_an_invalid_dockerfile_and_fails() {
        let docker_client = Docker::connect_with_local_defaults().unwrap();
        let image_builder = DockerImageBuilder::new(docker_client);

        let image_built = image_builder
            .build_image(&PathBuf::from_str("tests/fixtures/Invalid.dockerfile").unwrap())
            .await;

        assert!(image_built.is_err());
        assert!(matches!(
            image_built,
            Err(ImageBuildError::ImageBuilderError(_))
        ));
        assert_eq!(
            image_built.err().unwrap().to_string(),
            "image builder error: internal docker client error: DockerStreamError { error: \"The command '/bin/sh -c apt update # should fail, apt is not present in alpine' returned a non-zero code: 127\" }"
        );
    }
}
