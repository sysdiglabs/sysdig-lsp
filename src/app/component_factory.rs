use std::env::VarError;

use bollard::Docker;
use serde::Deserialize;
use thiserror::Error;
use tower_lsp::jsonrpc::{Error as LspError, ErrorCode};

use crate::infra::{DockerImageBuilder, SysdigAPIToken, SysdigImageScanner};

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Config {
    sysdig: SysdigConfig,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct SysdigConfig {
    api_url: String,
    api_token: Option<SysdigAPIToken>,
}

#[derive(Clone)]
pub struct ComponentFactory {
    scanner: SysdigImageScanner,
    builder: DockerImageBuilder,
}

#[derive(Error, Debug)]
pub enum ComponentFactoryError {
    #[error("unable to retrieve sysdig api token from env var: {0}")]
    UnableToRetrieveAPITokenFromEnvVar(#[from] VarError),

    #[error("docker client error: {0:?}")]
    DockerClientError(#[from] bollard::errors::Error),
}

impl ComponentFactory {
    pub fn new(config: Config) -> Result<Self, ComponentFactoryError> {
        let token = config
            .sysdig
            .api_token
            .clone()
            .map(Ok)
            .unwrap_or_else(|| std::env::var("SECURE_API_TOKEN").map(SysdigAPIToken))?;

        let scanner = SysdigImageScanner::new(config.sysdig.api_url.clone(), token);

        let docker_client = Docker::connect_with_local_defaults()?;
        let builder = DockerImageBuilder::new(docker_client);

        Ok(Self { scanner, builder })
    }

    pub fn image_scanner(&self) -> &SysdigImageScanner {
        &self.scanner
    }

    pub fn image_builder(&self) -> &DockerImageBuilder {
        &self.builder
    }
}

impl From<ComponentFactoryError> for LspError {
    fn from(err: ComponentFactoryError) -> Self {
        let (code, message) = match err {
            ComponentFactoryError::UnableToRetrieveAPITokenFromEnvVar(e) => (
                ErrorCode::InternalError,
                format!("Could not read SECURE_API_TOKEN from environment: {}", e),
            ),
            ComponentFactoryError::DockerClientError(e) => (
                ErrorCode::InternalError,
                format!("Failed to connect to Docker: {}", e),
            ),
        };
        LspError {
            code,
            message: message.into(),
            data: None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::{ComponentFactory, Config};

    #[test]
    fn it_creates_a_factory() {
        let factory = ComponentFactory::new(Config::default());
        assert!(factory.is_ok());
    }
}
