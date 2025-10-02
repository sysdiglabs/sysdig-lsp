use std::env::VarError;

use serde::Deserialize;
use thiserror::Error;
use tower_lsp::jsonrpc::{Error as LspError, ErrorCode};

use super::{ImageBuilder, ImageScanner};

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Config {
    pub sysdig: SysdigConfig,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct SysdigConfig {
    #[serde(alias = "apiUrl")]
    pub api_url: String,
    #[serde(alias = "apiToken")]
    pub api_token: Option<String>,
}

pub struct Components {
    pub scanner: Box<dyn ImageScanner + Send + Sync>,
    pub builder: Box<dyn ImageBuilder + Send + Sync>,
}

pub trait ComponentFactory: Send + Sync {
    fn create_components(&self, config: Config) -> Result<Components, ComponentFactoryError>;
}

#[derive(Error, Debug)]
pub enum ComponentFactoryError {
    #[error("unable to retrieve sysdig api token from env var: {0}")]
    UnableToRetrieveAPITokenFromEnvVar(#[from] VarError),

    #[error("docker client error: {0:?}")]
    DockerClientError(String),
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
