use std::env::VarError;

use bollard::Docker;
use serde::Deserialize;
use thiserror::Error;

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

#[derive(Clone, Default)]
pub struct ComponentFactory {
    config: Option<Config>,

    scanner: Option<SysdigImageScanner>,
    builder: Option<DockerImageBuilder>,
}

#[derive(Error, Debug)]
pub enum ComponentFactoryError {
    #[error("the configuration has not been provided")]
    ConfigurationNotProvided,

    #[error("unable to retrieve sysdig api token from env var: {0}")]
    UnableToRetrieveAPITokenFromEnvVar(#[from] VarError),

    #[error("docker client error: {0:?}")]
    DockerClientError(#[from] bollard::errors::Error),
}

impl ComponentFactory {
    pub fn initialize_with(&mut self, config: Config) {
        self.config.replace(config);
        self.scanner.take();
    }

    pub fn image_scanner(&mut self) -> Result<SysdigImageScanner, ComponentFactoryError> {
        if self.scanner.is_some() {
            return Ok(self.scanner.clone().unwrap());
        }

        let Some(config) = &self.config else {
            return Err(ComponentFactoryError::ConfigurationNotProvided);
        };

        let token = config
            .sysdig
            .api_token
            .clone()
            .map(Ok)
            .unwrap_or_else(|| std::env::var("SECURE_API_TOKEN").map(SysdigAPIToken))?;

        let image_scanner = SysdigImageScanner::new(config.sysdig.api_url.clone(), token);

        self.scanner.replace(image_scanner);
        Ok(self.scanner.clone().unwrap())
    }

    pub fn image_builder(&mut self) -> Result<DockerImageBuilder, ComponentFactoryError> {
        if self.builder.is_some() {
            return Ok(self.builder.clone().unwrap());
        }

        let docker_client = Docker::connect_with_local_defaults()?;
        let image_builder = DockerImageBuilder::new(docker_client);

        self.builder.replace(image_builder);
        Ok(self.builder.clone().unwrap())
    }
}

#[cfg(test)]
mod test {
    use super::{ComponentFactory, Config};

    #[test]
    fn it_loads_the_factory_uninit() {
        let factory = ComponentFactory::default();

        assert!(factory.config.is_none());
    }

    #[test]
    fn it_fails_to_create_the_scanner_without_config() {
        let mut factory = ComponentFactory::default();

        assert!(factory.image_scanner().is_err());
    }

    #[test]
    fn it_creates_a_scanner_after_initializing() {
        let mut factory = ComponentFactory::default();

        factory.initialize_with(Config::default());

        assert!(factory.image_scanner().is_ok());
    }

    #[test]
    fn it_creates_a_builder_without_config() {
        let mut factory = ComponentFactory::default();

        assert!(factory.image_builder().is_ok());
    }
}
