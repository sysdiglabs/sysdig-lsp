use std::env::VarError;

use serde::Deserialize;
use thiserror::Error;

use crate::infra::{SysdigAPIToken, SysdigImageScanner};

use super::ImageScanner;

#[derive(Clone, Default, Deserialize)]
pub struct Config {
    sysdig: SysdigConfig,
}

#[derive(Clone, Default, Deserialize)]
pub struct SysdigConfig {
    api_url: String,
    api_token: Option<String>,
}

#[derive(Clone)]
pub struct ComponentFactory {
    config: Option<Config>,

    scanner: Option<SysdigImageScanner>,
}

#[derive(Error, Debug)]
pub enum ComponentFactoryError {
    #[error("the configuration has not been provided")]
    ConfigurationNotProvided,

    #[error("unable to retrieve sysdig api token from env var: {0}")]
    UnableToRetrieveAPITokenFromEnvVar(#[from] VarError),
}

impl ComponentFactory {
    pub fn uninit() -> Self {
        Self {
            config: None,
            scanner: None,
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.config.is_some()
    }

    pub fn initialize_with(&mut self, config: Config) {
        self.config.replace(config);
        self.scanner.take();
    }

    pub fn image_scanner(&mut self) -> Result<&mut impl ImageScanner, ComponentFactoryError> {
        if self.scanner.is_some() {
            return Ok(self.scanner.as_mut().unwrap());
        }

        let Some(config) = self.config.clone() else {
            return Err(ComponentFactoryError::ConfigurationNotProvided);
        };

        let token = config
            .sysdig
            .api_token
            .map(Ok)
            .unwrap_or_else(|| std::env::var("SECURE_API_TOKEN"))?;

        self.scanner.replace(SysdigImageScanner::new(
            config.sysdig.api_url,
            SysdigAPIToken(token),
        ));

        Ok(self.scanner.as_mut().unwrap())
    }
}

#[cfg(test)]
mod test {
    use super::{ComponentFactory, Config};

    #[test]
    fn it_loads_the_factory_uninit() {
        let factory = ComponentFactory::uninit();

        assert!(!factory.is_initialized());
    }

    #[test]
    fn it_creates_a_scanner_with_the_provided_config() {
        let mut factory = ComponentFactory::uninit();

        factory.initialize_with(Config::default());

        assert!(factory.is_initialized());
    }
}
