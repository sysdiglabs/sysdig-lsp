use std::{env::VarError, sync::Arc};

use serde::Deserialize;
use thiserror::Error;
use tokio::sync::{OwnedRwLockReadGuard, RwLock};

use crate::infra::{SysdigAPIToken, SysdigImageScanner};

use super::ImageScanner;

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
    config: Option<Config>,

    scanner: Arc<RwLock<Option<SysdigImageScanner>>>,
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
            scanner: Default::default(),
        }
    }

    pub async fn is_initialized(&self) -> bool {
        self.config.is_some()
    }

    pub async fn initialize_with(&mut self, config: Config) {
        self.config.replace(config);
        self.scanner.write().await.take();
    }

    pub async fn image_scanner(
        &self,
    ) -> Result<OwnedRwLockReadGuard<Option<impl ImageScanner>>, ComponentFactoryError> {
        {
            let scanner = self.scanner.clone().read_owned().await;
            if scanner.is_some() {
                return Ok(scanner);
            }
        };

        let Some(config) = self.config.clone() else {
            return Err(ComponentFactoryError::ConfigurationNotProvided);
        };

        let token = config
            .sysdig
            .api_token
            .map(Ok)
            .unwrap_or_else(|| std::env::var("SECURE_API_TOKEN").map(SysdigAPIToken))?;

        self.scanner
            .write()
            .await
            .replace(SysdigImageScanner::new(config.sysdig.api_url, token));

        Ok(self.scanner.clone().read_owned().await)
    }
}

#[cfg(test)]
mod test {
    use super::{ComponentFactory, Config};

    #[tokio::test]
    async fn it_loads_the_factory_uninit() {
        let factory = ComponentFactory::uninit();

        assert!(!factory.is_initialized().await);
    }

    #[tokio::test]
    async fn it_creates_a_scanner_with_the_provided_config() {
        let mut factory = ComponentFactory::uninit();

        factory.initialize_with(Config::default()).await;

        assert!(factory.is_initialized().await);
    }
}
