use std::sync::Arc;

use tokio::sync::RwLock;

#[derive(Clone, Default)]
pub struct Config {}

#[derive(Clone)]
pub struct ComponentFactory {
    config: Arc<RwLock<Option<Config>>>,
}

impl ComponentFactory {
    pub fn uninit() -> Self {
        Self {
            config: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn is_initialized(&self) -> bool {
        self.config.read().await.is_some()
    }

    pub async fn initialize_with(&self, config: Config) {
        self.config.write().await.replace(config);
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
        let factory = ComponentFactory::uninit();

        factory.initialize_with(Config::default()).await;

        assert!(factory.is_initialized().await);
    }
}
