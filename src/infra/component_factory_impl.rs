use bollard::Docker;

use crate::{
    app::component_factory::{ComponentFactory, ComponentFactoryError, Components, Config},
    infra::{DockerImageBuilder, SysdigAPIToken, SysdigImageScanner},
};

pub struct ConcreteComponentFactory;

impl ComponentFactory for ConcreteComponentFactory {
    fn create_components(&self, config: Config) -> Result<Components, ComponentFactoryError> {
        let token = config
            .sysdig
            .api_token
            .clone()
            .map(Ok)
            .unwrap_or_else(|| std::env::var("SECURE_API_TOKEN"))
            .map(SysdigAPIToken)?;

        let scanner = SysdigImageScanner::new(config.sysdig.api_url.clone(), token);

        let docker_client = Docker::connect_with_local_defaults()
            .map_err(|e| ComponentFactoryError::DockerClientError(e.to_string()))?;
        let builder = DockerImageBuilder::new(docker_client);

        Ok(Components {
            scanner: Box::new(scanner),
            builder: Box::new(builder),
        })
    }
}
