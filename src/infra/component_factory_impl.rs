use crate::{
    app::component_factory::{ComponentFactory, ComponentFactoryError, Components, Config},
    infra::{DockerImageBuilder, SysdigAPIToken, SysdigImageScanner, connect_to_docker},
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

        // Get Docker connection with socket path
        let docker_connection = connect_to_docker()
            .map_err(|e| ComponentFactoryError::DockerClientError(e.to_string()))?;

        // Create scanner WITH the docker_host so CLI subprocess uses the same socket
        let scanner = SysdigImageScanner::with_docker_host(
            config.sysdig.api_url.clone(),
            token,
            docker_connection.socket_path.clone(),
        );

        // Create builder with the Docker client
        let builder = DockerImageBuilder::new(docker_connection.client);

        Ok(Components {
            scanner: Box::new(scanner),
            builder: Box::new(builder),
        })
    }
}
