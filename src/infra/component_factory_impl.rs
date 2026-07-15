use std::sync::Arc;

use tokio::sync::Mutex;

use crate::{
    app::component_factory::{ComponentFactory, ComponentFactoryError, Components, Config},
    infra::{
        DockerImageBuilder, SysdigAPIToken, SysdigImageScanner, connect_to_docker,
        scanner_binary_manager::ScannerBinaryManager, sysdig_iac_scanner::SysdigIacScanner,
    },
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

        // Both scanners share the same binary manager so the CLI binary is installed only once
        let scanner_binary_manager = Arc::new(Mutex::new(ScannerBinaryManager::default()));

        // Create scanner WITH the docker_host so CLI subprocess uses the same socket
        let scanner = SysdigImageScanner::with_docker_host(
            config.sysdig.api_url.clone(),
            token.clone(),
            docker_connection.socket_path.clone(),
            scanner_binary_manager.clone(),
        );

        // Create builder with the Docker client
        let builder = DockerImageBuilder::new(docker_connection.client);

        let iac_scanner =
            SysdigIacScanner::new(config.sysdig.api_url.clone(), token, scanner_binary_manager);

        Ok(Components {
            scanner: Box::new(scanner),
            builder: Box::new(builder),
            iac_scanner: Box::new(iac_scanner),
        })
    }
}
