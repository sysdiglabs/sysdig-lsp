use std::sync::Arc;
use tokio::sync::Mutex;

use mockall::mock;
use sysdig_lsp::{
    app::{
        ImageBuildError, ImageBuildResult, ImageBuilder, ImageScanError, ImageScanner, LSPServer,
        component_factory::{ComponentFactory, ComponentFactoryError, Components, Config},
    },
    domain::scanresult::scan_result::ScanResult,
};
use tower_lsp::lsp_types::{Diagnostic, MessageType};

// --- Contenido de recorder.rs ---
#[derive(Clone)]
pub struct TestClientRecorder {
    pub messages: Arc<Mutex<Vec<(MessageType, String)>>>,
    pub diagnostics: Arc<Mutex<Vec<Vec<Diagnostic>>>>,
}

impl TestClientRecorder {
    pub fn new() -> Self {
        Self {
            messages: Arc::new(Mutex::new(Vec::new())),
            diagnostics: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait::async_trait]
impl sysdig_lsp::app::LSPClient for TestClientRecorder {
    async fn show_message<M: std::fmt::Display + Send>(
        &self,
        message_type: MessageType,
        message: M,
    ) {
        self.messages
            .lock()
            .await
            .push((message_type, message.to_string()));
    }

    async fn publish_diagnostics(
        &self,
        _url: &str,
        diagnostics: Vec<Diagnostic>,
        _version: Option<i32>,
    ) {
        self.diagnostics.lock().await.push(diagnostics);
    }
}

// --- Contenido de mocks.rs ---
mock! {
    pub ImageBuilder {}
    #[async_trait::async_trait]
    impl ImageBuilder for ImageBuilder {
        async fn build_image(&self, containerfile: &std::path::Path) -> Result<ImageBuildResult, ImageBuildError>;
    }
}

mock! {
    pub ImageScanner {}
    #[async_trait::async_trait]
    impl ImageScanner for ImageScanner {
        async fn scan_image(&self, image_pull_string: &str) -> Result<ScanResult, ImageScanError>;
    }
}

// --- Implementaciones de traits para Arc<Mutex<Mock>> ---
#[derive(Clone)]
pub struct MockImageBuilderWrapper(pub Arc<Mutex<MockImageBuilder>>);
#[derive(Clone)]
pub struct MockImageScannerWrapper(pub Arc<Mutex<MockImageScanner>>);

#[async_trait::async_trait]
impl ImageBuilder for MockImageBuilderWrapper {
    async fn build_image(
        &self,
        containerfile: &std::path::Path,
    ) -> Result<ImageBuildResult, ImageBuildError> {
        self.0.lock().await.build_image(containerfile).await
    }
}

#[async_trait::async_trait]
impl ImageScanner for MockImageScannerWrapper {
    async fn scan_image(&self, image_pull_string: &str) -> Result<ScanResult, ImageScanError> {
        self.0.lock().await.scan_image(image_pull_string).await
    }
}

// --- Estructuras de Setup ---
#[derive(Clone)]
pub struct MockComponentFactory {
    pub image_builder: Arc<Mutex<MockImageBuilder>>,
    pub image_scanner: Arc<Mutex<MockImageScanner>>,
}

impl ComponentFactory for MockComponentFactory {
    fn create_components(&self, _config: Config) -> Result<Components, ComponentFactoryError> {
        Ok(Components {
            builder: Box::new(MockImageBuilderWrapper(self.image_builder.clone())),
            scanner: Box::new(MockImageScannerWrapper(self.image_scanner.clone())),
        })
    }
}

pub struct TestSetup {
    pub server: LSPServer<TestClientRecorder, MockComponentFactory>,
    pub client_recorder: TestClientRecorder,
    pub component_factory: MockComponentFactory,
}

impl TestSetup {
    pub fn new() -> Self {
        let client_recorder = TestClientRecorder::new();
        let component_factory = MockComponentFactory {
            image_builder: Arc::new(Mutex::new(MockImageBuilder::new())),
            image_scanner: Arc::new(Mutex::new(MockImageScanner::new())),
        };
        let server = LSPServer::new(client_recorder.clone(), component_factory.clone());
        Self {
            server,
            client_recorder,
            component_factory,
        }
    }
}
