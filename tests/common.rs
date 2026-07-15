use std::sync::Arc;
use tokio::sync::Mutex;

use mockall::mock;
use sysdig_lsp::{
    app::{
        IacScanError, IacScanScope, IacScanner, ImageBuildError, ImageBuildResult, ImageBuilder,
        ImageScanError, ImageScanner, LSPServer,
        component_factory::{ComponentFactory, ComponentFactoryError, Components, Config},
    },
    domain::{iacscanresult::iac_scan_result::IacScanResult, scanresult::scan_result::ScanResult},
};
use tower_lsp::lsp_types::{Diagnostic, MessageType};

// --- Contenido de recorder.rs ---
pub type PublishedDiagnostics = Vec<(String, Vec<Diagnostic>)>;

#[derive(Clone)]
pub struct TestClientRecorder {
    pub messages: Arc<Mutex<Vec<(MessageType, String)>>>,
    pub diagnostics: Arc<Mutex<PublishedDiagnostics>>,
}

impl TestClientRecorder {
    pub fn new() -> Self {
        Self {
            messages: Arc::new(Mutex::new(Vec::new())),
            diagnostics: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl Default for TestClientRecorder {
    fn default() -> Self {
        Self::new()
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
        url: &str,
        diagnostics: Vec<Diagnostic>,
        _version: Option<i32>,
    ) {
        self.diagnostics
            .lock()
            .await
            .push((url.to_string(), diagnostics));
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

mock! {
    pub IacScanner {}
    #[async_trait::async_trait]
    impl IacScanner for IacScanner {
        async fn scan_iac(&self, scope: &IacScanScope) -> Result<IacScanResult, IacScanError>;
    }
}

// --- Implementaciones de traits para Arc<Mutex<Mock>> ---
#[derive(Clone)]
pub struct MockImageBuilderWrapper(pub Arc<Mutex<MockImageBuilder>>);
#[derive(Clone)]
pub struct MockImageScannerWrapper(pub Arc<Mutex<MockImageScanner>>);
#[derive(Clone)]
pub struct MockIacScannerWrapper(pub Arc<Mutex<MockIacScanner>>);

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

#[async_trait::async_trait]
impl IacScanner for MockIacScannerWrapper {
    async fn scan_iac(&self, scope: &IacScanScope) -> Result<IacScanResult, IacScanError> {
        self.0.lock().await.scan_iac(scope).await
    }
}

// --- Estructuras de Setup ---
#[derive(Clone)]
pub struct MockComponentFactory {
    pub image_builder: Arc<Mutex<MockImageBuilder>>,
    pub image_scanner: Arc<Mutex<MockImageScanner>>,
    pub iac_scanner: Arc<Mutex<MockIacScanner>>,
}

impl ComponentFactory for MockComponentFactory {
    fn create_components(&self, _config: Config) -> Result<Components, ComponentFactoryError> {
        Ok(Components {
            builder: Box::new(MockImageBuilderWrapper(self.image_builder.clone())),
            scanner: Box::new(MockImageScannerWrapper(self.image_scanner.clone())),
            iac_scanner: Box::new(MockIacScannerWrapper(self.iac_scanner.clone())),
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
            iac_scanner: Arc::new(Mutex::new(MockIacScanner::new())),
        };
        let server = LSPServer::new(client_recorder.clone(), component_factory.clone());
        Self {
            server,
            client_recorder,
            component_factory,
        }
    }
}

impl Default for TestSetup {
    fn default() -> Self {
        Self::new()
    }
}
