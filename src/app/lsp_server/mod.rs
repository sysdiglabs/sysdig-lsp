use serde_json::Value;
use std::borrow::Cow;
use tokio::sync::RwLock;
use tower_lsp::LanguageServer;
use tower_lsp::jsonrpc::{Error, Result};
use tower_lsp::lsp_types::{
    CodeActionParams, CodeActionResponse, CodeLens, CodeLensParams, DidChangeConfigurationParams,
    DidChangeTextDocumentParams, DidOpenTextDocumentParams, ExecuteCommandParams, Hover,
    HoverParams, InitializeParams, InitializeResult, InitializedParams, Range,
};

use super::{InMemoryDocumentDatabase, LSPClient};

pub mod command_generator;
pub mod commands;
mod lsp_server_inner;
pub mod supported_commands;
use crate::app::component_factory::ComponentFactory;
use lsp_server_inner::LSPServerInner;

pub trait WithContext {
    fn with_message(self, message: impl Into<Cow<'static, str>>) -> Self;
}

impl WithContext for Error {
    fn with_message(mut self, message: impl Into<Cow<'static, str>>) -> Self {
        self.message = message.into();
        self
    }
}

pub struct LSPServer<C, F: ComponentFactory> {
    inner: RwLock<LSPServerInner<C, F>>,
}

impl<C, F: ComponentFactory> LSPServer<C, F> {
    pub fn new(client: C, component_factory: F) -> LSPServer<C, F> {
        LSPServer {
            inner: RwLock::new(LSPServerInner::new(client, component_factory)),
        }
    }
}

struct CommandInfo {
    title: String,
    command: String,
    arguments: Option<Vec<Value>>,
    range: Range,
}

#[async_trait::async_trait]
impl<C, F> LanguageServer for LSPServer<C, F>
where
    C: LSPClient + Send + Sync + 'static,
    F: ComponentFactory + Send + Sync + 'static,
{
    async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
        self.inner.write().await.initialize(params).await
    }

    async fn initialized(&self, params: InitializedParams) {
        self.inner.read().await.initialized(params).await
    }

    async fn did_change_configuration(&self, params: DidChangeConfigurationParams) {
        self.inner
            .write()
            .await
            .did_change_configuration(params)
            .await
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        self.inner.read().await.did_open(params).await
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        self.inner.read().await.did_change(params).await
    }

    async fn code_action(&self, params: CodeActionParams) -> Result<Option<CodeActionResponse>> {
        self.inner.read().await.code_action(params).await
    }

    async fn code_lens(&self, params: CodeLensParams) -> Result<Option<Vec<CodeLens>>> {
        self.inner.read().await.code_lens(params).await
    }

    async fn execute_command(&self, params: ExecuteCommandParams) -> Result<Option<Value>> {
        self.inner.read().await.execute_command(params).await
    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        self.inner.read().await.hover(params).await
    }

    async fn shutdown(&self) -> Result<()> {
        self.inner.read().await.shutdown().await
    }
}
