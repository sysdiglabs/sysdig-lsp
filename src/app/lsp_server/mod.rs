use serde_json::Value;
use std::borrow::Cow;
use tokio::sync::RwLock;
use tower_lsp::LanguageServer;
use tower_lsp::jsonrpc::{Error, Result};
use tower_lsp::lsp_types::{
    CodeActionParams, CodeActionResponse, CodeLens, CodeLensParams, DidChangeConfigurationParams,
    DidChangeTextDocumentParams, DidOpenTextDocumentParams, ExecuteCommandParams, InitializeParams,
    InitializeResult, InitializedParams, Range,
};

use super::{InMemoryDocumentDatabase, LSPClient};

pub mod command_generator;
mod lsp_server_inner;
pub mod supported_commands;
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

pub struct LSPServer<C> {
    inner: RwLock<LSPServerInner<C>>,
}

impl<C> LSPServer<C> {
    pub fn new(client: C) -> LSPServer<C> {
        LSPServer {
            inner: RwLock::new(LSPServerInner::new(client)),
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
impl<C> LanguageServer for LSPServer<C>
where
    C: LSPClient + Send + Sync + 'static,
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
        self.inner.write().await.execute_command(params).await
    }

    async fn shutdown(&self) -> Result<()> {
        self.inner.read().await.shutdown().await
    }
}
