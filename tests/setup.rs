use std::sync::Arc;

use sysdig_lsp::{LSPClient, LSP};
use tokio::sync::Mutex;
use tower_lsp::lsp_types::{
    Diagnostic, DidOpenTextDocumentParams, InitializeParams, InitializeResult, InitializedParams,
    MessageType, TextDocumentItem, Url,
};
use tower_lsp::LanguageServer;

pub struct Client {
    server: LSP<InnerClient>,
    inner_client: InnerClient,
}

impl Client {
    pub fn inner_client(&self) -> &InnerClient {
        &self.inner_client
    }

    pub async fn initialize_lsp(&mut self) -> InitializeResult {
        let result = self
            .server
            .initialize(InitializeParams::default())
            .await
            .expect("initialize failed");

        self.server.initialized(InitializedParams {}).await;

        result
    }

    pub async fn open_file_with_contents(&mut self, filename: &str, contents: &str) {
        self.server
            .did_open(DidOpenTextDocumentParams {
                text_document: TextDocumentItem {
                    uri: Url::parse(&("file://".to_owned() + filename)).unwrap(),
                    text: contents.to_string(),
                    language_id: "".to_owned(), // unused
                    version: 0,                 // unused
                },
            })
            .await;
    }
}

#[derive(Default, Clone)]
pub struct InnerClient {
    logged_messages: Arc<Mutex<Vec<(MessageType, String)>>>,
    diagnostics: Arc<Mutex<Vec<Diagnostic>>>,
}

#[async_trait::async_trait]
impl LSPClient for InnerClient {
    async fn log_message(&self, message_type: MessageType, message: &str) {
        self.logged_messages
            .lock()
            .await
            .push((message_type, message.to_owned()));
    }

    async fn publish_diagnostics(
        &self,
        _url: Url,
        mut diagnostics: Vec<Diagnostic>,
        _other: Option<i32>,
    ) {
        self.diagnostics.lock().await.append(&mut diagnostics);
    }
}

impl InnerClient {
    pub async fn received_diagnostics(&self) -> Vec<Diagnostic> {
        self.diagnostics.lock().await.clone()
    }
    pub async fn received_log_messages(&self) -> Vec<(MessageType, String)> {
        self.logged_messages.lock().await.clone()
    }
}

pub fn new_lsp_client() -> Client {
    let inner_client = InnerClient::default();
    let server = LSP::new(inner_client.clone());

    let client = Client {
        server,
        inner_client,
    };

    client
}
