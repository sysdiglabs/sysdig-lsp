use core::panic;
use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Arc;

use serde_json::json;
use sysdig_lsp::app::{LSPClient, LSPServer};
use tokio::sync::Mutex;
use tower_lsp::LanguageServer;
use tower_lsp::lsp_types::{
    CodeActionOrCommand, CodeActionParams, CodeLens, CodeLensParams, Diagnostic,
    DidOpenTextDocumentParams, InitializeParams, InitializeResult, InitializedParams, MessageType,
    Position, Range, TextDocumentIdentifier, TextDocumentItem, Url,
};

pub struct TestClient {
    server: LSPServer<TestClientRecorder>,
    recorder: TestClientRecorder,
}

impl TestClient {
    pub fn new() -> TestClient {
        let recorder = TestClientRecorder::default();
        let server = LSPServer::new(recorder.clone());
        TestClient { server, recorder }
    }

    pub async fn new_initialized() -> TestClient {
        let mut client = Self::new();
        client.initialize_lsp().await;
        client
    }

    pub fn recorder(&self) -> &TestClientRecorder {
        &self.recorder
    }

    pub async fn initialize_lsp(&mut self) -> InitializeResult {
        let result = self
            .server
            .initialize(InitializeParams {
                initialization_options: Some(json!({"sysdig":
                    {
                        "api_url": "some_api_url"
                    }
                })),
                ..Default::default()
            })
            .await
            .expect("initialize failed");

        self.server.initialized(InitializedParams {}).await;

        result
    }

    pub async fn open_file_with_contents(&mut self, filename: &str, contents: &str) {
        self.server
            .did_open(DidOpenTextDocumentParams {
                text_document: TextDocumentItem {
                    uri: url_from(filename),
                    text: contents.to_string(),
                    language_id: "".to_owned(), // unused
                    version: 0,                 // unused
                },
            })
            .await;
    }

    pub async fn request_available_actions_in_line(
        &mut self,
        filename: &str,
        line_number: u32,
    ) -> Option<Vec<CodeActionOrCommand>> {
        self.server
            .code_action(CodeActionParams {
                text_document: TextDocumentIdentifier::new(url_from(filename)),
                range: Range {
                    start: Position::new(line_number, 0),
                    end: Position::new(line_number, 0),
                },
                context: Default::default(),
                work_done_progress_params: Default::default(),
                partial_result_params: Default::default(),
            })
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "unable to send code action for filename {filename} in line number {line_number}",
                )
            })
    }

    pub async fn request_available_code_lens_in_file(
        &mut self,
        filename: &str,
    ) -> Option<Vec<CodeLens>> {
        self.server
            .code_lens(CodeLensParams {
                text_document: TextDocumentIdentifier::new(url_from(filename)),
                work_done_progress_params: Default::default(),
                partial_result_params: Default::default(),
            })
            .await
            .unwrap_or_else(|_| panic!("unable to send code lens for filename {filename}"))
    }
}

fn url_from(filename: &str) -> Url {
    Url::parse(&format!("file://{}", filename)).expect("unable to convert filename &str to Url")
}

impl Default for TestClient {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default, Clone)]
pub struct TestClientRecorder {
    messages_shown: Arc<Mutex<Vec<(MessageType, String)>>>,
    diagnostics_for_each_file: Arc<Mutex<HashMap<String, Vec<Diagnostic>>>>,
}

#[async_trait::async_trait]
impl LSPClient for TestClientRecorder {
    async fn show_message<M: Display + Send>(&self, message_type: MessageType, message: M) {
        self.messages_shown
            .lock()
            .await
            .push((message_type, message.to_string()));
    }

    async fn publish_diagnostics(
        &self,
        url: &str,
        diagnostics: Vec<Diagnostic>,
        _other: Option<i32>,
    ) {
        self.diagnostics_for_each_file
            .lock()
            .await
            .insert(url.to_string(), diagnostics);
    }
}

impl TestClientRecorder {
    pub async fn messages_shown(&self) -> Vec<(MessageType, String)> {
        self.messages_shown.lock().await.clone()
    }
}
