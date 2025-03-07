use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Arc;

use sysdig_lsp::app::{LSPClient, LSPServer};
use tokio::sync::Mutex;
use tower_lsp::lsp_types::{
    CodeActionOrCommand, CodeActionParams, Diagnostic, DidOpenTextDocumentParams,
    ExecuteCommandParams, InitializeParams, InitializeResult, InitializedParams, MessageType,
    Position, Range, TextDocumentIdentifier, TextDocumentItem, Url,
};
use tower_lsp::LanguageServer;

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
                    "unable to send code action for filename {} in line number {}",
                    filename, line_number
                )
            })
    }

    pub async fn execute_action(&mut self, action: &str, args: &[serde_json::Value]) {
        self.server
            .execute_command(ExecuteCommandParams {
                command: action.to_string(),
                arguments: args.to_vec(),
                work_done_progress_params: Default::default(),
            })
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "unable to execute action {} with args {}",
                    action,
                    serde_json::to_string_pretty(args).unwrap()
                )
            });
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
    logged_messages: Arc<Mutex<Vec<(MessageType, String)>>>,
    diagnostics_for_each_file: Arc<Mutex<HashMap<String, Vec<Diagnostic>>>>,
}

#[async_trait::async_trait]
impl LSPClient for TestClientRecorder {
    async fn log_message<M: Display + Send>(&self, message_type: MessageType, message: M) {
        self.logged_messages
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
    pub async fn diagnostics_displayed_for_file(&self, filename: &str) -> Option<Vec<Diagnostic>> {
        self.diagnostics_for_each_file
            .lock()
            .await
            .get(filename)
            .cloned()
    }
    pub async fn received_log_messages(&self) -> Vec<(MessageType, String)> {
        self.logged_messages.lock().await.clone()
    }
}
