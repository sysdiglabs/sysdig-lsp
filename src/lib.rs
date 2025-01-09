use std::io;
use std::path::Path;

use tower_lsp::jsonrpc::{Error, Result};
use tower_lsp::lsp_types::{
    CodeAction, CodeActionKind, CodeActionOrCommand, CodeActionParams,
    CodeActionProviderCapability, CodeActionResponse, InitializeParams, InitializeResult,
    InitializedParams, MessageType, Position, ServerCapabilities, TextDocumentSyncCapability,
    TextDocumentSyncKind, TextEdit, WorkspaceEdit,
};
use tower_lsp::Client;

pub struct LSP<F> {
    client: Client,
    filesystem: F,
}

#[async_trait::async_trait]
pub trait Filesystem {
    async fn read_file<A: AsRef<Path> + Send>(&self, path: A) -> io::Result<String>;
}

#[async_trait::async_trait]
impl Filesystem for std::path::PathBuf {
    async fn read_file<A: AsRef<Path> + Send>(&self, path: A) -> io::Result<String> {
        tokio::fs::read_to_string(self.join(path)).await
    }
}

impl<F> LSP<F> {
    pub fn new(client: Client, filesystem: F) -> LSP<F> {
        LSP { client, filesystem }
    }
}

#[async_trait::async_trait]
impl<F> tower_lsp::LanguageServer for LSP<F>
where
    F: Send + Sync + 'static,
    F: Filesystem,
{
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
                ..Default::default()
            },
            ..Default::default()
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "Sysdig LSP initialized!")
            .await;
    }

    async fn code_action(&self, params: CodeActionParams) -> Result<Option<CodeActionResponse>> {
        let file_path = params
            .text_document
            .uri
            .to_file_path()
            .or(Err(Error::internal_error()))?;

        let content = self
            .filesystem
            .read_file(file_path)
            .await
            .or(Err(Error::internal_error()))?;

        // Check if the range contains "FROM alpine"
        if let Some(line) = content.lines().nth(params.range.start.line as usize) {
            if line.starts_with("FROM ") {
                let action = CodeAction {
                    title: "Replace with 'ubuntu'".to_string(),
                    kind: Some(CodeActionKind::QUICKFIX),
                    edit: Some(WorkspaceEdit {
                        changes: Some(
                            vec![(
                                params.text_document.uri.clone(),
                                vec![TextEdit {
                                    range: tower_lsp::lsp_types::Range {
                                        start: Position::new(params.range.start.line, 0),
                                        end: Position::new(params.range.start.line, u32::MAX),
                                    },
                                    new_text: "FROM ubuntu".to_owned(),
                                }],
                            )]
                            .into_iter()
                            .collect(),
                        ),
                        ..Default::default()
                    }),
                    ..Default::default()
                };

                return Ok(Some(vec![CodeActionOrCommand::CodeAction(action)]));
            }
        }

        Ok(None)
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}
