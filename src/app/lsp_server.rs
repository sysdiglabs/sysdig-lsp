use std::borrow::Cow;

use serde_json::{json, Value};
use tower_lsp::jsonrpc::{Error, ErrorCode, Result};
use tower_lsp::lsp_types::{
    CodeActionOrCommand, CodeActionParams, CodeActionProviderCapability, CodeActionResponse,
    Command, DidChangeTextDocumentParams, DidOpenTextDocumentParams, ExecuteCommandOptions,
    ExecuteCommandParams, InitializeParams, InitializeResult, InitializedParams, MessageType,
    ServerCapabilities, TextDocumentSyncCapability, TextDocumentSyncKind,
};
use tower_lsp::LanguageServer;

use super::commands::CommandExecutor;
use super::queries::QueryExecutor;
use super::{ImageScanner, InMemoryDocumentDatabase, LSPClient};

pub struct LSPServer<Client, S> {
    command_executor: CommandExecutor<Client, S>,
    query_executor: QueryExecutor,
}

impl<C, S> LSPServer<C, S> {
    pub fn new(client: C, image_scanner: S) -> LSPServer<C, S> {
        let document_database = InMemoryDocumentDatabase::default();

        LSPServer {
            command_executor: CommandExecutor::new(
                client,
                image_scanner,
                document_database.clone(),
            ),
            query_executor: QueryExecutor::new(document_database.clone()),
        }
    }
}

pub enum SupportedCommands {
    ExecuteScan,
}

impl std::fmt::Display for SupportedCommands {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ExecuteScan => "sysdig-lsp.execute-scan",
        })
    }
}

impl TryFrom<&str> for SupportedCommands {
    type Error = String;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "sysdig-lsp.execute-scan" => Ok(SupportedCommands::ExecuteScan),
            _ => Err(format!("command not supported: {}", value)),
        }
    }
}

#[async_trait::async_trait]
impl<C, S> LanguageServer for LSPServer<C, S>
where
    C: LSPClient + Send + Sync + 'static,
    S: ImageScanner + Send + Sync + 'static,
{
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
                execute_command_provider: Some(ExecuteCommandOptions {
                    commands: vec![SupportedCommands::ExecuteScan.to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            },
            ..Default::default()
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.command_executor
            .log_message(MessageType::INFO, "Sysdig LSP initialized!")
            .await;
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        self.command_executor
            .update_document_with_text(
                params.text_document.uri.as_str(),
                params.text_document.text.as_str(),
            )
            .await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        if let Some(change) = params.content_changes.into_iter().last() {
            self.command_executor
                .update_document_with_text(params.text_document.uri.as_str(), &change.text)
                .await;
        }
    }

    async fn code_action(&self, params: CodeActionParams) -> Result<Option<CodeActionResponse>> {
        let content = self
            .query_executor
            .get_document_text(params.text_document.uri.as_str())
            .await
            .ok_or(lsp_error(
                ErrorCode::InternalError,
                format!(
                    "unable to extract document content for document: {}",
                    &params.text_document.uri
                ),
            ))?;

        if let Some(line) = content.lines().nth(params.range.start.line as usize) {
            if line.starts_with("FROM ") {
                let action = Command {
                    title: "Run function".to_string(),
                    command: SupportedCommands::ExecuteScan.to_string(),
                    arguments: Some(vec![
                        json!(params.text_document.uri),
                        json!(params.range.start.line),
                    ]),
                };

                return Ok(Some(vec![CodeActionOrCommand::Command(action)]));
            }
        }

        Ok(None)
    }

    async fn execute_command(&self, params: ExecuteCommandParams) -> Result<Option<Value>> {
        let command: SupportedCommands = params.command.as_str().try_into().map_err(|e| {
            lsp_error(
                ErrorCode::InternalError,
                format!("unable to parse command: {}", e),
            )
        })?;

        match command {
            SupportedCommands::ExecuteScan => {
                if params.arguments.len() < 2 {
                    return Err(lsp_error(
                        ErrorCode::InternalError,
                        format!(
                        "error executing command '{}', invalid number of arguments: {}, expected 2",
                        command,
                        params.arguments.len()
                    ),
                    ));
                }

                let uri = params
                    .arguments
                    .first()
                    .and_then(|x| x.as_str())
                    .unwrap_or_default();
                let line = params
                    .arguments
                    .get(1)
                    .and_then(|x| x.as_u64())
                    .and_then(|x| u32::try_from(x).ok())
                    .unwrap_or_default();

                self.command_executor
                    .scan_image_from_file(uri, line)
                    .await?;
                Ok(None)
            }
        }
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}

fn lsp_error(code: ErrorCode, message: impl Into<Cow<'static, str>>) -> Error {
    Error {
        code,
        message: message.into(),
        data: None,
    }
}
