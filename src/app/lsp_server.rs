use std::borrow::Cow;

use serde_json::{json, Value};
use tower_lsp::jsonrpc::{Error, ErrorCode, Result};
use tower_lsp::lsp_types::{
    CodeActionOrCommand, CodeActionParams, CodeActionProviderCapability, CodeActionResponse,
    Command, Diagnostic, DiagnosticSeverity, DidChangeTextDocumentParams,
    DidOpenTextDocumentParams, ExecuteCommandOptions, ExecuteCommandParams, InitializeParams,
    InitializeResult, InitializedParams, MessageType, Position, Range, ServerCapabilities,
    TextDocumentSyncCapability, TextDocumentSyncKind, Url,
};

use super::{Document, DocumentDatabase, LSPClient};

pub struct LSPServer<Client> {
    client: Client,
    documents: DocumentDatabase,
}

impl<C> LSPServer<C> {
    pub fn new(client: C) -> LSPServer<C> {
        LSPServer {
            client,
            documents: Default::default(),
        }
    }
}

const COMMAND_EXECUTE_SCAN: &str = "sysdig-lsp.execute-scan";

#[async_trait::async_trait]
impl<C> tower_lsp::LanguageServer for LSPServer<C>
where
    C: Send + Sync + 'static,
    C: LSPClient,
{
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
                execute_command_provider: Some(ExecuteCommandOptions {
                    commands: vec![COMMAND_EXECUTE_SCAN.to_string()],
                    ..Default::default()
                }),
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

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        self.update_document_text(
            params.text_document.uri.as_str(),
            &params.text_document.text,
        )
        .await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        if let Some(change) = params.content_changes.into_iter().last() {
            let uri = params.text_document.uri.as_str();
            self.documents.remove_document(uri).await;
            self.update_document_text(uri, &change.text).await;
            let _ = self.publish_all_diagnostics().await;
        }
    }

    async fn code_action(&self, params: CodeActionParams) -> Result<Option<CodeActionResponse>> {
        let content = self
            .get_document_text(&params.text_document.uri)
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
                    command: COMMAND_EXECUTE_SCAN.to_string(),
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
        let command = params.command.as_str();
        match command {
            COMMAND_EXECUTE_SCAN => {
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

                self.scan_image_from_file(uri, line).await?;
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}

impl<C> LSPServer<C> {
    async fn update_document_text<'a, 'b>(
        &self,
        document: impl Into<Cow<'a, str>>,
        text: impl Into<Cow<'b, str>>,
    ) {
        self.documents
            .add_document(
                document.into().into_owned(),
                Document {
                    text: text.into().into_owned(),
                    ..Default::default()
                },
            )
            .await;
    }

    async fn get_document_text<D: AsRef<str>>(&self, document: D) -> Option<String> {
        self.documents
            .read_document(document.as_ref())
            .await
            .map(|d| d.text)
    }
}

impl<C> LSPServer<C>
where
    C: LSPClient,
{
    async fn publish_all_diagnostics(&self) -> Result<()> {
        let all_diagnostics = self.documents.all_diagnostics().await;
        for (uri, diagnostics) in all_diagnostics {
            let url = Url::parse(&uri).map_err(|_| {
                lsp_error(
                    ErrorCode::InternalError,
                    format!("unable to parse uri ({}) when publishing diagnostics", &uri),
                )
            })?;
            self.client
                .publish_diagnostics(url, diagnostics, None)
                .await;
        }
        Ok(())
    }

    async fn scan_image_from_file(&self, uri: &str, line: u32) -> Result<()> {
        let document = self.documents.read_document(uri).await.ok_or(lsp_error(
            ErrorCode::InternalError,
            "unable to obtain document to scan",
        ))?;

        let image_for_selected_line =
            self.image_from_line(line, &document.text).ok_or(lsp_error(
                ErrorCode::ParseError,
                format!("unable to retrieve image for the selected line: {}", line),
            ))?;

        let diagnostic = Diagnostic {
            range: Range {
                start: Position::new(line, 0),
                end: Position::new(line, u32::MAX),
            },
            severity: Some(DiagnosticSeverity::WARNING),
            message: format!("Vulnerabilities for {}: 1 Critical, 2 High, 6 Medium, 10 Low, 50 Negligible. At least, lol", image_for_selected_line),
            ..Default::default()
        };

        self.documents.remove_diagnostics(uri).await;
        self.documents.add_diagnostics(uri, &[diagnostic]).await;
        self.publish_all_diagnostics().await
    }

    fn image_from_line<'a>(&self, line: u32, contents: &'a str) -> Option<&'a str> {
        let line_number: usize = line.try_into().ok()?;
        let line_that_contains_from = contents.lines().nth(line_number)?;
        let image = line_that_contains_from
            .strip_prefix("FROM ")?
            .split_whitespace()
            .next();

        image
    }
}

fn lsp_error(code: ErrorCode, message: impl Into<Cow<'static, str>>) -> Error {
    Error {
        code,
        message: message.into(),
        data: None,
    }
}
