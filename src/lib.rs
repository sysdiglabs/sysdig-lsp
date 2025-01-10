use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp::jsonrpc::{Error, Result};
use tower_lsp::lsp_types::{
    CodeAction, CodeActionKind, CodeActionOrCommand, CodeActionParams,
    CodeActionProviderCapability, CodeActionResponse, Diagnostic, DiagnosticSeverity,
    DidChangeTextDocumentParams, DidOpenTextDocumentParams, InitializeParams, InitializeResult,
    InitializedParams, MessageType, Position, Range, ServerCapabilities,
    TextDocumentSyncCapability, TextDocumentSyncKind, TextEdit, Url, WorkspaceEdit,
};
use tower_lsp::Client;

pub struct LSP {
    client: Client,
    documents: Arc<RwLock<HashMap<String, String>>>,
}

impl LSP {
    pub fn new(client: Client) -> LSP {
        LSP {
            client,
            documents: Default::default(),
        }
    }
}

#[async_trait::async_trait]
impl tower_lsp::LanguageServer for LSP {
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

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        self.update_document_text(
            params.text_document.uri.as_str(),
            &params.text_document.text,
        )
        .await;
        self.check_for_errors(&params.text_document.uri, &params.text_document.text)
            .await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        if let Some(change) = params.content_changes.into_iter().last() {
            self.update_document_text(params.text_document.uri.as_str(), &change.text)
                .await;

            self.check_for_errors(&params.text_document.uri, &change.text)
                .await;
        }
    }

    async fn code_action(&self, params: CodeActionParams) -> Result<Option<CodeActionResponse>> {
        let content = self
            .get_document_text(&params.text_document.uri)
            .await
            .ok_or(Error::internal_error())?;

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

impl LSP {
    async fn update_document_text<'a, 'b>(
        &self,
        document: impl Into<Cow<'a, str>>,
        text: impl Into<Cow<'b, str>>,
    ) {
        self.documents
            .write()
            .await
            .insert(document.into().into_owned(), text.into().into_owned());
    }

    async fn get_document_text<D: AsRef<str>>(&self, document: D) -> Option<String> {
        self.documents
            .read()
            .await
            .get(document.as_ref())
            .map(String::to_owned)
    }

    async fn check_for_errors(&self, uri: &Url, content: &str) {
        let mut diagnostics = Vec::new();

        for (line_index, line) in content.lines().enumerate() {
            let Some(start) = line.find("FROM") else {
                continue;
            };
            let range = Range {
                start: Position::new(line_index as u32, start as u32),
                end: Position::new(line_index as u32, (start + 4) as u32),
            };

            let diagnostic = Diagnostic {
                range,
                severity: Some(DiagnosticSeverity::WARNING),
                source: Some("sysdig-lsp".to_string()),
                message: "Vulnerabilities found: 5 Critical, 10 High, 12 Low, 50 Negligible"
                    .to_string(),
                ..Default::default()
            };

            diagnostics.push(diagnostic);
        }

        // Enviamos los diagnósticos al cliente
        self.client
            .publish_diagnostics(uri.clone(), diagnostics, None)
            .await;
    }
}
