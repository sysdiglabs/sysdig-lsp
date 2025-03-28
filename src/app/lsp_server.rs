use std::borrow::Cow;

use serde_json::{Value, json};
use tokio::sync::RwLock;
use tower_lsp::LanguageServer;
use tower_lsp::jsonrpc::{Error, ErrorCode, Result};
use tower_lsp::lsp_types::{
    CodeActionOrCommand, CodeActionParams, CodeActionProviderCapability, CodeActionResponse,
    CodeLens, CodeLensOptions, CodeLensParams, Command, DidChangeConfigurationParams,
    DidChangeTextDocumentParams, DidOpenTextDocumentParams, ExecuteCommandOptions,
    ExecuteCommandParams, InitializeParams, InitializeResult, InitializedParams, MessageType,
    Position, Range, ServerCapabilities, TextDocumentSyncCapability, TextDocumentSyncKind,
};
use tracing::{debug, info};

use super::commands::CommandExecutor;
use super::component_factory::{ComponentFactory, Config};
use super::queries::QueryExecutor;
use super::{InMemoryDocumentDatabase, LSPClient};

pub struct LSPServer<C> {
    command_executor: CommandExecutor<C>,
    query_executor: QueryExecutor,
    component_factory: RwLock<ComponentFactory>,
}

impl<C> LSPServer<C> {
    pub fn new(client: C) -> LSPServer<C> {
        let document_database = InMemoryDocumentDatabase::default();

        LSPServer {
            command_executor: CommandExecutor::new(client, document_database.clone()),
            query_executor: QueryExecutor::new(document_database.clone()),
            component_factory: RwLock::new(ComponentFactory::uninit()), // to be initialized in the initialize method of the LSP
        }
    }
}

impl<C> LSPServer<C>
where
    C: LSPClient + Send + Sync + 'static,
{
    async fn initialize_component_factory_with(&self, config: &Value) -> Result<()> {
        let Ok(config) = serde_json::from_value::<Config>(config.clone()) else {
            return Err(lsp_error(
                ErrorCode::InternalError,
                format!("unable to transform json into config: {}", config),
            ));
        };

        debug!("updating with configuration: {config:?}");

        self.component_factory
            .write()
            .await
            .initialize_with(config)
            .await;

        debug!("updated configuration");
        Ok(())
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
impl<C> LanguageServer for LSPServer<C>
where
    C: LSPClient + Send + Sync + 'static,
{
    async fn initialize(&self, initialize_params: InitializeParams) -> Result<InitializeResult> {
        let Some(config) = initialize_params.initialization_options else {
            return Err(Error {
                code: ErrorCode::InvalidParams,
                message: "expected parameters to configure the LSP, received nothing".into(),
                data: None,
            });
        };

        self.initialize_component_factory_with(&config).await?;

        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
                code_lens_provider: Some(CodeLensOptions {
                    resolve_provider: Some(false),
                }),
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
        info!("Initialized");
        self.command_executor
            .show_message(MessageType::INFO, "Sysdig LSP initialized")
            .await;
    }

    async fn did_change_configuration(&self, params: DidChangeConfigurationParams) {
        let _ = self
            .initialize_component_factory_with(&params.settings)
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
        let Some(content) = self
            .query_executor
            .get_document_text(params.text_document.uri.as_str())
            .await
        else {
            return Err(lsp_error(
                ErrorCode::InternalError,
                format!(
                    "unable to extract document content for document: {}",
                    &params.text_document.uri
                ),
            ));
        };

        let Some(last_line_starting_with_from_statement) = content
            .lines()
            .enumerate()
            .filter(|(_, line)| line.trim_start().starts_with("FROM "))
            .map(|(line_num, _)| line_num)
            .last()
        else {
            return Ok(None);
        };

        let Ok(line_selected_as_usize) = usize::try_from(params.range.start.line) else {
            return Err(lsp_error(
                ErrorCode::InternalError,
                format!("unable to parse u32 as usize: {}", params.range.start.line),
            ));
        };

        if last_line_starting_with_from_statement == line_selected_as_usize {
            let action = Command {
                title: "Scan base image".to_string(),
                command: SupportedCommands::ExecuteScan.to_string(),
                arguments: Some(vec![
                    json!(params.text_document.uri),
                    json!(line_selected_as_usize),
                ]),
            };

            return Ok(Some(vec![CodeActionOrCommand::Command(action)]));
        }

        return Ok(None);
    }

    async fn code_lens(&self, params: CodeLensParams) -> Result<Option<Vec<CodeLens>>> {
        info!("{}", format!("received code lens params: {params:?}"));

        let Some(content) = self
            .query_executor
            .get_document_text(params.text_document.uri.as_str())
            .await
        else {
            return Err(lsp_error(
                ErrorCode::InternalError,
                format!(
                    "unable to extract document content for document: {}",
                    &params.text_document.uri
                ),
            ));
        };

        let Some(last_line_starting_with_from_statement) = content
            .lines()
            .enumerate()
            .filter(|(_, line)| line.trim_start().starts_with("FROM "))
            .map(|(line_num, _)| line_num)
            .last()
        else {
            return Ok(None);
        };

        let scan_base_image_lens = CodeLens {
            range: Range {
                start: Position {
                    line: last_line_starting_with_from_statement as u32,
                    character: 0,
                },
                end: Position {
                    line: last_line_starting_with_from_statement as u32,
                    character: 0,
                },
            },
            command: Some(Command {
                title: "Scan base image".to_string(),
                command: SupportedCommands::ExecuteScan.to_string(),
                arguments: Some(vec![
                    json!(params.text_document.uri),
                    json!(last_line_starting_with_from_statement),
                ]),
            }),
            data: None,
        };

        Ok(Some(vec![scan_base_image_lens]))
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

                let component_factory_lock = self.component_factory.read().await;
                let image_scanner = component_factory_lock.image_scanner().await.map_err(|e| {
                    lsp_error(
                        ErrorCode::InternalError,
                        format!("unable to create image scanner: {e}"),
                    )
                })?;

                self.command_executor
                    .scan_image_from_file(
                        uri,
                        line,
                        image_scanner.as_ref().ok_or_else(|| {
                            lsp_error(
                                ErrorCode::InternalError,
                                "unable to retrieve created image scanner",
                            )
                        })?,
                    )
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
