use std::borrow::Cow;
use std::path::PathBuf;
use std::str::FromStr;

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
            component_factory: Default::default(), // to be initialized in the initialize method of the LSP
        }
    }
}

impl<C> LSPServer<C>
where
    C: LSPClient + Send + Sync + 'static,
{
    async fn initialize_component_factory_with(&self, config: &Value) -> Result<()> {
        let Ok(config) = serde_json::from_value::<Config>(config.clone()) else {
            return Err(Error::internal_error()
                .with_message(format!("unable to transform json into config: {}", config)));
        };

        debug!("updating with configuration: {config:?}");

        self.component_factory.write().await.initialize_with(config);

        debug!("updated configuration");
        Ok(())
    }
}

pub enum SupportedCommands {
    ExecuteBaseImageScan,
    ExecuteBuildAndScan,
}

impl std::fmt::Display for SupportedCommands {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ExecuteBaseImageScan => "sysdig-lsp.execute-scan",
            Self::ExecuteBuildAndScan => "sysdig-lsp.execute-build-and-scan",
        })
    }
}

impl TryFrom<&str> for SupportedCommands {
    type Error = String;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "sysdig-lsp.execute-scan" => Ok(SupportedCommands::ExecuteBaseImageScan),
            "sysdig-lsp.execute-build-and-scan" => Ok(SupportedCommands::ExecuteBuildAndScan),
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
                    commands: vec![
                        SupportedCommands::ExecuteBaseImageScan.to_string(),
                        SupportedCommands::ExecuteBuildAndScan.to_string(),
                    ],
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
        let mut code_actions = vec![];

        let Some(content) = self
            .query_executor
            .get_document_text(params.text_document.uri.as_str())
            .await
        else {
            return Err(Error::internal_error().with_message(format!(
                "unable to extract document content for document: {}",
                &params.text_document.uri
            )));
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
            return Err(Error::internal_error().with_message(format!(
                "unable to parse u32 as usize: {}",
                params.range.start.line
            )));
        };

        if last_line_starting_with_from_statement == line_selected_as_usize {
            code_actions.push(CodeActionOrCommand::Command(Command {
                title: "Build and scan".to_string(),
                command: SupportedCommands::ExecuteBuildAndScan.to_string(),
                arguments: Some(vec![
                    json!(params.text_document.uri),
                    json!(line_selected_as_usize),
                ]),
            }));
            code_actions.push(CodeActionOrCommand::Command(Command {
                title: "Scan base image".to_string(),
                command: SupportedCommands::ExecuteBaseImageScan.to_string(),
                arguments: Some(vec![
                    json!(params.text_document.uri),
                    json!(line_selected_as_usize),
                ]),
            }));
        }

        Ok(Some(code_actions))
    }

    async fn code_lens(&self, params: CodeLensParams) -> Result<Option<Vec<CodeLens>>> {
        let mut code_lens = vec![];

        let Some(content) = self
            .query_executor
            .get_document_text(params.text_document.uri.as_str())
            .await
        else {
            return Err(Error::internal_error().with_message(format!(
                "unable to extract document content for document: {}",
                &params.text_document.uri
            )));
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

        code_lens.push(CodeLens {
            range: Range::new(
                Position::new(last_line_starting_with_from_statement as u32, 0),
                Position::new(last_line_starting_with_from_statement as u32, 0),
            ),
            command: Some(Command {
                title: "Build and scan".to_string(),
                command: SupportedCommands::ExecuteBuildAndScan.to_string(),
                arguments: Some(vec![
                    json!(params.text_document.uri),
                    json!(last_line_starting_with_from_statement),
                ]),
            }),
            data: None,
        });
        code_lens.push(CodeLens {
            range: Range::new(
                Position::new(last_line_starting_with_from_statement as u32, 0),
                Position::new(last_line_starting_with_from_statement as u32, 0),
            ),
            command: Some(Command {
                title: "Scan base image".to_string(),
                command: SupportedCommands::ExecuteBaseImageScan.to_string(),
                arguments: Some(vec![
                    json!(params.text_document.uri),
                    json!(last_line_starting_with_from_statement),
                ]),
            }),
            data: None,
        });

        Ok(Some(code_lens))
    }

    async fn execute_command(&self, params: ExecuteCommandParams) -> Result<Option<Value>> {
        let command: SupportedCommands = params.command.as_str().try_into().map_err(|e| {
            Error::internal_error().with_message(format!("unable to parse command: {}", e))
        })?;

        let result = match command {
            SupportedCommands::ExecuteBaseImageScan => {
                execute_command_scan_base_image(self, &params)
                    .await
                    .map(|_| None)
            }

            SupportedCommands::ExecuteBuildAndScan => execute_command_build_and_scan(self, &params)
                .await
                .map(|_| None),
        };

        result.map_err(|mut e: Error| {
            e.message = format!("error calling command: '{command}': {e}").into();
            e
        })
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}

async fn execute_command_scan_base_image<C: LSPClient>(
    server: &LSPServer<C>,
    params: &ExecuteCommandParams,
) -> Result<()> {
    let Some(uri) = params.arguments.first() else {
        return Err(Error::internal_error().with_message("no uri was provided"));
    };

    let Some(uri) = uri.as_str() else {
        return Err(Error::internal_error().with_message("uri is not a string"));
    };

    let Some(line) = params.arguments.get(1) else {
        return Err(Error::internal_error().with_message("no line was provided"));
    };

    let Some(line) = line.as_u64().and_then(|x| u32::try_from(x).ok()) else {
        return Err(Error::internal_error().with_message("line is not a u32"));
    };

    let image_scanner = {
        let mut lock = server.component_factory.write().await;
        lock.image_scanner().map_err(|e| {
            Error::internal_error().with_message(format!("unable to create image scanner: {e}"))
        })?
    };

    server
        .command_executor
        .scan_image_from_file(uri, line, &image_scanner)
        .await?;

    Ok(())
}

async fn execute_command_build_and_scan<C: LSPClient>(
    server: &LSPServer<C>,
    params: &ExecuteCommandParams,
) -> Result<()> {
    let Some(uri) = params.arguments.first() else {
        return Err(Error::internal_error().with_message("no uri was provided"));
    };

    let Some(uri) = uri.as_str() else {
        return Err(Error::internal_error().with_message("uri is not a string"));
    };

    let Some(line) = params.arguments.get(1) else {
        return Err(Error::internal_error().with_message("no line was provided"));
    };

    let Some(line) = line.as_u64().and_then(|x| u32::try_from(x).ok()) else {
        return Err(Error::internal_error().with_message("line is not a u32"));
    };

    let (image_scanner, image_builder) = {
        let mut factory = server.component_factory.write().await;

        let image_scanner = factory.image_scanner().map_err(|e| {
            Error::internal_error().with_message(format!("unable to create image scanner: {}", e))
        })?;
        let image_builder = factory.image_builder().map_err(|e| {
            Error::internal_error().with_message(format!("unable to create image builder: {}", e))
        })?;

        (image_scanner, image_builder)
    };

    server
        .command_executor
        .build_and_scan_from_file(
            &PathBuf::from_str(uri).unwrap(),
            line,
            &image_builder,
            &image_scanner,
        )
        .await?;

    Ok(())
}

pub(super) trait WithContext {
    fn with_message(self, message: impl Into<Cow<'static, str>>) -> Self;
}

impl WithContext for Error {
    fn with_message(mut self, message: impl Into<Cow<'static, str>>) -> Self {
        self.message = message.into();
        self
    }
}
