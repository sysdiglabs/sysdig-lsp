use std::borrow::Cow;
use std::path::PathBuf;
use std::str::FromStr;

use serde_json::Value;
use tokio::sync::RwLock;
use tower_lsp::LanguageServer;
use tower_lsp::jsonrpc::{Error, ErrorCode, Result};
use tower_lsp::lsp_types::{
    CodeActionOrCommand, CodeActionParams, CodeActionProviderCapability, CodeActionResponse,
    CodeLens, CodeLensOptions, CodeLensParams, Command, DidChangeConfigurationParams,
    DidChangeTextDocumentParams, DidOpenTextDocumentParams, ExecuteCommandOptions,
    ExecuteCommandParams, InitializeParams, InitializeResult, InitializedParams, Location,
    MessageType, Range, ServerCapabilities, TextDocumentSyncCapability, TextDocumentSyncKind,
};
use tracing::{debug, info};

use super::commands::CommandExecutor;
use super::component_factory::{ComponentFactory, Config};
use super::queries::QueryExecutor;
use super::{InMemoryDocumentDatabase, LSPClient};
use crate::infra::{parse_compose_file, parse_dockerfile};

mod supported_commands;
use supported_commands::SupportedCommands;

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
                .with_message(format!("unable to transform json into config: {config}")));
        };

        debug!("updating with configuration: {config:?}");

        self.component_factory.write().await.initialize_with(config);

        debug!("updated configuration");
        Ok(())
    }
}

struct CommandInfo {
    title: String,
    command: String,
    arguments: Option<Vec<Value>>,
    range: Range,
}

impl<C> LSPServer<C>
where
    C: LSPClient + Send + Sync + 'static,
{
    fn generate_commands_for_uri(
        &self,
        uri: &tower_lsp::lsp_types::Url,
        content: &str,
    ) -> Vec<CommandInfo> {
        let file_uri = uri.as_str();

        if file_uri.contains("docker-compose.yml")
            || file_uri.contains("compose.yml")
            || file_uri.contains("docker-compose.yaml")
            || file_uri.contains("compose.yaml")
        {
            self.generate_compose_commands(uri, content)
        } else {
            self.generate_dockerfile_commands(uri, content)
        }
    }

    fn generate_compose_commands(
        &self,
        url: &tower_lsp::lsp_types::Url,
        content: &str,
    ) -> Vec<CommandInfo> {
        let mut commands = vec![];
        if let Ok(instructions) = parse_compose_file(content) {
            for instruction in instructions {
                commands.push(
                    SupportedCommands::ExecuteBaseImageScan {
                        location: Location::new(url.clone(), instruction.range),
                        image: instruction.image_name,
                    }
                    .into(),
                );
            }
        }
        commands
    }

    fn generate_dockerfile_commands(
        &self,
        uri: &tower_lsp::lsp_types::Url,
        content: &str,
    ) -> Vec<CommandInfo> {
        let mut commands = vec![];
        let instructions = parse_dockerfile(content);
        if let Some(last_from_instruction) = instructions
            .iter()
            .filter(|instruction| instruction.keyword == "FROM")
            .next_back()
        {
            let range = last_from_instruction.range;
            commands.push(
                SupportedCommands::ExecuteBuildAndScan {
                    location: Location::new(uri.clone(), range),
                }
                .into(),
            );
            if let Some(image) = last_from_instruction.arguments.first() {
                commands.push(
                    SupportedCommands::ExecuteBaseImageScan {
                        location: Location::new(uri.clone(), range),
                        image: image.to_owned(),
                    }
                    .into(),
                );
            }
        }
        commands
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
                    commands: SupportedCommands::all_supported_commands_as_string(),
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
        if let Some(change) = params.content_changes.into_iter().next_back() {
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
            return Err(Error::internal_error().with_message(format!(
                "unable to extract document content for document: {}",
                &params.text_document.uri
            )));
        };

        let commands = self.generate_commands_for_uri(&params.text_document.uri, &content);
        let code_actions: Vec<CodeActionOrCommand> = commands
            .into_iter()
            .filter(|cmd| cmd.range.start.line == params.range.start.line)
            .map(|cmd| {
                CodeActionOrCommand::Command(Command {
                    title: cmd.title,
                    command: cmd.command,
                    arguments: cmd.arguments,
                })
            })
            .collect();

        Ok(Some(code_actions))
    }

    async fn code_lens(&self, params: CodeLensParams) -> Result<Option<Vec<CodeLens>>> {
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

        let commands = self.generate_commands_for_uri(&params.text_document.uri, &content);
        let code_lenses = commands
            .into_iter()
            .map(|cmd| CodeLens {
                range: cmd.range,
                command: Some(Command {
                    title: cmd.title,
                    command: cmd.command,
                    arguments: cmd.arguments,
                }),
                data: None,
            })
            .collect();

        Ok(Some(code_lenses))
    }

    async fn execute_command(&self, params: ExecuteCommandParams) -> Result<Option<Value>> {
        let command: SupportedCommands = params.try_into()?;

        let result = match command.clone() {
            SupportedCommands::ExecuteBaseImageScan { location, image } => {
                execute_command_scan_base_image(
                    self,
                    location.uri.to_string(),
                    location.range,
                    image,
                )
                .await
                .map(|_| None)
            }

            SupportedCommands::ExecuteBuildAndScan { location } => {
                execute_command_build_and_scan(self, location.uri.to_string(), location.range)
                    .await
                    .map(|_| None)
            }
        };

        match result {
            Ok(_) => result,
            Err(mut e) => {
                self.command_executor
                    .show_message(MessageType::ERROR, e.to_string().as_str())
                    .await;
                e.message = format!("error calling command: '{command}': {e}").into();
                Err(e)
            }
        }
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}

async fn execute_command_scan_base_image<C: LSPClient>(
    server: &LSPServer<C>,
    file: String,
    range: Range,
    image: String,
) -> Result<()> {
    let image_scanner = {
        let mut lock = server.component_factory.write().await;
        lock.image_scanner().map_err(|e| {
            Error::internal_error().with_message(format!("unable to create image scanner: {e}"))
        })?
    };

    server
        .command_executor
        .scan_image(&file, range, &image, &image_scanner)
        .await?;

    Ok(())
}

async fn execute_command_build_and_scan<C: LSPClient>(
    server: &LSPServer<C>,
    file: String,
    range: Range,
) -> Result<()> {
    let (image_scanner, image_builder) = {
        let mut factory = server.component_factory.write().await;

        let image_scanner = factory.image_scanner().map_err(|e| {
            Error::internal_error().with_message(format!("unable to create image scanner: {e}"))
        })?;
        let image_builder = factory.image_builder().map_err(|e| {
            Error::internal_error().with_message(format!("unable to create image builder: {e}"))
        })?;

        (image_scanner, image_builder)
    };

    server
        .command_executor
        .build_and_scan_from_file(
            &PathBuf::from_str(&file).unwrap(),
            range.start.line,
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
