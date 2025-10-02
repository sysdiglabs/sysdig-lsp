use serde_json::Value;
use tower_lsp::jsonrpc::{Error, ErrorCode, Result};
use tower_lsp::lsp_types::{
    CodeActionOrCommand, CodeActionParams, CodeActionProviderCapability, CodeActionResponse,
    CodeLens, CodeLensOptions, CodeLensParams, Command, DidChangeConfigurationParams,
    DidChangeTextDocumentParams, DidOpenTextDocumentParams, ExecuteCommandOptions,
    ExecuteCommandParams, InitializeParams, InitializeResult, InitializedParams, Location,
    MessageType, ServerCapabilities, TextDocumentSyncCapability, TextDocumentSyncKind,
};
use tracing::{debug, info};

use super::super::LspInteractor;
use super::super::component_factory::{ComponentFactory, Config};
use super::super::queries::QueryExecutor;
use super::command_generator;
use super::commands::{
    LspCommand, build_and_scan::BuildAndScanCommand, scan_base_image::ScanBaseImageCommand,
};
use super::{InMemoryDocumentDatabase, LSPClient, WithContext};

use super::supported_commands::SupportedCommands;

pub struct LSPServerInner<C> {
    interactor: LspInteractor<C>,
    query_executor: QueryExecutor,
    component_factory: Option<ComponentFactory>,
}

impl<C> LSPServerInner<C> {
    pub fn new(client: C) -> LSPServerInner<C> {
        let document_database = InMemoryDocumentDatabase::default();

        LSPServerInner {
            interactor: LspInteractor::new(client, document_database.clone()),
            query_executor: QueryExecutor::new(document_database.clone()),
            component_factory: None, // to be initialized in the initialize method of the LSP
        }
    }
}

impl<C> LSPServerInner<C>
where
    C: LSPClient + Send + Sync + 'static,
{
    async fn initialize_component_factory_with(&mut self, config: &Value) -> Result<()> {
        let Ok(config) = serde_json::from_value::<Config>(config.clone()) else {
            return Err(Error::internal_error()
                .with_message(format!("unable to transform json into config: {config}")));
        };

        debug!("updating with configuration: {config:?}");

        let mut factory = ComponentFactory::default();
        factory.initialize_with(config);
        self.component_factory = Some(factory);

        debug!("updated configuration");
        Ok(())
    }
}

impl<C> LSPServerInner<C>
where
    C: LSPClient + Send + Sync + 'static,
{
    async fn get_commands_for_document(
        &self,
        uri: &tower_lsp::lsp_types::Url,
    ) -> Result<Vec<command_generator::CommandInfo>> {
        let Some(content) = self.query_executor.get_document_text(uri.as_str()).await else {
            return Err(Error::internal_error().with_message(format!(
                "unable to extract document content for document: {uri}"
            )));
        };

        let commands = command_generator::generate_commands_for_uri(uri, &content);
        Ok(commands)
    }

    pub async fn initialize(
        &mut self,
        initialize_params: InitializeParams,
    ) -> Result<InitializeResult> {
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

    pub async fn initialized(&self, _: InitializedParams) {
        info!("Initialized");
        self.interactor
            .show_message(MessageType::INFO, "Sysdig LSP initialized")
            .await;
    }

    pub async fn did_change_configuration(&mut self, params: DidChangeConfigurationParams) {
        let _ = self
            .initialize_component_factory_with(&params.settings)
            .await;
    }

    pub async fn did_open(&self, params: DidOpenTextDocumentParams) {
        self.interactor
            .update_document_with_text(
                params.text_document.uri.as_str(),
                params.text_document.text.as_str(),
            )
            .await;
    }

    pub async fn did_change(&self, params: DidChangeTextDocumentParams) {
        if let Some(change) = params.content_changes.into_iter().next_back() {
            self.interactor
                .update_document_with_text(params.text_document.uri.as_str(), &change.text)
                .await;
        }
    }

    pub async fn code_action(
        &self,
        params: CodeActionParams,
    ) -> Result<Option<CodeActionResponse>> {
        let commands = self
            .get_commands_for_document(&params.text_document.uri)
            .await?;
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

    pub async fn code_lens(&self, params: CodeLensParams) -> Result<Option<Vec<CodeLens>>> {
        let commands = self
            .get_commands_for_document(&params.text_document.uri)
            .await?;
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

    fn component_factory_mut(&mut self) -> Result<&mut ComponentFactory> {
        self.component_factory
            .as_mut()
            .ok_or_else(|| Error::internal_error().with_message("LSP not initialized"))
    }

    async fn execute_base_image_scan(
        &mut self,
        location: Location,
        image: String,
    ) -> Result<Option<Value>> {
        let image_scanner = self.component_factory_mut()?.image_scanner().map_err(|e| {
            Error::internal_error().with_message(format!("unable to create image scanner: {e}"))
        })?;
        let mut command =
            ScanBaseImageCommand::new(&image_scanner, &self.interactor, location, image);
        command.execute().await.map(|_| None)
    }

    async fn execute_build_and_scan(&mut self, location: Location) -> Result<Option<Value>> {
        let factory = self.component_factory_mut()?;
        let image_scanner = factory.image_scanner().map_err(|e| {
            Error::internal_error().with_message(format!("unable to create image scanner: {e}"))
        })?;
        let image_builder = factory.image_builder().map_err(|e| {
            Error::internal_error().with_message(format!("unable to create image builder: {e}"))
        })?;
        let mut command =
            BuildAndScanCommand::new(&image_builder, &image_scanner, &self.interactor, location);
        command.execute().await.map(|_| None)
    }

    pub async fn execute_command(&mut self, params: ExecuteCommandParams) -> Result<Option<Value>> {
        let command: SupportedCommands = params.try_into()?;

        let result = match command.clone() {
            SupportedCommands::ExecuteBaseImageScan { location, image } => {
                self.execute_base_image_scan(location, image).await
            }

            SupportedCommands::ExecuteBuildAndScan { location } => {
                self.execute_build_and_scan(location).await
            }
        };

        if let Err(e) = &result {
            self.interactor
                .show_message(MessageType::ERROR, e.to_string().as_str())
                .await;
            return Err(Error {
                code: e.code,
                message: format!("error calling command: '{command}': {}", e.message).into(),
                data: e.data.clone(),
            });
        }

        result
    }

    pub async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}
