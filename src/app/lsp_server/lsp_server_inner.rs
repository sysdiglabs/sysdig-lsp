use serde_json::Value;
use tower_lsp::jsonrpc::{Error, ErrorCode, Result};
use tower_lsp::lsp_types::{
    CodeActionOrCommand, CodeActionParams, CodeActionProviderCapability, CodeActionResponse,
    CodeLens, CodeLensOptions, CodeLensParams, DidChangeConfigurationParams,
    DidChangeTextDocumentParams, DidOpenTextDocumentParams, ExecuteCommandOptions,
    ExecuteCommandParams, InitializeParams, InitializeResult, InitializedParams, MessageType,
    ServerCapabilities, TextDocumentSyncCapability, TextDocumentSyncKind,
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
    fn update_component_factory(&mut self, config: &Value) -> Result<()> {
        let config = serde_json::from_value::<Config>(config.clone()).map_err(|e| {
            Error::internal_error()
                .with_message(format!("unable to transform json into config: {e}"))
        })?;

        debug!("updating with configuration: {config:?}");

        let factory = ComponentFactory::new(config)?;
        self.component_factory.replace(factory);

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

        self.update_component_factory(&config)?;

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
        let _ = self.update_component_factory(&params.settings);
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
            .map(|cmd| CodeActionOrCommand::Command(cmd.into()))
            .collect();

        Ok(Some(code_actions))
    }

    pub async fn code_lens(&self, params: CodeLensParams) -> Result<Option<Vec<CodeLens>>> {
        let commands = self
            .get_commands_for_document(&params.text_document.uri)
            .await?;
        let code_lenses = commands.into_iter().map(|cmd| cmd.into()).collect();

        Ok(Some(code_lenses))
    }

    async fn execute_base_image_scan(
        &self,
        location: tower_lsp::lsp_types::Location,
        image: String,
    ) -> Result<()> {
        let factory = self
            .component_factory
            .as_ref()
            .ok_or_else(|| Error::internal_error().with_message("LSP not initialized"))?;
        let image_scanner = factory.image_scanner();
        ScanBaseImageCommand::new(image_scanner, &self.interactor, location, image)
            .execute()
            .await
    }

    async fn execute_build_and_scan(&self, location: tower_lsp::lsp_types::Location) -> Result<()> {
        let factory = self
            .component_factory
            .as_ref()
            .ok_or_else(|| Error::internal_error().with_message("LSP not initialized"))?;
        let image_scanner = factory.image_scanner();
        let image_builder = factory.image_builder();
        BuildAndScanCommand::new(image_builder, image_scanner, &self.interactor, location)
            .execute()
            .await
    }

    async fn handle_command_error(&self, command_name: &str, e: Error) -> Error {
        self.interactor
            .show_message(MessageType::ERROR, e.to_string().as_str())
            .await;
        Error {
            code: e.code,
            message: format!("error calling command: '{command_name}': {}", e.message).into(),
            data: e.data,
        }
    }

    pub async fn execute_command(&self, params: ExecuteCommandParams) -> Result<Option<Value>> {
        let command: SupportedCommands = params.try_into()?;
        let command_name = command.to_string();

        let result = match command {
            SupportedCommands::ExecuteBaseImageScan { location, image } => {
                self.execute_base_image_scan(location, image).await
            }
            SupportedCommands::ExecuteBuildAndScan { location } => {
                self.execute_build_and_scan(location).await
            }
        };

        match result {
            Ok(_) => Ok(None),
            Err(e) => Err(self.handle_command_error(&command_name, e).await),
        }
    }

    pub async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}
