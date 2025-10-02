use serde_json::Value;
use tower_lsp::jsonrpc::{Error, ErrorCode, Result};
use tower_lsp::lsp_types::{
    CodeActionOrCommand, CodeActionParams, CodeActionProviderCapability, CodeActionResponse,
    CodeLens, CodeLensOptions, CodeLensParams, Command, DidChangeConfigurationParams,
    DidChangeTextDocumentParams, DidOpenTextDocumentParams, ExecuteCommandOptions,
    ExecuteCommandParams, InitializeParams, InitializeResult, InitializedParams, MessageType,
    ServerCapabilities, TextDocumentSyncCapability, TextDocumentSyncKind,
};
use tracing::{debug, info};

use super::super::LspInteractor;
use super::super::component_factory::{ComponentFactory, Config};
use super::super::queries::QueryExecutor;
use super::command_generator;
use super::commands::{BuildAndScanCommand, LspCommand, ScanBaseImageCommand};
use super::{InMemoryDocumentDatabase, LSPClient, WithContext};

use super::supported_commands::SupportedCommands;

pub struct LSPServerInner<C> {
    interactor: LspInteractor<C>,
    query_executor: QueryExecutor,
    component_factory: ComponentFactory,
}

impl<C> LSPServerInner<C> {
    pub fn new(client: C) -> LSPServerInner<C> {
        let document_database = InMemoryDocumentDatabase::default();

        LSPServerInner {
            interactor: LspInteractor::new(client, document_database.clone()),
            query_executor: QueryExecutor::new(document_database.clone()),
            component_factory: Default::default(), // to be initialized in the initialize method of the LSP
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

        self.component_factory.initialize_with(config);

        debug!("updated configuration");
        Ok(())
    }
}

impl<C> LSPServerInner<C>
where
    C: LSPClient + Send + Sync + 'static,
{
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

        let commands =
            command_generator::generate_commands_for_uri(&params.text_document.uri, &content);
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

        let commands =
            command_generator::generate_commands_for_uri(&params.text_document.uri, &content);
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

    pub async fn execute_command(&mut self, params: ExecuteCommandParams) -> Result<Option<Value>> {
        let command: SupportedCommands = params.try_into()?;

        let result = match command.clone() {
            SupportedCommands::ExecuteBaseImageScan { location, image } => {
                let image_scanner = self.component_factory.image_scanner().map_err(|e| {
                    Error::internal_error()
                        .with_message(format!("unable to create image scanner: {e}"))
                })?;
                let mut command =
                    ScanBaseImageCommand::new(&image_scanner, &self.interactor, location, image);
                command.execute().await.map(|_| None)
            }

            SupportedCommands::ExecuteBuildAndScan { location } => {
                let image_scanner = self.component_factory.image_scanner().map_err(|e| {
                    Error::internal_error()
                        .with_message(format!("unable to create image scanner: {e}"))
                })?;
                let image_builder = self.component_factory.image_builder().map_err(|e| {
                    Error::internal_error()
                        .with_message(format!("unable to create image builder: {e}"))
                })?;
                let mut command = BuildAndScanCommand::new(
                    &image_builder,
                    &image_scanner,
                    &self.interactor,
                    location,
                );
                command.execute().await.map(|_| None)
            }
        };

        match result {
            Ok(_) => result,
            Err(mut e) => {
                self.interactor
                    .show_message(MessageType::ERROR, e.to_string().as_str())
                    .await;
                e.message = format!("error calling command: '{command}': {e}").into();
                Err(e)
            }
        }
    }

    pub async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}
