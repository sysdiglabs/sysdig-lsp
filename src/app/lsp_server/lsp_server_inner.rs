use std::path::PathBuf;
use std::sync::Arc;

use serde_json::Value;
use tower_lsp::jsonrpc::{Error, ErrorCode, Result};
use tower_lsp::lsp_types::HoverContents::Markup;
use tower_lsp::lsp_types::MarkupKind::Markdown;
use tower_lsp::lsp_types::{
    CodeActionOrCommand, CodeActionParams, CodeActionProviderCapability, CodeActionResponse,
    CodeLens, CodeLensOptions, CodeLensParams, DidChangeConfigurationParams,
    DidChangeTextDocumentParams, DidOpenTextDocumentParams, ExecuteCommandOptions,
    ExecuteCommandParams, Hover, HoverParams, HoverProviderCapability, InitializeParams,
    InitializeResult, InitializedParams, MarkupContent, MessageType, ServerCapabilities,
    TextDocumentSyncCapability, TextDocumentSyncKind, Url,
};
use tracing::{debug, info};

use super::super::component_factory::{ComponentFactory, Components, Config};
use super::super::queries::QueryExecutor;
use super::command_generator;
use super::commands::{
    LspCommand, build_and_scan::BuildAndScanCommand, iac_scan::IacScanCommand,
    scan_base_image::ScanBaseImageCommand,
};
use super::{InMemoryDocumentDatabase, LSPClient, WithContext};
use crate::app::IacScanScope;
use crate::app::LspInteractor;

use super::supported_commands::SupportedCommands;

pub struct LSPServerInner<C, F: ComponentFactory> {
    interactor: LspInteractor<C>,
    query_executor: QueryExecutor,
    component_factory: F,
    components: Option<Arc<Components>>,
    workspace_root: Option<PathBuf>,
}

/// Executes LSP commands with its own clones of the server dependencies, so
/// long-running scans don't hold the server-wide lock.
pub struct CommandExecutor<C> {
    components: Option<Arc<Components>>,
    interactor: LspInteractor<C>,
    workspace_root: Option<PathBuf>,
}

impl<C> CommandExecutor<C>
where
    C: LSPClient + Send + Sync + 'static,
{
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
            SupportedCommands::ExecuteIacScan { uri } => self.execute_iac_scan(uri).await,
        };

        match result {
            Ok(_) => Ok(None),
            Err(e) => Err(self.handle_command_error(&command_name, e).await),
        }
    }

    /// Resolved here (not when building the executor) so a missing initialization
    /// flows through `handle_command_error` and is surfaced to the user.
    fn components(&self) -> Result<&Arc<Components>> {
        self.components
            .as_ref()
            .ok_or_else(|| Error::internal_error().with_message("LSP not initialized"))
    }

    async fn execute_base_image_scan(
        &self,
        location: tower_lsp::lsp_types::Location,
        image: String,
    ) -> Result<()> {
        ScanBaseImageCommand::new(
            self.components()?.scanner.as_ref(),
            &self.interactor,
            location,
            image,
        )
        .execute()
        .await
    }

    async fn execute_build_and_scan(&self, location: tower_lsp::lsp_types::Location) -> Result<()> {
        let components = self.components()?;
        BuildAndScanCommand::new(
            components.builder.as_ref(),
            components.scanner.as_ref(),
            &self.interactor,
            location,
        )
        .execute()
        .await
    }

    async fn execute_iac_scan(&self, uri: Option<Url>) -> Result<()> {
        let scope = match uri {
            Some(uri) => {
                let path = uri.to_file_path().map_err(|_| {
                    Error::invalid_params(format!(
                        "only file:// URIs are supported, received: {uri}"
                    ))
                })?;
                IacScanScope::File { uri, path }
            }
            None => IacScanScope::Directory(self.workspace_root.clone().ok_or_else(|| {
                Error::internal_error()
                    .with_message("no workspace root available; open a folder or pass a file URI")
            })?),
        };

        IacScanCommand::new(
            self.components()?.iac_scanner.as_ref(),
            &self.interactor,
            scope,
        )
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
}

impl<C, F: ComponentFactory> LSPServerInner<C, F> {
    pub fn new(client: C, component_factory: F) -> LSPServerInner<C, F> {
        let document_database = InMemoryDocumentDatabase::default();

        LSPServerInner {
            interactor: LspInteractor::new(client, document_database.clone()),
            query_executor: QueryExecutor::new(document_database.clone()),
            component_factory,
            components: None,
            workspace_root: None,
        }
    }
}

impl<C, F: ComponentFactory> LSPServerInner<C, F>
where
    C: LSPClient + Send + Sync + 'static,
{
    fn update_components(&mut self, config: &Value) -> Result<()> {
        let config = serde_json::from_value::<Config>(config.clone()).map_err(|e| {
            Error::internal_error()
                .with_message(format!("unable to transform json into config: {e}"))
        })?;

        debug!("updating with configuration: {config:?}");

        let components = self.component_factory.create_components(config)?;
        self.components.replace(Arc::new(components));

        debug!("updated configuration");
        Ok(())
    }
}

impl<C, F: ComponentFactory> LSPServerInner<C, F>
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

        Ok(command_generator::generate_commands_for_uri(uri, &content))
    }

    pub async fn initialize(
        &mut self,
        initialize_params: InitializeParams,
    ) -> Result<InitializeResult> {
        self.workspace_root = workspace_root_from(&initialize_params);

        let Some(config) = initialize_params.initialization_options else {
            return Err(Error {
                code: ErrorCode::InvalidParams,
                message: "expected parameters to configure the LSP, received nothing".into(),
                data: None,
            });
        };

        self.update_components(&config)?;

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
                hover_provider: Some(HoverProviderCapability::Simple(true)),
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
        let _ = self.update_components(&params.settings);
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

    /// Clones everything a command needs so it can run without holding the
    /// server lock: commands spawn long-lived scanner subprocesses, and keeping
    /// the read guard for their whole duration would block `did_change_configuration`
    /// (write) and, since the lock is FIFO-fair, every request queued after it.
    pub fn command_executor(&self) -> CommandExecutor<C>
    where
        C: Clone,
    {
        CommandExecutor {
            components: self.components.clone(),
            interactor: self.interactor.clone(),
            workspace_root: self.workspace_root.clone(),
        }
    }

    pub async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let documentation_found = self
            .interactor
            .read_documentation_at(
                params
                    .text_document_position_params
                    .text_document
                    .uri
                    .as_str(),
                params.text_document_position_params.position,
            )
            .await;

        let Some(documentation) = documentation_found else {
            return Ok(None);
        };

        Ok(Some(Hover {
            contents: Markup(MarkupContent {
                kind: Markdown,
                value: documentation,
            }),
            range: None,
        }))
    }

    pub async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}

fn workspace_root_from(initialize_params: &InitializeParams) -> Option<PathBuf> {
    let from_workspace_folders = initialize_params
        .workspace_folders
        .as_ref()
        .and_then(|folders| folders.first())
        .and_then(|folder| folder.uri.to_file_path().ok());

    #[allow(deprecated)]
    from_workspace_folders.or_else(|| {
        initialize_params
            .root_uri
            .as_ref()
            .and_then(|uri| uri.to_file_path().ok())
    })
}
