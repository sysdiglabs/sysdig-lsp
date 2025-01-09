use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::{InitializeParams, InitializeResult, InitializedParams};

#[derive(Default)]
pub struct LSP {}

#[async_trait::async_trait]
impl tower_lsp::LanguageServer for LSP {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult::default())
    }

    async fn initialized(&self, _: InitializedParams) {
        // No action needed for now
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}
