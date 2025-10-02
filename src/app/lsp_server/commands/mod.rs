pub mod build_and_scan;
pub mod scan_base_image;

use tower_lsp::jsonrpc::Result;

#[async_trait::async_trait]
pub trait LspCommand {
    async fn execute(&mut self) -> Result<()>;
}
