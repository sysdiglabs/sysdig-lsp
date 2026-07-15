pub mod build_and_scan;
pub mod iac_scan;
pub mod scan_base_image;

use tower_lsp::jsonrpc::Result;

pub use crate::app::{IAC_DIAGNOSTIC_SOURCE, VULN_DIAGNOSTIC_SOURCE};

#[async_trait::async_trait]
pub trait LspCommand {
    async fn execute(&mut self) -> Result<()>;
}
