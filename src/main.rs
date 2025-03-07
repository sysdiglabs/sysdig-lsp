use sysdig_lsp::app::LSPServer;
use sysdig_lsp::infra::SysdigImageScanner;
use tower_lsp::{LspService, Server};

#[tokio::main]
async fn main() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let image_scanner = SysdigImageScanner::new();
    let (service, messages) = LspService::new(|client| LSPServer::new(client, image_scanner));
    Server::new(stdin, stdout, messages).serve(service).await;
}
