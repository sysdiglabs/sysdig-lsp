use sysdig_lsp::LSPServer;
use tower_lsp::{LspService, Server};

#[tokio::main]
async fn main() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, messages) = LspService::new(LSPServer::new);
    Server::new(stdin, stdout, messages).serve(service).await;
}
