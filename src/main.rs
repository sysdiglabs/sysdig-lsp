use sysdig_lsp::LSP;
use tower_lsp::{LspService, Server};

#[tokio::main]
async fn main() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, messages) = LspService::new(LSP::new);
    Server::new(stdin, stdout, messages).serve(service).await;
}
