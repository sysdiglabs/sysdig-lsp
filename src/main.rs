use sysdig_lsp::LSP;
use tower_lsp::{LspService, Server};

#[tokio::main]
async fn main() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let current_dir = std::env::current_dir().expect("unable to obtain the currenct directoy");
    let (service, messages) = LspService::new(|client| LSP::new(client, current_dir));
    Server::new(stdin, stdout, messages).serve(service).await;
}
