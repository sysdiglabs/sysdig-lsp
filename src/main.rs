use clap::Parser;
use sysdig_lsp::{app::LSPServer, infra::lsp_logger::LSPLogger};
use tower_lsp::{LspService, Server};
use tracing_subscriber::layer::SubscriberExt;

#[derive(Parser, Debug)]
#[command(version, author, about, long_about)]
struct Args {}

#[tokio::main]
async fn main() {
    let _ = Args::parse();
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, messages) = LspService::new(|client| {
        let subscriber = tracing_subscriber::registry()
            .with(LSPLogger::new(client.clone()))
            .with(tracing_subscriber::fmt::layer());

        tracing::subscriber::set_global_default(subscriber)
            .expect("setting default subscriber failed");

        LSPServer::new(client)
    });

    Server::new(stdin, stdout, messages).serve(service).await;
}
