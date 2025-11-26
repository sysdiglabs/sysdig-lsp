use crate::{
    app::LSPServer,
    infra::{ConcreteComponentFactory, lsp_logger::LSPLogger},
};
use clap::Parser;
use tower_lsp::{LspService, Server};
use tracing_subscriber::layer::SubscriberExt;

mod app;
mod domain;
mod infra;

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
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr));

        tracing::subscriber::set_global_default(subscriber)
            .expect("setting default subscriber failed");

        LSPServer::new(client, ConcreteComponentFactory)
    });

    Server::new(stdin, stdout, messages).serve(service).await;
}
