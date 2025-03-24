use std::fmt::Display;

use tower_lsp::{
    Client as TowerClient,
    lsp_types::{Diagnostic, MessageType, Url},
};
use tracing::{error, info};

#[async_trait::async_trait]
pub trait LSPClient {
    async fn show_message<M: Display + Send>(&self, message_type: MessageType, message: M);
    async fn publish_diagnostics(
        &self,
        url: &str,
        diagnostics: Vec<Diagnostic>,
        version: Option<i32>,
    );
}

#[async_trait::async_trait]
impl LSPClient for TowerClient {
    async fn show_message<M: Display + Send>(&self, message_type: MessageType, message: M) {
        TowerClient::show_message(self, message_type, message).await
    }

    async fn publish_diagnostics(
        &self,
        url: &str,
        diagnostics: Vec<Diagnostic>,
        version: Option<i32>,
    ) {
        match Url::parse(url) {
            Ok(parsed_url) => {
                info!("published diagnostics: {diagnostics:?}");
                // self.log_message(
                //     MessageType::INFO,
                //     format!("published diagnostics: {diagnostics:?}"),
                // )
                // .await;
                TowerClient::publish_diagnostics(self, parsed_url, diagnostics, version).await
            }
            Err(parse_error) => {
                error!("unable to send diagnostics, the url could not be parsed: {parse_error}");
            }
        }
    }
}
