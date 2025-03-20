use std::fmt::Display;

use tower_lsp::{
    lsp_types::{Diagnostic, MessageType, Url},
    Client as TowerClient,
};

#[async_trait::async_trait]
pub trait LSPClient {
    async fn log_message<M: Display + Send>(&self, message_type: MessageType, message: M);
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
    async fn log_message<M: Display + Send>(&self, message_type: MessageType, message: M) {
        TowerClient::log_message(self, message_type, message).await
    }

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
                self.log_message(
                    MessageType::INFO,
                    format!("published diagnostics: {diagnostics:?}"),
                )
                .await;
                TowerClient::publish_diagnostics(self, parsed_url, diagnostics, version).await
            }
            Err(parse_error) => {
                self.log_message(
                    MessageType::WARNING,
                    format!("unable to parse url to send diagnostics: {}", parse_error),
                )
                .await
            }
        }
    }
}
