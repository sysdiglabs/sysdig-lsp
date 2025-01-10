use tower_lsp::{
    lsp_types::{Diagnostic, MessageType, Url},
    Client,
};

#[async_trait::async_trait]
pub trait LSPClient {
    async fn log_message(&self, message_type: MessageType, message: &str);
    async fn publish_diagnostics(&self, url: Url, diagnostics: Vec<Diagnostic>, other: Option<i32>);
}

#[async_trait::async_trait]
impl LSPClient for Client {
    async fn log_message(&self, message_type: MessageType, message: &str) {
        Client::log_message(self, message_type, message).await
    }
    async fn publish_diagnostics(
        &self,
        url: Url,
        diagnostics: Vec<Diagnostic>,
        other: Option<i32>,
    ) {
        Client::publish_diagnostics(self, url, diagnostics, other).await
    }
}
