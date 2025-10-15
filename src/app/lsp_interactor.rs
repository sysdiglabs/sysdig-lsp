use tower_lsp::{
    jsonrpc::Result,
    lsp_types::{Diagnostic, MessageType, Position, Range},
};

use super::{InMemoryDocumentDatabase, LSPClient};

pub struct LspInteractor<C> {
    client: C,
    document_database: InMemoryDocumentDatabase,
}

impl<C> LspInteractor<C> {
    pub fn new(client: C, document_database: InMemoryDocumentDatabase) -> Self {
        Self {
            client,
            document_database,
        }
    }
}

impl<C> LspInteractor<C>
where
    C: LSPClient,
{
    pub async fn update_document_with_text(&self, uri: &str, text: &str) {
        self.document_database.write_document_text(uri, text).await;
        self.document_database.remove_diagnostics(uri).await;
        self.document_database.remove_documentations(uri).await;
        let _ = self.publish_all_diagnostics().await;
    }

    pub async fn show_message(&self, message_type: MessageType, message: &str) {
        self.client.show_message(message_type, message).await;
    }

    pub async fn publish_all_diagnostics(&self) -> Result<()> {
        let all_diagnostics = self.document_database.all_diagnostics().await;
        for (url, diagnostics) in all_diagnostics {
            self.client
                .publish_diagnostics(&url, diagnostics, None)
                .await;
        }
        Ok(())
    }

    pub async fn read_document_text(&self, uri: &str) -> Option<String> {
        self.document_database.read_document_text(uri).await
    }

    pub async fn remove_diagnostics(&self, uri: &str) {
        self.document_database.remove_diagnostics(uri).await
    }

    pub async fn append_document_diagnostics(&self, uri: &str, diagnostics: &[Diagnostic]) {
        self.document_database
            .append_document_diagnostics(uri, diagnostics)
            .await
    }

    pub async fn append_documentation(&self, uri: &str, range: Range, documentation: String) {
        self.document_database
            .append_documentation(uri, range, documentation)
            .await
    }
    pub async fn read_documentation_at(&self, uri: &str, position: Position) -> Option<String> {
        self.document_database
            .read_documentation_at(uri, position)
            .await
    }

    pub async fn remove_documentations(&self, uri: &str) {
        self.document_database.remove_documentations(uri).await
    }
}
