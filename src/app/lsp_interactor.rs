use std::collections::HashMap;

use tower_lsp::{
    jsonrpc::Result,
    lsp_types::{Diagnostic, MessageType, Position, Range},
};

use super::{DiagnosticsScope, InMemoryDocumentDatabase, LSPClient, VULN_DIAGNOSTIC_SOURCE};

#[derive(Clone)]
pub struct LspInteractor<C> {
    client: C,
    document_database: InMemoryDocumentDatabase,
    /// Serializes snapshot+publish+prune sequences: without it, a concurrent
    /// publish could send a stale snapshot after a clearing publish, and the
    /// prune would then drop the entry so no future publish self-heals it.
    publish_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
}

impl<C> LspInteractor<C> {
    pub fn new(client: C, document_database: InMemoryDocumentDatabase) -> Self {
        Self {
            client,
            document_database,
            publish_lock: Default::default(),
        }
    }
}

impl<C> LspInteractor<C>
where
    C: LSPClient,
{
    pub async fn update_document_with_text(&self, uri: &str, text: &str) {
        self.document_database.write_document_text(uri, text).await;
        // Vulnerability diagnostics anchor to specific lines, so they go stale as soon
        // as the text changes. IaC diagnostics anchor to the top of the file and keep
        // being meaningful across edits, so they survive the document lifecycle.
        self.document_database
            .replace_diagnostics_with_source(
                VULN_DIAGNOSTIC_SOURCE,
                DiagnosticsScope::Document(uri),
                HashMap::new(),
            )
            .await;
        self.document_database.remove_documentations(uri).await;
        let _ = self.publish_all_diagnostics().await;
    }

    pub async fn show_message(&self, message_type: MessageType, message: &str) {
        self.client.show_message(message_type, message).await;
    }

    pub async fn publish_all_diagnostics(&self) -> Result<()> {
        let _guard = self.publish_lock.lock().await;

        let all_diagnostics: Vec<_> = self.document_database.all_diagnostics().await.collect();
        for (url, diagnostics) in &all_diagnostics {
            self.client
                .publish_diagnostics(url, diagnostics.clone(), None)
                .await;
        }

        // Drop only the entries whose clearing publish we just sent, so the
        // database doesn't grow unbounded with never-opened files discovered by
        // workspace scans. Pruning is limited to the URIs observed empty in THIS
        // snapshot: an entry emptied concurrently after the snapshot was taken
        // stays in the database, so the next publish still sends its clearing
        // update instead of stranding stale diagnostics on the client forever.
        let published_as_empty: Vec<&str> = all_diagnostics
            .iter()
            .filter(|(_, diagnostics)| diagnostics.is_empty())
            .map(|(url, _)| url.as_str())
            .collect();
        self.document_database
            .prune_documents_if_empty(&published_as_empty)
            .await;
        Ok(())
    }

    pub async fn read_document_text(&self, uri: &str) -> Option<String> {
        self.document_database.read_document_text(uri).await
    }

    pub async fn replace_diagnostics_with_source(
        &self,
        source: &str,
        scope: DiagnosticsScope<'_>,
        new_diagnostics: HashMap<String, Vec<Diagnostic>>,
    ) {
        self.document_database
            .replace_diagnostics_with_source(source, scope, new_diagnostics)
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
