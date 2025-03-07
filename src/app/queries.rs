use super::InMemoryDocumentDatabase;

pub struct QueryExecutor {
    document_database: InMemoryDocumentDatabase,
}

impl QueryExecutor {
    pub fn new(document_database: InMemoryDocumentDatabase) -> Self {
        Self { document_database }
    }

    pub async fn get_document_text(&self, uri: &str) -> Option<String> {
        self.document_database.read_document_text(uri).await
    }
}
