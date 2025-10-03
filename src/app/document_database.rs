use std::{collections::HashMap, sync::Arc};

use tokio::sync::RwLock;
use tower_lsp::lsp_types::{Diagnostic, Position, Range};

#[derive(Default, Debug, Clone)]
pub struct InMemoryDocumentDatabase {
    documents: Arc<RwLock<HashMap<String, Document>>>,
}

#[derive(Default, Debug, Clone)]
struct Document {
    pub text: String,
    pub diagnostics: Vec<Diagnostic>,
    pub documentations: Vec<Documentation>,
}

#[derive(Default, Debug, Clone)]
struct Documentation {
    pub range: Range,
    pub content: String,
}

impl InMemoryDocumentDatabase {
    pub async fn write_document_text(&self, uri: impl Into<String>, text: impl Into<String>) {
        let text = text.into();

        self.documents
            .write()
            .await
            .entry(uri.into())
            .and_modify(|e| e.text = text.clone())
            .or_insert_with(|| Document {
                text,
                ..Default::default()
            });
    }

    async fn read_document(&self, uri: &str) -> Option<Document> {
        self.documents.read().await.get(uri).cloned()
    }

    pub async fn read_document_text(&self, uri: &str) -> Option<String> {
        self.read_document(uri).await.map(|e| e.text)
    }

    pub async fn remove_document(&self, uri: &str) {
        self.documents.write().await.remove(uri);
    }

    pub async fn append_document_diagnostics(
        &self,
        uri: impl Into<String>,
        diagnostics: &[Diagnostic],
    ) {
        self.documents
            .write()
            .await
            .entry(uri.into())
            .and_modify(|d| d.diagnostics.extend_from_slice(diagnostics))
            .or_insert_with(|| Document {
                diagnostics: diagnostics.to_vec(),
                ..Default::default()
            });
    }

    pub async fn remove_diagnostics(&self, uri: impl Into<String>) {
        self.documents
            .write()
            .await
            .entry(uri.into())
            .and_modify(|d| d.diagnostics.clear());
    }

    pub async fn all_diagnostics(&self) -> impl Iterator<Item = (String, Vec<Diagnostic>)> {
        let hash_map = self.documents.read().await.clone();
        hash_map
            .into_iter()
            .map(|(uri, doc)| (uri, doc.diagnostics))
    }

    pub async fn append_documentation(&self, uri: &str, range: Range, documentation: String) {
        self.documents
            .write()
            .await
            .entry(uri.into())
            .and_modify(|d| {
                d.documentations.push(Documentation {
                    range,
                    content: documentation.clone(),
                })
            })
            .or_insert_with(|| Document {
                documentations: vec![Documentation {
                    range,
                    content: documentation,
                }],
                ..Default::default()
            });
    }

    pub async fn read_documentation_at(&self, uri: &str, position: Position) -> Option<String> {
        let documents = self.documents.read().await;
        let document_asked_for = documents.get(uri);
        let mut documentations_for_document = document_asked_for
            .iter()
            .flat_map(|d| d.documentations.iter());
        let first_documentation_in_range = documentations_for_document.find(|documentation| {
            position > documentation.range.start && position < documentation.range.end
        });

        first_documentation_in_range.map(|d| d.content.clone())
    }

    pub async fn remove_documentations(&self, uri: &str) {
        let mut documents = self.documents.write().await;
        if let Some(document_asked_for) = documents.get_mut(uri) {
            document_asked_for.documentations.clear();
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;
    use tower_lsp::lsp_types::{Diagnostic, Position, Range};

    fn create_diagnostic(start: (u32, u32), end: (u32, u32), message: &str) -> Diagnostic {
        Diagnostic {
            range: Range {
                start: Position {
                    line: start.0,
                    character: start.1,
                },
                end: Position {
                    line: end.0,
                    character: end.1,
                },
            },
            message: message.to_string(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_add_text_if_not_exists() {
        let db = InMemoryDocumentDatabase::default();

        db.write_document_text("file://main.rs", "contents").await;

        let document = db.read_document("file://main.rs").await.unwrap();
        assert_eq!(document.text, "contents");
    }

    #[tokio::test]
    async fn test_add_text_and_update_if_exists() {
        let db = InMemoryDocumentDatabase::default();

        db.write_document_text("file://main.rs", "contents").await;
        db.write_document_text("file://main.rs", "updated").await;

        let document = db.read_document("file://main.rs").await.unwrap();
        assert_eq!(document.text, "updated");
    }

    #[tokio::test]
    async fn test_remove_document() {
        let db = InMemoryDocumentDatabase::default();

        db.write_document_text("file://main.rs", "contents").await;
        assert!(db.read_document("file://main.rs").await.is_some());

        db.remove_document("file://main.rs").await;
        assert!(db.read_document("file://main.rs").await.is_none());
    }

    #[tokio::test]
    async fn test_add_diagnostics() {
        let db = InMemoryDocumentDatabase::default();
        let diagnostics = vec![
            create_diagnostic((0, 3), (0, 7), "Function name is too generic"),
            create_diagnostic((0, 0), (0, 2), "Missing doc comment"),
        ];

        db.append_document_diagnostics("file://test.rs", &diagnostics)
            .await;

        let retrieved_doc = db.read_document("file://test.rs").await.unwrap();
        assert_eq!(retrieved_doc.diagnostics.len(), diagnostics.len());
        assert_eq!(
            retrieved_doc.diagnostics[0].message,
            "Function name is too generic"
        );
    }

    #[tokio::test]
    async fn test_all_diagnostics() {
        let db = InMemoryDocumentDatabase::default();

        db.append_document_diagnostics(
            "file://mod1.rs",
            &vec![create_diagnostic((0, 0), (0, 6), "Incorrect module name")],
        )
        .await;

        db.append_document_diagnostics(
            "file://mod2.rs",
            &vec![
                create_diagnostic((0, 0), (0, 6), "Incorrect module name"),
                create_diagnostic((0, 7), (0, 8), "Unexpected token"),
            ],
        )
        .await;

        let all_diagnostics: Vec<_> = db
            .all_diagnostics()
            .await
            .sorted_by(|(x, _), (y, _)| Ord::cmp(x, y))
            .collect();
        assert_eq!(all_diagnostics.len(), 2);
        assert_eq!(all_diagnostics[0].1.len(), 1);
        assert_eq!(all_diagnostics[1].1.len(), 2);

        let mod1_diag = &all_diagnostics[0].1[0];
        assert_eq!(mod1_diag.message, "Incorrect module name");

        let mod2_diag = &all_diagnostics[1].1[1];
        assert_eq!(mod2_diag.message, "Unexpected token");
    }

    #[tokio::test]
    async fn test_empty_database() {
        let db = InMemoryDocumentDatabase::default();

        let all_diagnostics: Vec<_> = db.all_diagnostics().await.collect();
        assert!(all_diagnostics.is_empty());

        assert!(db.read_document("nonexistent").await.is_none());
    }
}
