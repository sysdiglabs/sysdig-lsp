use std::collections::HashMap;

use tokio::sync::RwLock;
use tower_lsp::lsp_types::Diagnostic;

#[derive(Default, Debug)]
pub struct DocumentDatabase {
    documents: RwLock<HashMap<String, Document>>,
}

#[derive(Default, Debug, Clone)]
pub struct Document {
    pub text: String,
    pub diagnostics: Vec<Diagnostic>,
}

impl DocumentDatabase {
    pub async fn add_document(&self, uri: impl Into<String>, document: Document) {
        self.documents.write().await.insert(uri.into(), document);
    }

    pub async fn read_document(&self, uri: &str) -> Option<Document> {
        self.documents.read().await.get(uri).cloned()
    }

    pub async fn remove_document(&self, uri: &str) {
        self.documents.write().await.remove(uri);
    }

    pub async fn add_diagnostics(&self, uri: impl Into<String>, diagnostics: &[Diagnostic]) {
        self.documents
            .write()
            .await
            .entry(uri.into())
            .and_modify(|d| d.diagnostics.extend_from_slice(diagnostics));
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
    async fn test_add_and_read_document() {
        let db = DocumentDatabase::default();
        let doc = Document {
            text: "let x = 42;".to_string(),
            diagnostics: vec![create_diagnostic((0, 4), (0, 5), "Unused variable")],
        };

        db.add_document("file://test.rs", doc.clone()).await;
        let retrieved_doc = db.read_document("file://test.rs").await;

        assert!(retrieved_doc.is_some());
        assert_eq!(retrieved_doc.unwrap().text, "let x = 42;");
    }

    #[tokio::test]
    async fn test_remove_document() {
        let db = DocumentDatabase::default();
        let doc = Document {
            text: "fn main() {}".to_string(),
            diagnostics: vec![],
        };

        db.add_document("file://main.rs", doc).await;
        assert!(db.read_document("file://main.rs").await.is_some());

        db.remove_document("file://main.rs").await;
        assert!(db.read_document("file://main.rs").await.is_none());
    }

    #[tokio::test]
    async fn test_add_diagnostics() {
        let db = DocumentDatabase::default();
        let doc = Document {
            text: "fn test() {}".to_string(),
            diagnostics: vec![],
        };

        let diagnostics = vec![
            create_diagnostic((0, 3), (0, 7), "Function name is too generic"),
            create_diagnostic((0, 0), (0, 2), "Missing doc comment"),
        ];

        db.add_document("file://test.rs", doc).await;
        db.add_diagnostics("file://test.rs", &diagnostics).await;

        let retrieved_doc = db.read_document("file://test.rs").await.unwrap();
        assert_eq!(retrieved_doc.diagnostics.len(), diagnostics.len());
        assert_eq!(
            retrieved_doc.diagnostics[0].message,
            "Function name is too generic"
        );
    }

    #[tokio::test]
    async fn test_all_diagnostics() {
        let db = DocumentDatabase::default();

        db.add_document(
            "file://mod1.rs",
            Document {
                text: "module 1".to_string(),
                diagnostics: vec![create_diagnostic((0, 0), (0, 6), "Incorrect module name")],
            },
        )
        .await;

        db.add_document(
            "file://mod2.rs",
            Document {
                text: "module 2".to_string(),
                diagnostics: vec![
                    create_diagnostic((0, 0), (0, 6), "Incorrect module name"),
                    create_diagnostic((0, 7), (0, 8), "Unexpected token"),
                ],
            },
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
        let db = DocumentDatabase::default();

        let all_diagnostics: Vec<_> = db.all_diagnostics().await.collect();
        assert!(all_diagnostics.is_empty());

        assert!(db.read_document("nonexistent").await.is_none());
    }
}
