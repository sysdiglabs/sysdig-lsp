use std::{collections::HashMap, sync::Arc};

use tokio::sync::RwLock;
use tower_lsp::lsp_types::{Diagnostic, Position, Range};

#[derive(Default, Debug, Clone)]
pub struct InMemoryDocumentDatabase {
    documents: Arc<RwLock<HashMap<String, Document>>>,
}

#[derive(Default, Debug, Clone)]
struct Document {
    /// `Some` once the client has opened the document (even if its content is
    /// empty); `None` for entries that only hold diagnostics for files that were
    /// never opened (e.g. discovered by a workspace-wide IaC scan).
    pub text: Option<String>,
    pub diagnostics: Vec<Diagnostic>,
    pub documentations: Vec<Documentation>,
}

#[derive(Default, Debug, Clone)]
struct Documentation {
    pub range: Range,
    pub content: String,
}

/// Which documents a diagnostics replacement clears before inserting new ones.
#[derive(Debug, Clone, Copy)]
pub enum DiagnosticsScope<'a> {
    /// Only the document with this exact URI.
    Document(&'a str),
    /// Every document whose URI starts with this prefix (e.g. a workspace root
    /// with a trailing `/`). An empty prefix matches all documents.
    DocumentsWithUriPrefix(&'a str),
}

impl InMemoryDocumentDatabase {
    pub async fn write_document_text(&self, uri: impl Into<String>, text: impl Into<String>) {
        let text = text.into();

        self.documents
            .write()
            .await
            .entry(uri.into())
            .and_modify(|e| e.text = Some(text.clone()))
            .or_insert_with(|| Document {
                text: Some(text),
                ..Default::default()
            });
    }

    async fn read_document(&self, uri: &str) -> Option<Document> {
        self.documents.read().await.get(uri).cloned()
    }

    pub async fn read_document_text(&self, uri: &str) -> Option<String> {
        self.read_document(uri).await.and_then(|e| e.text)
    }

    /// Drops the given document entries if they (still) hold no state at all:
    /// never opened by the client and no diagnostics/documentation left to publish.
    pub async fn prune_documents_if_empty(&self, uris: &[&str]) {
        let mut documents = self.documents.write().await;
        for uri in uris {
            let is_empty = documents.get(*uri).is_some_and(|d| {
                d.text.is_none() && d.diagnostics.is_empty() && d.documentations.is_empty()
            });
            if is_empty {
                documents.remove(*uri);
            }
        }
    }

    /// Atomically replaces every diagnostic tagged with `source` by `new_diagnostics`,
    /// under a single write lock so concurrent commands cannot observe or interleave
    /// a half-updated state.
    ///
    /// `scope` limits the removal; diagnostics with a different (or no) source are
    /// always preserved.
    pub async fn replace_diagnostics_with_source(
        &self,
        source: &str,
        scope: DiagnosticsScope<'_>,
        new_diagnostics: HashMap<String, Vec<Diagnostic>>,
    ) {
        let mut documents = self.documents.write().await;

        let retain_other_sources = |document: &mut Document| {
            document
                .diagnostics
                .retain(|diag| diag.source.as_deref() != Some(source))
        };
        match scope {
            DiagnosticsScope::Document(uri) => {
                if let Some(document) = documents.get_mut(uri) {
                    retain_other_sources(document);
                }
            }
            DiagnosticsScope::DocumentsWithUriPrefix(prefix) => documents
                .iter_mut()
                .filter(|(uri, _)| uri.starts_with(prefix))
                .for_each(|(_, document)| retain_other_sources(document)),
        }

        for (uri, diagnostics) in new_diagnostics {
            // Inserting outside the cleared scope would accumulate duplicates on
            // every repeated call, so the invariant is enforced here on data
            // (diagnostic URIs can derive from external scanner output).
            let in_scope = match scope {
                DiagnosticsScope::Document(scoped_uri) => uri == scoped_uri,
                DiagnosticsScope::DocumentsWithUriPrefix(prefix) => uri.starts_with(prefix),
            };
            if !in_scope {
                tracing::warn!("dropping diagnostics outside the replacement scope: {uri}");
                continue;
            }

            documents
                .entry(uri)
                .or_default()
                .diagnostics
                .extend(diagnostics);
        }
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
        assert_eq!(document.text.as_deref(), Some("contents"));
    }

    #[tokio::test]
    async fn test_add_text_and_update_if_exists() {
        let db = InMemoryDocumentDatabase::default();

        db.write_document_text("file://main.rs", "contents").await;
        db.write_document_text("file://main.rs", "updated").await;

        let document = db.read_document("file://main.rs").await.unwrap();
        assert_eq!(document.text.as_deref(), Some("updated"));
    }

    /// Seeds diagnostics as-is: replacing a source no diagnostic has just appends.
    async fn seed_diagnostics(
        db: &InMemoryDocumentDatabase,
        uri: &str,
        diagnostics: Vec<Diagnostic>,
    ) {
        db.replace_diagnostics_with_source(
            "__nonexistent__",
            DiagnosticsScope::DocumentsWithUriPrefix(""),
            HashMap::from([(uri.to_string(), diagnostics)]),
        )
        .await;
    }

    #[tokio::test]
    async fn test_add_diagnostics() {
        let db = InMemoryDocumentDatabase::default();
        let diagnostics = vec![
            create_diagnostic((0, 3), (0, 7), "Function name is too generic"),
            create_diagnostic((0, 0), (0, 2), "Missing doc comment"),
        ];

        seed_diagnostics(&db, "file://test.rs", diagnostics.clone()).await;

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

        seed_diagnostics(
            &db,
            "file://mod1.rs",
            vec![create_diagnostic((0, 0), (0, 6), "Incorrect module name")],
        )
        .await;

        seed_diagnostics(
            &db,
            "file://mod2.rs",
            vec![
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

    fn create_diagnostic_with_source(message: &str, source: Option<&str>) -> Diagnostic {
        Diagnostic {
            source: source.map(str::to_string),
            ..create_diagnostic((0, 0), (0, 1), message)
        }
    }

    #[tokio::test]
    async fn test_replace_diagnostics_with_source_across_all_documents() {
        let db = InMemoryDocumentDatabase::default();

        let iac = create_diagnostic_with_source("IaC finding", Some("sysdig-iac"));
        let other = create_diagnostic_with_source("Other tool finding", Some("other-source"));
        let untagged = create_diagnostic_with_source("Image scan finding", None);

        seed_diagnostics(
            &db,
            "file://doc1.yaml",
            vec![iac.clone(), other.clone(), untagged.clone()],
        )
        .await;
        seed_diagnostics(&db, "file://doc2.yaml", vec![iac.clone()]).await;

        let replacement = create_diagnostic_with_source("New IaC finding", Some("sysdig-iac"));
        db.replace_diagnostics_with_source(
            "sysdig-iac",
            DiagnosticsScope::DocumentsWithUriPrefix(""),
            HashMap::from([("file://doc3.yaml".to_string(), vec![replacement])]),
        )
        .await;

        let all_diagnostics: Vec<_> = db
            .all_diagnostics()
            .await
            .sorted_by(|(x, _), (y, _)| Ord::cmp(x, y))
            .collect();

        assert_eq!(all_diagnostics.len(), 3);
        // Exact source match: "other-source" and untagged diagnostics are preserved
        assert_eq!(all_diagnostics[0].0, "file://doc1.yaml");
        let messages: Vec<_> = all_diagnostics[0]
            .1
            .iter()
            .map(|d| d.message.as_str())
            .collect();
        assert_eq!(messages, vec!["Other tool finding", "Image scan finding"]);
        // doc2 entry persists with empty diagnostics, so publish clears the client
        assert_eq!(all_diagnostics[1].0, "file://doc2.yaml");
        assert!(all_diagnostics[1].1.is_empty());
        // The replacement is appended
        assert_eq!(all_diagnostics[2].0, "file://doc3.yaml");
        assert_eq!(all_diagnostics[2].1[0].message, "New IaC finding");
    }

    #[tokio::test]
    async fn test_replace_drops_insertions_outside_a_document_scope() {
        let db = InMemoryDocumentDatabase::default();

        let in_scope = create_diagnostic_with_source("In scope", Some("sysdig-iac"));
        let out_of_scope = create_diagnostic_with_source("Out of scope", Some("sysdig-iac"));
        db.replace_diagnostics_with_source(
            "sysdig-iac",
            DiagnosticsScope::Document("file:///a.yaml"),
            HashMap::from([
                ("file:///a.yaml".to_string(), vec![in_scope]),
                ("file:///b.yaml".to_string(), vec![out_of_scope]),
            ]),
        )
        .await;

        let all_diagnostics: Vec<_> = db
            .all_diagnostics()
            .await
            .sorted_by(|(x, _), (y, _)| Ord::cmp(x, y))
            .collect();

        // Insertions outside the cleared scope are dropped: they would accumulate
        // duplicates on every rescan since no replacement would ever clear them.
        assert_eq!(all_diagnostics.len(), 1);
        assert_eq!(all_diagnostics[0].0, "file:///a.yaml");
        assert_eq!(all_diagnostics[0].1[0].message, "In scope");
    }

    #[tokio::test]
    async fn test_replace_diagnostics_with_source_scoped_by_uri_prefix() {
        let db = InMemoryDocumentDatabase::default();

        let iac = create_diagnostic_with_source("IaC finding", Some("sysdig-iac"));
        seed_diagnostics(&db, "file:///workspace/a.yaml", vec![iac.clone()]).await;
        seed_diagnostics(&db, "file:///outside/b.yaml", vec![iac.clone()]).await;

        db.replace_diagnostics_with_source(
            "sysdig-iac",
            DiagnosticsScope::DocumentsWithUriPrefix("file:///workspace/"),
            HashMap::new(),
        )
        .await;

        let all_diagnostics: Vec<_> = db
            .all_diagnostics()
            .await
            .sorted_by(|(x, _), (y, _)| Ord::cmp(x, y))
            .collect();

        // Only documents under the prefix are cleared
        assert_eq!(all_diagnostics[0].0, "file:///outside/b.yaml");
        assert_eq!(all_diagnostics[0].1.len(), 1);
        assert_eq!(all_diagnostics[1].0, "file:///workspace/a.yaml");
        assert!(all_diagnostics[1].1.is_empty());
    }

    #[tokio::test]
    async fn test_prune_keeps_open_documents_with_empty_text() {
        let db = InMemoryDocumentDatabase::default();

        db.write_document_text("file:///empty.yaml", "").await;
        seed_diagnostics(&db, "file:///never-opened.yaml", vec![]).await;

        db.prune_documents_if_empty(&["file:///empty.yaml", "file:///never-opened.yaml"])
            .await;

        // An opened-but-empty document must survive (code lens reads its text);
        // a never-opened entry without diagnostics is dropped.
        assert!(db.read_document_text("file:///empty.yaml").await.is_some());
        let remaining: Vec<_> = db.all_diagnostics().await.map(|(uri, _)| uri).collect();
        assert_eq!(remaining, vec!["file:///empty.yaml".to_string()]);
    }

    #[tokio::test]
    async fn test_prune_keeps_entries_that_are_no_longer_empty() {
        let db = InMemoryDocumentDatabase::default();

        let iac = create_diagnostic_with_source("IaC finding", Some("sysdig-iac"));
        seed_diagnostics(&db, "file:///refilled.yaml", vec![iac]).await;

        // A concurrent replacement refilled the entry between the publish snapshot
        // and the prune: it must survive so the next publish sends its diagnostics.
        db.prune_documents_if_empty(&["file:///refilled.yaml"])
            .await;

        let remaining: Vec<_> = db.all_diagnostics().await.map(|(uri, _)| uri).collect();
        assert_eq!(remaining, vec!["file:///refilled.yaml".to_string()]);
    }

    #[tokio::test]
    async fn test_replace_diagnostics_with_source_scoped_to_a_single_document() {
        let db = InMemoryDocumentDatabase::default();

        let iac = create_diagnostic_with_source("IaC finding", Some("sysdig-iac"));
        seed_diagnostics(&db, "file://doc1.yaml", vec![iac.clone()]).await;
        seed_diagnostics(&db, "file://doc2.yaml", vec![iac.clone()]).await;

        let replacement = create_diagnostic_with_source("New IaC finding", Some("sysdig-iac"));
        db.replace_diagnostics_with_source(
            "sysdig-iac",
            DiagnosticsScope::Document("file://doc1.yaml"),
            HashMap::from([("file://doc1.yaml".to_string(), vec![replacement])]),
        )
        .await;

        let all_diagnostics: Vec<_> = db
            .all_diagnostics()
            .await
            .sorted_by(|(x, _), (y, _)| Ord::cmp(x, y))
            .collect();

        // doc1 replaced, doc2 untouched by the scoped replacement
        assert_eq!(all_diagnostics[0].1[0].message, "New IaC finding");
        assert_eq!(all_diagnostics[1].1[0].message, "IaC finding");
    }

    #[tokio::test]
    async fn test_empty_database() {
        let db = InMemoryDocumentDatabase::default();

        let all_diagnostics: Vec<_> = db.all_diagnostics().await.collect();
        assert!(all_diagnostics.is_empty());

        assert!(db.read_document("nonexistent").await.is_none());
    }
}
