use tower_lsp::{
    jsonrpc::{Error, ErrorCode, Result},
    lsp_types::{Diagnostic, DiagnosticSeverity, MessageType, Position, Range},
};

use super::{ImageScanner, InMemoryDocumentDatabase, LSPClient};

pub struct CommandExecutor<C> {
    client: C,
    document_database: InMemoryDocumentDatabase,
}

impl<C> CommandExecutor<C> {
    pub fn new(client: C, document_database: InMemoryDocumentDatabase) -> Self {
        Self {
            client,
            document_database,
        }
    }

    fn image_from_line<'a>(&self, line: u32, contents: &'a str) -> Option<&'a str> {
        let line_number: usize = line.try_into().ok()?;
        let line_that_contains_from = contents.lines().nth(line_number)?;
        let image = line_that_contains_from
            .strip_prefix("FROM ")?
            .split_whitespace()
            .next();

        image
    }
}

impl<C> CommandExecutor<C>
where
    C: LSPClient,
{
    pub async fn update_document_with_text(&self, uri: &str, text: &str) {
        self.document_database.remove_document(uri).await;
        self.document_database.write_document_text(uri, text).await;
        let _ = self.publish_all_diagnostics().await;
    }

    pub async fn log_message(&self, message_type: MessageType, message: &str) {
        self.client.log_message(message_type, message).await;
    }

    pub async fn show_message(&self, message_type: MessageType, message: &str) {
        self.client.show_message(message_type, message).await;
    }

    async fn publish_all_diagnostics(&self) -> Result<()> {
        let all_diagnostics = self.document_database.all_diagnostics().await;
        for (url, diagnostics) in all_diagnostics {
            self.client
                .publish_diagnostics(&url, diagnostics, None)
                .await;
        }
        Ok(())
    }
}

impl<C> CommandExecutor<C>
where
    C: LSPClient,
{
    pub async fn scan_image_from_file<S: ImageScanner>(
        &self,
        uri: &str,
        line: u32,
        image_scanner: &mut S,
    ) -> Result<()> {
        let document_text = self
            .document_database
            .read_document_text(uri)
            .await
            .ok_or_else(|| Error {
                code: ErrorCode::InternalError,
                message: "unable to obtain document to scan".into(),
                data: None,
            })?;

        let image_for_selected_line =
            self.image_from_line(line, &document_text)
                .ok_or_else(|| Error {
                    code: ErrorCode::ParseError,
                    message: format!("unable to retrieve image for the selected line: {}", line)
                        .into(),
                    data: None,
                })?;

        let range_for_selected_line = document_text
            .lines()
            .nth(line as usize)
            .map(|x| x.len() as u32)
            .unwrap_or(u32::MAX);

        self.show_message(
            MessageType::INFO,
            format!("Starting scan of {}...", image_for_selected_line).as_str(),
        )
        .await;

        let scan_result = image_scanner
            .scan_image(image_for_selected_line)
            .await
            .map_err(|e| Error {
                code: ErrorCode::InternalError,
                message: e.to_string().into(),
                data: None,
            })?;

        self.show_message(
            MessageType::INFO,
            format!("Finished scan of {}.", image_for_selected_line).as_str(),
        )
        .await;

        let diagnostic = {
            let mut diagnostic = Diagnostic {
                range: Range {
                    start: Position::new(line, 0),
                    end: Position::new(line, range_for_selected_line),
                },
                severity: Some(DiagnosticSeverity::HINT),
                message: "No vulnerabilities found.".to_owned(),
                ..Default::default()
            };

            if scan_result.has_vulnerabilities() {
                let v = &scan_result.vulnerabilities;
                diagnostic.message = format!("Vulnerabilities found for {}: {} Critical, {} High, {} Medium, {} Low, {} Negligible",
                    image_for_selected_line,
                    v.critical,
                    v.high,
                    v.medium,
                    v.low,
                    v.negligible
                );

                diagnostic.severity = Some(if scan_result.is_compliant {
                    DiagnosticSeverity::INFORMATION
                } else {
                    DiagnosticSeverity::ERROR
                });
            }

            diagnostic
        };

        self.document_database.remove_diagnostics(uri).await;
        self.document_database
            .append_document_diagnostics(uri, &[diagnostic])
            .await;
        self.publish_all_diagnostics().await
    }
}
