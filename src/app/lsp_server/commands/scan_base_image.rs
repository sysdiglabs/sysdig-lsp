use itertools::Itertools;
use tower_lsp::lsp_types::{Diagnostic, DiagnosticSeverity, Location, MessageType};

use crate::{
    app::{
        ImageScanner, LSPClient, LspInteractor, lsp_server::WithContext, markdown::MarkdownData,
    },
    domain::scanresult::severity::Severity,
};

use super::LspCommand;

pub struct ScanBaseImageCommand<'a, C, S: ?Sized>
where
    S: ImageScanner,
{
    image_scanner: &'a S,
    interactor: &'a LspInteractor<C>,
    location: Location,
    image: String,
}

impl<'a, C, S: ?Sized> ScanBaseImageCommand<'a, C, S>
where
    S: ImageScanner,
{
    pub fn new(
        image_scanner: &'a S,
        interactor: &'a LspInteractor<C>,
        location: Location,
        image: String,
    ) -> Self {
        Self {
            image_scanner,
            interactor,
            location,
            image,
        }
    }
}

#[async_trait::async_trait]
impl<'a, C, S: ?Sized> LspCommand for ScanBaseImageCommand<'a, C, S>
where
    C: LSPClient + Sync,
    S: ImageScanner + Sync,
{
    async fn execute(&mut self) -> tower_lsp::jsonrpc::Result<()> {
        let image_name = &self.image;
        self.interactor
            .show_message(
                MessageType::INFO,
                format!("Starting scan of {image_name}...").as_str(),
            )
            .await;

        let scan_result = self
            .image_scanner
            .scan_image(image_name)
            .await
            .map_err(|e| tower_lsp::jsonrpc::Error::internal_error().with_message(e.to_string()))?;

        self.interactor
            .show_message(
                MessageType::INFO,
                format!("Finished scan of {image_name}.").as_str(),
            )
            .await;

        let diagnostic = {
            let mut diagnostic = Diagnostic {
                range: self.location.range,
                severity: Some(DiagnosticSeverity::HINT),
                message: "No vulnerabilities found.".to_owned(),
                ..Default::default()
            };

            if !scan_result.vulnerabilities().is_empty() {
                let vulns = scan_result
                    .vulnerabilities()
                    .iter()
                    .counts_by(|v| v.severity());
                diagnostic.message = format!(
                    "Vulnerabilities found for {}: {} Critical, {} High, {} Medium, {} Low, {} Negligible",
                    image_name,
                    vulns.get(&Severity::Critical).unwrap_or(&0_usize),
                    vulns.get(&Severity::High).unwrap_or(&0_usize),
                    vulns.get(&Severity::Medium).unwrap_or(&0_usize),
                    vulns.get(&Severity::Low).unwrap_or(&0_usize),
                    vulns.get(&Severity::Negligible).unwrap_or(&0_usize),
                );

                diagnostic.severity = Some(if scan_result.evaluation_result().is_passed() {
                    DiagnosticSeverity::INFORMATION
                } else {
                    DiagnosticSeverity::ERROR
                });
            }

            diagnostic
        };

        let uri = self.location.uri.as_str();
        self.interactor.remove_diagnostics(uri).await;
        self.interactor.remove_documentations(uri).await;
        self.interactor
            .append_document_diagnostics(uri, &[diagnostic])
            .await;
        self.interactor.publish_all_diagnostics().await?;
        self.interactor
            .append_documentation(
                self.location.uri.as_str(),
                self.location.range,
                MarkdownData::from(scan_result).to_string(),
            )
            .await;
        Ok(())
    }
}
