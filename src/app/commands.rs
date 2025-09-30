use std::{
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use itertools::Itertools;
use tower_lsp::{
    jsonrpc::{Error, Result},
    lsp_types::{Diagnostic, DiagnosticSeverity, MessageType, Position, Range},
};

use crate::{
    domain::scanresult::{layer::Layer, scan_result::ScanResult, severity::Severity},
    infra::parse_dockerfile,
};

use super::{
    ImageBuilder, ImageScanner, InMemoryDocumentDatabase, LSPClient, lsp_server::WithContext,
};

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
        line_that_contains_from
            .strip_prefix("FROM ")?
            .split_whitespace()
            .next()
    }
}

impl<C> CommandExecutor<C>
where
    C: LSPClient,
{
    pub async fn update_document_with_text(&self, uri: &str, text: &str) {
        self.document_database.write_document_text(uri, text).await;
        self.document_database.remove_diagnostics(uri).await;
        let _ = self.publish_all_diagnostics().await;
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
    pub async fn scan_image(
        &self,
        uri: &str,
        range: Range,
        image_name: &str,
        image_scanner: &impl ImageScanner,
    ) -> Result<()> {
        self.show_message(
            MessageType::INFO,
            format!("Starting scan of {image_name}...").as_str(),
        )
        .await;

        let scan_result = image_scanner
            .scan_image(image_name)
            .await
            .map_err(|e| Error::internal_error().with_message(e.to_string()))?;

        self.show_message(
            MessageType::INFO,
            format!("Finished scan of {image_name}.").as_str(),
        )
        .await;

        let diagnostic = {
            let mut diagnostic = Diagnostic {
                range,
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

        self.document_database.remove_diagnostics(uri).await;
        self.document_database
            .append_document_diagnostics(uri, &[diagnostic])
            .await;
        self.publish_all_diagnostics().await
    }

    pub async fn build_and_scan_from_file(
        &self,
        uri: &Path,
        line: u32,
        image_builder: &impl ImageBuilder,
        image_scanner: &impl ImageScanner,
    ) -> Result<()> {
        let document_text = self
            .document_database
            .read_document_text(uri.to_str().unwrap_or_default())
            .await
            .ok_or_else(|| {
                Error::internal_error().with_message("unable to obtain document to scan")
            })?;

        let uri_without_file_path = uri
            .to_str()
            .and_then(|s| s.strip_prefix("file://"))
            .ok_or_else(|| {
                Error::internal_error().with_message("unable to strip prefix file:// from uri")
            })?;

        self.show_message(
            MessageType::INFO,
            format!("Starting build of {uri_without_file_path}...").as_str(),
        )
        .await;

        let build_result = image_builder
            .build_image(&PathBuf::from_str(uri_without_file_path).unwrap())
            .await
            .map_err(|e| Error::internal_error().with_message(e.to_string()))?;

        self.show_message(
            MessageType::INFO,
            format!(
                "Temporal image built '{}', starting scan...",
                &build_result.image_name
            )
            .as_str(),
        )
        .await;

        let scan_result = image_scanner
            .scan_image(&build_result.image_name)
            .await
            .map_err(|e| Error::internal_error().with_message(e.to_string()))?;

        self.show_message(
            MessageType::INFO,
            format!("Finished scan of {}.", &build_result.image_name).as_str(),
        )
        .await;

        let diagnostic = diagnostic_for_image(line, &document_text, &scan_result);
        let diagnostics_per_layer = diagnostics_for_layers(&document_text, &scan_result)?;

        self.document_database
            .remove_diagnostics(uri.to_str().unwrap())
            .await;
        self.document_database
            .append_document_diagnostics(uri.to_str().unwrap(), &[diagnostic])
            .await;
        self.document_database
            .append_document_diagnostics(uri.to_str().unwrap(), &diagnostics_per_layer)
            .await;
        self.publish_all_diagnostics().await
    }
}

pub fn diagnostics_for_layers(
    document_text: &str,
    scan_result: &ScanResult,
) -> Result<Vec<Diagnostic>> {
    let instructions = parse_dockerfile(document_text);
    let layers = &scan_result.layers();

    let mut instr_idx = instructions.len().checked_sub(1);
    let mut layer_idx = layers.len().checked_sub(1);

    let mut diagnostics = Vec::new();

    while let (Some(i), Some(l)) = (instr_idx, layer_idx) {
        let instr = &instructions[i];
        let layer = &layers[l];

        if instr.keyword == "FROM" {
            break;
        }

        instr_idx = instr_idx.and_then(|x| x.checked_sub(1));
        layer_idx = layer_idx.and_then(|x| x.checked_sub(1));

        if !layer.vulnerabilities().is_empty() {
            let vulns = layer.vulnerabilities().iter().counts_by(|v| v.severity());
            let msg = format!(
                "Vulnerabilities found in layer: {} Critical, {} High, {} Medium, {} Low, {} Negligible",
                vulns.get(&Severity::Critical).unwrap_or(&0_usize),
                vulns.get(&Severity::High).unwrap_or(&0_usize),
                vulns.get(&Severity::Medium).unwrap_or(&0_usize),
                vulns.get(&Severity::Low).unwrap_or(&0_usize),
                vulns.get(&Severity::Negligible).unwrap_or(&0_usize),
            );
            let diagnostic = Diagnostic {
                range: instr.range,
                severity: Some(DiagnosticSeverity::WARNING),
                message: msg,
                ..Default::default()
            };

            diagnostics.push(diagnostic);

            fill_vulnerability_hints_for_layer(layer, instr.range, &mut diagnostics)
        }
    }

    Ok(diagnostics)
}

fn fill_vulnerability_hints_for_layer(
    layer: &Arc<Layer>,
    range: Range,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let vulns_per_severity = layer
        .vulnerabilities()
        .iter()
        .cloned()
        .sorted_by_key(|v| v.severity());

    // TODO(fede): eventually we would want to add here a .take() to truncate the number
    // of vulnerabilities shown as hint per layer.
    vulns_per_severity.for_each(|vuln| {
        let url = format!("https://nvd.nist.gov/vuln/detail/{}", vuln.cve());
        diagnostics.push(Diagnostic {
            range,
            severity: Some(DiagnosticSeverity::HINT),
            message: format!(
                "Vulnerability: {} ({:?}) {}",
                vuln.cve(),
                vuln.severity(),
                url
            ),
            ..Default::default()
        });
    });
}

fn diagnostic_for_image(line: u32, document_text: &str, scan_result: &ScanResult) -> Diagnostic {
    let range_for_selected_line = Range::new(
        Position::new(line, 0),
        Position::new(
            line,
            document_text
                .lines()
                .nth(line as usize)
                .map(|x| x.len() as u32)
                .unwrap_or(u32::MAX),
        ),
    );

    let mut diagnostic = Diagnostic {
        range: range_for_selected_line,
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
            "Total vulnerabilities found: {} Critical, {} High, {} Medium, {} Low, {} Negligible",
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
}
