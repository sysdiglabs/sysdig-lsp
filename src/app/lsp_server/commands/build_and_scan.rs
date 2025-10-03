use std::{path::PathBuf, str::FromStr, sync::Arc};

use itertools::Itertools;
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::{
    Diagnostic, DiagnosticSeverity, Location, MessageType, Position, Range,
};

use crate::app::markdown::{MarkdownData, MarkdownLayerData};
use crate::{
    app::{ImageBuilder, ImageScanner, LSPClient, LspInteractor, lsp_server::WithContext},
    domain::scanresult::{layer::Layer, scan_result::ScanResult, severity::Severity},
    infra::parse_dockerfile,
};

use super::LspCommand;

pub struct BuildAndScanCommand<'a, C, B: ?Sized, S: ?Sized>
where
    B: ImageBuilder,
    S: ImageScanner,
{
    image_builder: &'a B,
    image_scanner: &'a S,
    interactor: &'a LspInteractor<C>,
    location: Location,
}

impl<'a, C, B: ?Sized, S: ?Sized> BuildAndScanCommand<'a, C, B, S>
where
    B: ImageBuilder,
    S: ImageScanner,
{
    pub fn new(
        image_builder: &'a B,
        image_scanner: &'a S,
        interactor: &'a LspInteractor<C>,
        location: Location,
    ) -> Self {
        Self {
            image_builder,
            image_scanner,
            interactor,
            location,
        }
    }
}

#[async_trait::async_trait]
impl<'a, C, B: ?Sized, S: ?Sized> LspCommand for BuildAndScanCommand<'a, C, B, S>
where
    C: LSPClient + Sync,
    B: ImageBuilder + Sync,
    S: ImageScanner + Sync,
{
    async fn execute(&mut self) -> Result<()> {
        let uri = self.location.uri.as_str();
        let line = self.location.range.start.line;

        let document_text = self
            .interactor
            .read_document_text(uri)
            .await
            .ok_or_else(|| {
                tower_lsp::jsonrpc::Error::internal_error()
                    .with_message("unable to obtain document to scan")
            })?;

        let uri_without_file_path = uri.strip_prefix("file://").ok_or_else(|| {
            tower_lsp::jsonrpc::Error::internal_error()
                .with_message("unable to strip prefix file:// from uri")
        })?;

        self.interactor
            .show_message(
                MessageType::INFO,
                format!("Starting build of {uri_without_file_path}...").as_str(),
            )
            .await;

        let build_result = self
            .image_builder
            .build_image(&PathBuf::from_str(uri_without_file_path).unwrap())
            .await
            .map_err(|e| tower_lsp::jsonrpc::Error::internal_error().with_message(e.to_string()))?;

        self.interactor
            .show_message(
                MessageType::INFO,
                format!(
                    "Temporal image built '{}', starting scan...",
                    &build_result.image_name
                )
                .as_str(),
            )
            .await;

        let scan_result = self
            .image_scanner
            .scan_image(&build_result.image_name)
            .await
            .map_err(|e| tower_lsp::jsonrpc::Error::internal_error().with_message(e.to_string()))?;

        self.interactor
            .show_message(
                MessageType::INFO,
                format!("Finished scan of {}.", &build_result.image_name).as_str(),
            )
            .await;

        let diagnostic = diagnostic_for_image(line, &document_text, &scan_result);
        let (diagnostics_per_layer, docs_per_layer) =
            diagnostics_for_layers(&document_text, &scan_result)?;

        self.interactor.remove_diagnostics(uri).await;
        self.interactor
            .append_document_diagnostics(uri, &[diagnostic])
            .await;
        self.interactor
            .append_document_diagnostics(uri, &diagnostics_per_layer)
            .await;
        self.interactor
            .append_documentation(
                uri,
                self.location.range,
                MarkdownData::from(scan_result).to_string(),
            )
            .await;
        for (range, docs) in docs_per_layer {
            self.interactor.append_documentation(uri, range, docs).await;
        }
        self.interactor.publish_all_diagnostics().await
    }
}

pub type LayerScanResult = (Vec<Diagnostic>, Vec<(Range, String)>);

pub fn diagnostics_for_layers(
    document_text: &str,
    scan_result: &ScanResult,
) -> Result<LayerScanResult> {
    let instructions = parse_dockerfile(document_text);
    let layers = &scan_result.layers();

    let mut instr_idx = instructions.len().checked_sub(1);
    let mut layer_idx = layers.len().checked_sub(1);

    let mut diagnostics = Vec::new();
    let mut docs = Vec::new();

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
            docs.push((
                instr.range,
                MarkdownLayerData::from(layer.clone()).to_string(),
            ));

            fill_vulnerability_hints_for_layer(layer, instr.range, &mut diagnostics)
        }
    }

    Ok((diagnostics, docs))
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
            "Vulnerabilities found: {} Critical, {} High, {} Medium, {} Low, {} Negligible",
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
