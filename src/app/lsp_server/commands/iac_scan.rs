use std::collections::HashMap;

use tower_lsp::lsp_types::{Diagnostic, DiagnosticSeverity, MessageType, Range, Url};

use crate::{
    app::{
        DiagnosticsScope, IacScanError, IacScanScope, IacScanner, LSPClient, LspInteractor,
        lsp_server::WithContext,
    },
    domain::iacscanresult::iac_severity::IacSeverity,
};

use super::{IAC_DIAGNOSTIC_SOURCE, LspCommand};

pub struct IacScanCommand<'a, C, S: ?Sized>
where
    S: IacScanner,
{
    iac_scanner: &'a S,
    interactor: &'a LspInteractor<C>,
    scope: IacScanScope,
}

impl<'a, C, S: ?Sized> IacScanCommand<'a, C, S>
where
    S: IacScanner,
{
    pub fn new(iac_scanner: &'a S, interactor: &'a LspInteractor<C>, scope: IacScanScope) -> Self {
        Self {
            iac_scanner,
            interactor,
            scope,
        }
    }
}

#[async_trait::async_trait]
impl<'a, C, S: ?Sized> LspCommand for IacScanCommand<'a, C, S>
where
    C: LSPClient + Sync,
    S: IacScanner + Sync,
{
    async fn execute(&mut self) -> tower_lsp::jsonrpc::Result<()> {
        let path_display = self.scope.path().display().to_string();
        self.interactor
            .show_message(
                MessageType::INFO,
                format!("Starting IaC scan of {path_display}...").as_str(),
            )
            .await;

        let scan_result = self
            .iac_scanner
            .scan_iac(&self.scope)
            .await
            .map_err(|e| match &e {
                IacScanError::InvalidConfiguration(_) => {
                    tower_lsp::jsonrpc::Error::invalid_params(e.to_string())
                }
                IacScanError::InternalScannerError(_) => {
                    tower_lsp::jsonrpc::Error::internal_error().with_message(e.to_string())
                }
            })?;

        let findings_count = scan_result.findings.len();
        let mut diagnostics_per_uri: HashMap<String, Vec<Diagnostic>> = HashMap::new();
        for finding in &scan_result.findings {
            for resource in &finding.resources {
                let Some(uri) = self.uri_for_resource_source(&resource.source) else {
                    tracing::warn!(
                        "unable to build a file URI for IaC finding resource: {}",
                        resource.source.display()
                    );
                    continue;
                };

                let diagnostic = Diagnostic {
                    range: Range::default(),
                    severity: Some(diagnostic_severity_for(finding.severity)),
                    message: format!(
                        "{}: {} ({}: {})",
                        finding.name, resource.location, resource.resource_type, resource.name
                    ),
                    source: Some(IAC_DIAGNOSTIC_SOURCE.to_owned()),
                    ..Default::default()
                };

                diagnostics_per_uri.entry(uri).or_default().push(diagnostic);
            }
        }

        // A file scan only refreshes the IaC diagnostics of that file; a directory
        // scan refreshes them for every file under the scanned root — but not
        // beyond it, so results for files outside the root are preserved.
        let scope_key = match &self.scope {
            IacScanScope::File { uri, .. } => uri.to_string(),
            IacScanScope::Directory(root) => Url::from_file_path(root)
                .map(|u| {
                    let uri = String::from(u);
                    // A root of `/` already yields a trailing slash (`file:///`).
                    if uri.ends_with('/') {
                        uri
                    } else {
                        format!("{uri}/")
                    }
                })
                // An empty prefix matches every document: falling back to the
                // previous whole-database refresh is safe, just broader.
                .unwrap_or_default(),
        };
        let scope = match &self.scope {
            IacScanScope::File { .. } => DiagnosticsScope::Document(&scope_key),
            IacScanScope::Directory(_) => DiagnosticsScope::DocumentsWithUriPrefix(&scope_key),
        };
        self.interactor
            .replace_diagnostics_with_source(IAC_DIAGNOSTIC_SOURCE, scope, diagnostics_per_uri)
            .await;
        self.interactor.publish_all_diagnostics().await?;

        self.interactor
            .show_message(
                MessageType::INFO,
                format!("Finished IaC scan of {path_display}: {findings_count} findings.").as_str(),
            )
            .await;

        Ok(())
    }
}

impl<'a, C, S: ?Sized> IacScanCommand<'a, C, S>
where
    S: IacScanner,
{
    /// Diagnostics for the scanned file are published under the exact URI the
    /// client used (a path→URI round-trip is not guaranteed to be byte-identical);
    /// URIs are only synthesized for other files discovered by directory scans.
    fn uri_for_resource_source(&self, source: &std::path::Path) -> Option<String> {
        match &self.scope {
            IacScanScope::File { uri, path } if source == path => Some(uri.to_string()),
            _ => Url::from_file_path(source).map(String::from).ok(),
        }
    }
}

fn diagnostic_severity_for(severity: IacSeverity) -> DiagnosticSeverity {
    match severity {
        IacSeverity::High => DiagnosticSeverity::ERROR,
        IacSeverity::Medium => DiagnosticSeverity::WARNING,
        IacSeverity::Low | IacSeverity::Unknown => DiagnosticSeverity::INFORMATION,
    }
}

#[cfg(test)]
mod tests {
    use super::diagnostic_severity_for;
    use crate::domain::iacscanresult::iac_severity::IacSeverity;
    use tower_lsp::lsp_types::DiagnosticSeverity;

    #[test]
    fn it_maps_iac_severities_to_diagnostic_severities() {
        assert_eq!(
            diagnostic_severity_for(IacSeverity::High),
            DiagnosticSeverity::ERROR
        );
        assert_eq!(
            diagnostic_severity_for(IacSeverity::Medium),
            DiagnosticSeverity::WARNING
        );
        assert_eq!(
            diagnostic_severity_for(IacSeverity::Low),
            DiagnosticSeverity::INFORMATION
        );
        assert_eq!(
            diagnostic_severity_for(IacSeverity::Unknown),
            DiagnosticSeverity::INFORMATION
        );
    }
}
