use serde::Deserialize;

use crate::app::IacScanScope;
use crate::domain::iacscanresult::{
    iac_finding::IacFinding, iac_resource::IacResource, iac_scan_result::IacScanResult,
    iac_severity::IacSeverity,
};

#[derive(Deserialize, Debug, Default)]
pub(super) struct JsonIacScanResultV1 {
    #[serde(default)]
    pub result: JsonIacResult,
}

#[derive(Deserialize, Debug, Default)]
pub(super) struct JsonIacResult {
    #[serde(default)]
    pub findings: Vec<JsonIacFinding>,
}

#[derive(Deserialize, Debug, Default)]
pub(super) struct JsonIacFinding {
    pub name: Option<String>,
    pub severity: Option<String>,
    #[serde(default)]
    pub resources: Vec<JsonIacResource>,
}

#[derive(Deserialize, Debug, Default)]
pub(super) struct JsonIacResource {
    pub source: Option<String>,
    pub location: Option<String>,
    #[serde(rename = "type")]
    pub resource_type: Option<String>,
    pub name: Option<String>,
}

impl JsonIacScanResultV1 {
    /// Converts the raw scanner report into the domain model, resolving each
    /// resource `source` to an absolute path.
    ///
    /// The CLI scanner reports sources relative to the scanned root (with a
    /// leading `/`) when scanning a directory, and an unreliable value when
    /// scanning a single file; in the latter case every finding belongs to the
    /// scanned file itself. This anti-corruption layer hides that contract from
    /// the rest of the application.
    pub(super) fn into_scan_result(self, scope: &IacScanScope) -> IacScanResult {
        let findings = self
            .result
            .findings
            .into_iter()
            .map(|finding| IacFinding {
                name: finding.name.unwrap_or_default(),
                severity: parse_severity(finding.severity.as_deref().unwrap_or_default()),
                resources: finding
                    .resources
                    .into_iter()
                    .filter_map(|resource| {
                        let source = resolve_source(scope, resource.source.as_deref())?;
                        Some(IacResource {
                            source,
                            location: resource.location.unwrap_or_default(),
                            resource_type: resource.resource_type.unwrap_or_default(),
                            name: resource.name.unwrap_or_default(),
                        })
                    })
                    .collect(),
            })
            .collect();

        IacScanResult { findings }
    }
}

fn resolve_source(scope: &IacScanScope, raw_source: Option<&str>) -> Option<std::path::PathBuf> {
    match scope {
        IacScanScope::File { path, .. } => Some(path.clone()),
        IacScanScope::Directory(root) => {
            let raw_source = raw_source.unwrap_or_default().trim_start_matches('/');
            if raw_source.is_empty() {
                // Joining an empty source would attribute the finding to the
                // scanned directory itself, which editors cannot render.
                tracing::warn!("skipping IaC finding resource without a source file");
                return None;
            }
            Some(root.join(raw_source))
        }
    }
}

fn parse_severity(severity: &str) -> IacSeverity {
    match severity.to_ascii_lowercase().as_str() {
        "high" => IacSeverity::High,
        "medium" => IacSeverity::Medium,
        "low" => IacSeverity::Low,
        other => {
            // Unknown severities render as the least severe diagnostic; make the
            // downgrade observable in case the CLI schema ever adds new values.
            tracing::warn!("unknown IaC finding severity reported by the scanner: {other:?}");
            IacSeverity::Unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{JsonIacScanResultV1, parse_severity};
    use crate::app::IacScanScope;
    use crate::domain::iacscanresult::iac_severity::IacSeverity;

    fn parse(json: &str) -> JsonIacScanResultV1 {
        serde_json::from_str(json).unwrap_or_else(|e| panic!("failed to parse: {e}"))
    }

    #[test]
    fn it_parses_a_representative_iac_report_scanned_recursively() {
        let json = r#"{
            "result": {
                "findings": [
                    {
                        "name": "Container runs without memory limits",
                        "severity": "High",
                        "resources": [
                            {
                                "source": "/deployment.yaml",
                                "location": "spec.template.spec.containers[0]",
                                "type": "Deployment",
                                "name": "nginx-deployment"
                            }
                        ]
                    }
                ]
            }
        }"#;

        let scope = IacScanScope::Directory(PathBuf::from("/workspace"));
        let result = parse(json).into_scan_result(&scope);

        assert_eq!(result.findings.len(), 1);
        let finding = &result.findings[0];
        assert_eq!(finding.name, "Container runs without memory limits");
        assert_eq!(finding.severity, IacSeverity::High);
        assert_eq!(finding.resources.len(), 1);
        let resource = &finding.resources[0];
        assert_eq!(resource.source, Path::new("/workspace/deployment.yaml"));
        assert_eq!(resource.location, "spec.template.spec.containers[0]");
        assert_eq!(resource.resource_type, "Deployment");
        assert_eq!(resource.name, "nginx-deployment");
    }

    #[test]
    fn it_resolves_nested_sources_against_the_scanned_root() {
        let json = r#"{"result":{"findings":[{"name":"x","severity":"low","resources":[
            {"source":"subdir/deploy.yaml","location":"l","type":"t","name":"n"}]}]}}"#;

        let scope = IacScanScope::Directory(PathBuf::from("/workspace"));
        let result = parse(json).into_scan_result(&scope);

        assert_eq!(
            result.findings[0].resources[0].source,
            Path::new("/workspace/subdir/deploy.yaml")
        );
    }

    #[test]
    fn it_attributes_all_findings_to_the_scanned_file_in_file_scope() {
        let json = r#"{"result":{"findings":[{"name":"x","severity":"low","resources":[
            {"source":"/whatever-the-cli-says","location":"l","type":"t","name":"n"}]}]}}"#;

        let scope = IacScanScope::File {
            uri: "file:///deployment.yaml"
                .parse()
                .unwrap_or_else(|e| panic!("invalid uri: {e}")),
            path: PathBuf::from("/deployment.yaml"),
        };
        let result = parse(json).into_scan_result(&scope);

        assert_eq!(
            result.findings[0].resources[0].source,
            Path::new("/deployment.yaml")
        );
    }

    #[test]
    fn it_skips_resources_without_a_source_in_directory_scope() {
        let json = r#"{"result":{"findings":[{"name":"x","severity":"low","resources":[
            {"location":"l","type":"t","name":"n"},
            {"source":"","location":"l","type":"t","name":"n"}]}]}}"#;

        let scope = IacScanScope::Directory(PathBuf::from("/workspace"));
        let result = parse(json).into_scan_result(&scope);

        assert!(result.findings[0].resources.is_empty());
    }

    #[test]
    fn it_parses_an_empty_report() {
        let scope = IacScanScope::Directory(PathBuf::from("/workspace"));
        let result = parse("{}").into_scan_result(&scope);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn it_parses_findings_with_missing_fields() {
        let json =
            r#"{"result":{"findings":[{"severity":"weird","resources":[{"source":"/x.yaml"}]}]}}"#;
        let scope = IacScanScope::Directory(PathBuf::from("/workspace"));
        let result = parse(json).into_scan_result(&scope);

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].name, "");
        assert_eq!(result.findings[0].severity, IacSeverity::Unknown);
        assert_eq!(
            result.findings[0].resources[0].source,
            Path::new("/workspace/x.yaml")
        );
        assert_eq!(result.findings[0].resources[0].location, "");
    }

    #[test]
    fn it_parses_severities_case_insensitively() {
        assert_eq!(parse_severity("HIGH"), IacSeverity::High);
        assert_eq!(parse_severity("High"), IacSeverity::High);
        assert_eq!(parse_severity("medium"), IacSeverity::Medium);
        assert_eq!(parse_severity("Low"), IacSeverity::Low);
        assert_eq!(parse_severity("weird"), IacSeverity::Unknown);
        assert_eq!(parse_severity(""), IacSeverity::Unknown);
    }
}
