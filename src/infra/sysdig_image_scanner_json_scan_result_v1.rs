#![allow(dead_code)]

use chrono::{DateTime, NaiveDate, Utc};
use serde::Deserialize;
use std::collections::HashMap;

use crate::domain::scanresult::{
    accepted_risk_reason::AcceptedRiskReason,
    architecture::Architecture,
    operating_system::{Family, OperatingSystem},
    package_type::PackageType,
    scan_result::ScanResult,
    scan_type::ScanType,
    severity::Severity,
};
use semver::Version;

impl From<JsonScanResultV1> for ScanResult {
    fn from(report: JsonScanResultV1) -> Self {
        let mut scan_result = ScanResult::from(&report.result);

        add_layers(&report.result, &mut scan_result);
        add_risk_accepts(&report.result, &mut scan_result);
        add_vulnerabilities(&report.result, &mut scan_result);
        add_packages(&report.result, &mut scan_result);
        add_policies(&report.result, &mut scan_result);

        scan_result
    }
}

fn add_layers(report: &JsonResult, scan_result: &mut ScanResult) {
    report.layers.values().for_each(|json_layer| {
        scan_result.add_layer(
            json_layer.digest.clone(),
            json_layer.index,
            json_layer.size,
            json_layer.command.clone().unwrap_or_default(),
        );
    });
}

fn add_risk_accepts(result: &JsonResult, scan_result: &mut ScanResult) {
    for json_risk in result.risk_accepts.values() {
        scan_result.add_accepted_risk(
            json_risk.id.clone(),
            json_risk.reason.clone().into(),
            json_risk.description.clone(),
            json_risk.expiration_date,
            json_risk.status.eq_ignore_ascii_case("active"),
            json_risk.created_at,
            json_risk.updated_at,
        );
    }
}

fn add_vulnerabilities(result: &JsonResult, scan_result: &mut ScanResult) {
    for v in result.vulnerabilities.values() {
        let fix_version = v.fix_version.as_ref().and_then(|s| Version::parse(s).ok());

        let vuln = scan_result.add_vulnerability(
            v.name.clone(),
            v.severity.clone().into(),
            v.disclosure_date,
            v.solution_date,
            v.exploitable,
            fix_version,
        );

        v.risk_accept_refs
            .as_deref()
            .unwrap_or_default()
            .iter()
            .flat_map(|risk_ref| result.risk_accepts.get(risk_ref))
            .flat_map(|json_risk_accept| scan_result.find_accepted_risk_by_id(&json_risk_accept.id))
            .for_each(|risk_accept| vuln.add_accepted_risk(risk_accept));
    }
}

fn add_packages(result: &JsonResult, scan_result: &mut ScanResult) {
    for json_pkg in result.packages.values() {
        let Some(json_layer) = result.layers.get(&json_pkg.layer_ref) else {
            continue;
        };

        let Some(layer_where_this_package_is_found) =
            scan_result.find_layer_by_digest(&json_layer.digest)
        else {
            continue;
        };

        let Ok(version) = Version::parse(&json_pkg.version) else {
            continue;
        };

        let pkg = scan_result.add_package(
            json_pkg.package_type.clone().into(),
            json_pkg.name.clone(),
            version,
            json_pkg.path.clone(),
            layer_where_this_package_is_found,
        );

        json_pkg
            .vulnerabilities_refs
            .as_deref()
            .unwrap_or_default()
            .iter()
            .flat_map(|json_vuln_ref| result.vulnerabilities.get(json_vuln_ref))
            .flat_map(|json_vuln| scan_result.find_vulnerability_by_cve(&json_vuln.name))
            .for_each(|vuln| pkg.add_vulnerability_found(vuln));

        json_pkg
            .vulnerabilities_refs
            .as_deref()
            .unwrap_or_default()
            .iter()
            .flat_map(|json_vuln_ref| result.vulnerabilities.get(json_vuln_ref))
            .flat_map(|json_vuln| {
                json_vuln
                    .risk_accept_refs
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
            })
            .flat_map(|json_risk_accepted_ref| result.risk_accepts.get(json_risk_accepted_ref))
            .flat_map(|json_risk_accepted| {
                scan_result.find_accepted_risk_by_id(&json_risk_accepted.id)
            })
            .for_each(|risk| pkg.add_accepted_risk(risk));
    }
}

fn add_policies(result: &JsonResult, scan_result: &mut ScanResult) {
    for json_policy in result.policies.evaluations.as_deref().unwrap_or_default() {
        let policy = scan_result.add_policy(
            json_policy.identifier.clone(),
            json_policy.name.clone(),
            json_policy.created_at,
            json_policy.updated_at,
        );

        for json_bundle in json_policy.bundles.as_deref().unwrap_or_default() {
            let policy_bundle = scan_result.add_policy_bundle(
                json_bundle.identifier.clone(),
                json_bundle.name.clone(),
                policy.clone(),
            );

            for json_rule in json_bundle.rules.as_deref().unwrap_or_default() {
                let rule = policy_bundle.add_rule(
                    json_rule.rule_id.clone(),
                    json_rule.description.clone(),
                    json_rule.evaluation_result.as_str().into(),
                );

                for json_failure in json_rule.failures.as_deref().unwrap_or_default() {
                    match json_rule.failure_type.as_str() {
                        "imageConfigFailure" => {
                            rule.add_image_config_failure(json_failure.remediation.clone());
                        }
                        "pkgVulnFailure" => {
                            rule.add_pkg_vuln_failure(failure_message_for(
                                result,
                                &json_failure.package_ref,
                                &json_failure.vulnerability_ref,
                            ));
                        }
                        _ => {}
                    };
                }
            }
        }
    }
}

fn failure_message_for(result: &JsonResult, package_ref: &str, vulnerability_ref: &str) -> String {
    if let Some(package) = result.packages.get(package_ref)
        && let Some(vulnerability) = result.vulnerabilities.get(vulnerability_ref)
    {
        format!(
            "{} found in {} ({})",
            vulnerability.name, package.name, package.version
        )
    } else {
        format!(
            "vuln ref {} found in package ref {}",
            vulnerability_ref, package_ref
        )
    }
}

impl From<&JsonResult> for ScanResult {
    fn from(result: &JsonResult) -> Self {
        let metadata = &result.metadata;
        ScanResult::new(
            ScanType::Docker,
            metadata.pull_string.clone(),
            metadata.image_id.clone(),
            metadata.digest.clone(),
            OperatingSystem::new(os_family_from_str(&metadata.os), metadata.base_os.clone()),
            metadata.size,
            arch_from_str(&metadata.architecture),
            metadata.labels.clone(),
            metadata.created_at,
            result.policies.global_evaluation.as_str().into(),
        )
    }
}

fn os_family_from_str(string: &str) -> Family {
    match string.to_lowercase().as_str() {
        "linux" => Family::Linux,
        "darwin" => Family::Darwin,
        "windows" => Family::Windows,
        _ => Family::Unknown,
    }
}

fn arch_from_str(string: &str) -> Architecture {
    match string.to_lowercase().as_str() {
        "amd64" => Architecture::Amd64,
        "arm64" => Architecture::Arm64,
        _ => Architecture::Unknown,
    }
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct JsonScanResultV1 {
    pub info: JsonInfo,
    pub scanner: JsonScanner,
    pub result: JsonResult,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct JsonScanner {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct JsonInfo {
    #[serde(rename = "scanTime")]
    pub scan_time: DateTime<Utc>,
    #[serde(rename = "scanDuration")]
    pub scan_duration: String,
    #[serde(rename = "resultUrl", default)]
    pub result_url: Option<String>,
    #[serde(rename = "resultId", default)]
    pub result_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ContextType {
    HostAssetToken,
    HostName,
    ImageAssetToken,
    ImageName,
    ImagePrefix,
    ImageSuffix,
    PackageName,
    PackageVersion,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ImageMetadataArchitecture {
    Amd64,
    Arm,
    Arm64,
    Loong64,
    Mips,
    Mips64,
    Mips64le,
    Mipsle,
    N386,
    Ppc64,
    Ppc64le,
    Riscv64,
    S390x,
    Wasm,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "lowercase")]
pub enum JsonSeverity {
    Critical,
    High,
    Low,
    Medium,
    Negligible,
}

impl From<JsonSeverity> for Severity {
    fn from(value: JsonSeverity) -> Self {
        match value {
            JsonSeverity::Critical => Self::Critical,
            JsonSeverity::High => Self::High,
            JsonSeverity::Low => Self::Low,
            JsonSeverity::Medium => Self::Medium,
            JsonSeverity::Negligible => Self::Negligible,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct JsonBundle {
    #[serde(rename = "identifier", default)]
    pub identifier: String,
    #[serde(rename = "name", default)]
    pub name: String,
    #[serde(rename = "rules", default)]
    pub rules: Option<Vec<JsonRule>>,
    #[serde(rename = "type", default)]
    pub bundle_type: String,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct JsonCvssScore {
    pub score: f32,
    #[serde(default)] // FIXME(fede): test this
    pub vector: String,
    pub version: String,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct JsonLayer {
    #[serde(rename = "command", default)]
    pub command: Option<String>,
    #[serde(rename = "digest")]
    pub digest: String,
    #[serde(rename = "index", default)]
    pub index: usize,
    #[serde(rename = "size", default)]
    pub size: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct JsonPackage {
    #[serde(rename = "isRemoved", default)]
    pub is_removed: bool,
    #[serde(rename = "isRunning", default)]
    pub is_running: bool,
    #[serde(rename = "layerRef")]
    pub layer_ref: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "path", default)]
    pub path: String,
    // FIXME(fede): Maybe we could use this to implement a suggestion to fix in the LSP?
    // #[serde(rename = "suggestedFix", default)]
    // pub suggested_fix: Option<String>,
    #[serde(rename = "type", default)]
    pub package_type: JsonPackageType,
    #[serde(rename = "version")]
    pub version: String,
    #[serde(rename = "vulnerabilitiesRefs", default)]
    pub vulnerabilities_refs: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub(super) enum JsonPackageType {
    #[serde(rename = "C#")]
    CSharp,
    #[serde(rename = "golang")]
    Golang,
    #[serde(rename = "java")]
    Java,
    #[serde(rename = "javascript")]
    Javascript,
    #[serde(rename = "os")]
    Os,
    #[serde(rename = "php")]
    Php,
    #[serde(rename = "python")]
    Python,
    #[serde(rename = "ruby")]
    Ruby,
    #[serde(rename = "rust")]
    Rust,
    #[default]
    Unknown,
}

impl From<JsonPackageType> for PackageType {
    fn from(value: JsonPackageType) -> Self {
        match value {
            JsonPackageType::CSharp => Self::CSharp,
            JsonPackageType::Golang => Self::Golang,
            JsonPackageType::Java => Self::Java,
            JsonPackageType::Javascript => Self::Javascript,
            JsonPackageType::Os => Self::Os,
            JsonPackageType::Php => Self::Php,
            JsonPackageType::Python => Self::Python,
            JsonPackageType::Ruby => Self::Ruby,
            JsonPackageType::Rust => Self::Rust,
            JsonPackageType::Unknown => Self::Unknown,
        }
    }
}

#[derive(Debug, Deserialize, Default, Clone)]
pub(super) struct JsonPolicies {
    #[serde(rename = "globalEvaluation", default)]
    pub global_evaluation: String,
    #[serde(rename = "evaluations", default)]
    pub evaluations: Option<Vec<JsonPolicy>>,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct JsonPolicy {
    #[serde(rename = "bundles", default)]
    pub bundles: Option<Vec<JsonBundle>>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "description", default)]
    pub description: String,
    #[serde(rename = "evaluation")]
    pub evaluation: String,
    #[serde(rename = "identifier")]
    pub identifier: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub(super) struct JsonProducer {
    #[serde(rename = "producedAt", default)]
    pub produced_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct JsonRiskAccept {
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "description", default)]
    pub description: String,
    #[serde(rename = "entityType")]
    pub entity_type: String,
    #[serde(rename = "entityValue")]
    pub entity_value: String,
    #[serde(rename = "expirationDate", default)]
    pub expiration_date: Option<NaiveDate>,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "reason", default)]
    pub reason: JsonRiskAcceptReason,
    #[serde(rename = "status")]
    pub status: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub(super) enum JsonRiskAcceptReason {
    RiskOwned,
    RiskTransferred,
    RiskAvoided,
    RiskMitigated,
    RiskNotRelevant,
    Custom,
    #[default]
    Unknown,
}

impl From<JsonRiskAcceptReason> for AcceptedRiskReason {
    fn from(value: JsonRiskAcceptReason) -> Self {
        match value {
            JsonRiskAcceptReason::RiskOwned => Self::RiskOwned,
            JsonRiskAcceptReason::RiskTransferred => Self::RiskTransferred,
            JsonRiskAcceptReason::RiskAvoided => Self::RiskAvoided,
            JsonRiskAcceptReason::RiskMitigated => Self::RiskMitigated,
            JsonRiskAcceptReason::RiskNotRelevant => Self::RiskNotRelevant,
            JsonRiskAcceptReason::Custom => Self::Custom,
            JsonRiskAcceptReason::Unknown => Self::Unknown,
        }
    }
}
#[derive(Debug, Deserialize, Clone)]
pub(super) struct JsonRule {
    #[serde(rename = "description")]
    pub description: String,
    #[serde(rename = "evaluationResult", default)]
    pub evaluation_result: String,
    #[serde(rename = "failureType")]
    pub failure_type: String,
    #[serde(rename = "failures", default)]
    pub failures: Option<Vec<JsonFailure>>,
    #[serde(rename = "ruleId", default)]
    pub rule_id: String,
    #[serde(rename = "ruleType")]
    pub rule_type: String,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct JsonFailure {
    #[serde(rename = "remediation", default)]
    pub remediation: String,
    #[serde(rename = "packageRef", default)]
    pub package_ref: String,
    #[serde(rename = "vulnerabilityRef", default)]
    pub vulnerability_ref: String,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct JsonResult {
    #[serde(rename = "assetType")]
    pub asset_type: String,
    #[serde(rename = "layers", default)]
    pub layers: HashMap<String, JsonLayer>,
    #[serde(rename = "metadata")]
    pub metadata: JsonMetadata,
    #[serde(rename = "packages", default)]
    pub packages: HashMap<String, JsonPackage>,
    #[serde(rename = "policies", default)]
    pub policies: JsonPolicies,
    #[serde(rename = "producer", default)]
    pub producer: JsonProducer,
    #[serde(rename = "riskAccepts", default)]
    pub risk_accepts: HashMap<String, JsonRiskAccept>,
    #[serde(rename = "stage")]
    pub stage: String,
    #[serde(rename = "vulnerabilities", default)]
    pub vulnerabilities: HashMap<String, JsonVulnerability>,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct JsonMetadata {
    #[serde(rename = "architecture")]
    pub architecture: String,
    #[serde(rename = "author")]
    pub author: String,
    #[serde(rename = "baseOs")]
    pub base_os: String,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "digest", default)]
    pub digest: Option<String>,
    #[serde(rename = "imageId")]
    pub image_id: String,
    #[serde(rename = "labels", default)]
    pub labels: HashMap<String, String>,
    #[serde(rename = "os")]
    pub os: String,
    #[serde(rename = "pullString")]
    pub pull_string: String,
    #[serde(rename = "size")]
    pub size: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct JsonVulnerability {
    #[serde(rename = "cvssScore")]
    pub cvss_score: JsonCvssScore,
    #[serde(rename = "disclosureDate", default)]
    pub disclosure_date: NaiveDate,
    #[serde(rename = "exploitable")]
    pub exploitable: bool,
    #[serde(rename = "fixVersion", default)]
    pub fix_version: Option<String>,
    #[serde(rename = "mainProvider", default)]
    pub main_provider: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "packageRef", default)]
    pub package_ref: String,
    #[serde(rename = "riskAcceptRefs", default)]
    pub risk_accept_refs: Option<Vec<String>>,
    #[serde(rename = "severity")]
    pub severity: JsonSeverity,
    #[serde(rename = "solutionDate", default)]
    pub solution_date: Option<NaiveDate>,
}

#[cfg(test)]
mod tests {
    use crate::{
        domain::scanresult::{scan_result::ScanResult, severity::Severity},
        infra::sysdig_image_scanner_json_scan_result_v1::JsonScanResultV1,
    };

    #[test]
    fn it_loads_postgres13() {
        let postgres_13_json = include_bytes!("../../tests/fixtures/scan-results/postgres_13.json");
        let json_scan_result: JsonScanResultV1 = serde_json::from_slice(postgres_13_json).unwrap();

        let scan_result: ScanResult = json_scan_result.clone().into();

        assert_eq!(json_scan_result.result.vulnerabilities.len(), 100);
        assert_eq!(
            scan_result
                .vulnerabilities()
                .iter()
                .filter(|v| v.severity() == Severity::Critical)
                .count(),
            2
        );
        assert_eq!(
            scan_result
                .vulnerabilities()
                .iter()
                .filter(|v| v.severity() == Severity::High)
                .count(),
            3
        );
        assert_eq!(
            scan_result
                .vulnerabilities()
                .iter()
                .filter(|v| v.severity() == Severity::Medium)
                .count(),
            1
        );
        assert_eq!(
            scan_result
                .vulnerabilities()
                .iter()
                .filter(|v| v.severity() == Severity::Low)
                .count(),
            2
        );
        assert_eq!(
            scan_result
                .vulnerabilities()
                .iter()
                .filter(|v| v.severity() == Severity::Negligible)
                .count(),
            32
        );
        // assert_eq!(scan_result.vulnerabilities().len(), 97);
    }

    #[test]
    fn test_handles_layers_without_digest() {
        let postgres_13_json = include_bytes!("../../tests/fixtures/scan-results/postgres_13.json");
        let json_scan_result: JsonScanResultV1 = serde_json::from_slice(postgres_13_json).unwrap();
        let scan_result: ScanResult = json_scan_result.into();

        assert_eq!(
            scan_result.layers().len(),
            25,
            "Should have 25 layers in total"
        );

        let layers_with_digest = scan_result
            .layers()
            .into_iter()
            .filter(|l| l.digest().is_some())
            .count();
        assert_eq!(
            layers_with_digest, 14,
            "Should have 14 layers with a digest"
        );

        let layers_without_digest = scan_result
            .layers()
            .into_iter()
            .filter(|l| l.digest().is_none())
            .count();
        assert_eq!(
            layers_without_digest, 11,
            "Should have 11 layers without a digest"
        );

        assert!(
            scan_result.find_layer_by_digest("").is_none(),
            "Searching for an empty digest should return None"
        );
        assert!(
            scan_result.find_layer_by_digest("   ").is_none(),
            "Searching for a whitespace digest should return None"
        );

        let digest = "sha256:04d52f0a5b32b0f627bbd4427a0374f0a8d2d409dbbfda0099d89b87c774df36";
        let found_layer = scan_result.find_layer_by_digest(digest);
        assert!(found_layer.is_some(), "Should find layer by valid digest");
        assert_eq!(found_layer.unwrap().digest(), Some(digest));
    }
}
