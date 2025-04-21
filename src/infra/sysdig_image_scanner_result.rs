#![allow(dead_code)]

use chrono::{DateTime, NaiveDate, Utc};
use serde::Deserialize;
use std::collections::HashMap;

use crate::app::{self, ImageScanResult, LayerScanResult, VulnerabilityEntry};

impl From<SysdigImageScannerReport> for ImageScanResult {
    fn from(report: SysdigImageScannerReport) -> Self {
        // a) Todas las vulnerabilidades de la imagen
        let vulnerabilities = report
            .result
            .as_ref()
            .and_then(|r| r.vulnerabilities.as_ref())
            .map(|map| {
                map.iter()
                    .map(|(id, v)| VulnerabilityEntry {
                        id: id.clone(),
                        severity: severity_for(&v.severity),
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        // b) Cumplimiento de políticas
        let is_compliant = report
            .result
            .as_ref()
            .and_then(|r| r.policies.as_ref())
            .and_then(|p| p.global_evaluation.as_ref())
            .map(|e| e == &PoliciesGlobalEvaluation::Accepted)
            .unwrap_or(false);

        // c) Por capas
        let layers = layers_for_result(report.result.as_ref().unwrap());

        ImageScanResult {
            vulnerabilities,
            is_compliant,
            layers: layers.unwrap_or_default(),
        }
    }
}

fn layers_for_result(scan: &ScanResultResponse) -> Option<Vec<LayerScanResult>> {
    // Agrupa cada vuln por digest de capa
    let mut layer_map: HashMap<&String, Vec<VulnerabilityEntry>> = HashMap::new();
    for (vuln_id, vuln) in scan.vulnerabilities.as_ref()? {
        if let (Some(_pkg), Some(layer_ref)) = (
            vuln.package_ref.as_ref().and_then(|r| scan.packages.get(r)),
            scan.packages
                .get(vuln.package_ref.as_ref()?)?
                .layer_ref
                .as_ref(),
        ) {
            layer_map
                .entry(layer_ref)
                .or_default()
                .push(VulnerabilityEntry {
                    id: vuln_id.clone(),
                    severity: severity_for(&vuln.severity),
                });
        }
    }

    Some(
        scan.layers
            .as_ref()?
            .iter()
            .map(|(_, layer)| {
                let entries = layer_map.get(&layer.digest).cloned().unwrap_or_default();
                LayerScanResult {
                    layer_instruction: layer
                        .command
                        .as_deref()
                        .unwrap_or_default()
                        .strip_prefix("/bin/sh -c #(nop) ")
                        .unwrap_or_default()
                        .split_whitespace()
                        .next()
                        .unwrap_or_default()
                        .to_uppercase(),
                    layer_text: layer.command.clone().unwrap_or_default(),
                    vulnerabilities: entries,
                }
            })
            .collect(),
    )
}

fn severity_for(sev: &VulnSeverity) -> app::VulnSeverity {
    match sev {
        VulnSeverity::Critical => app::VulnSeverity::Critical,
        VulnSeverity::High => app::VulnSeverity::High,
        VulnSeverity::Medium => app::VulnSeverity::Medium,
        VulnSeverity::Low => app::VulnSeverity::Low,
        VulnSeverity::Negligible => app::VulnSeverity::Negligible,
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct SysdigImageScannerReport {
    pub info: Option<Info>,
    pub scanner: Option<Scanner>,
    pub result: Option<ScanResultResponse>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Scanner {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct Info {
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
pub enum BundleType {
    Custom,
    Predefined,
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

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PoliciesGlobalEvaluation {
    Accepted,
    Failed,
    NoPolicy,
    Passed,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PolicyEvaluationEvaluation {
    Accepted,
    Failed,
    NoPolicy,
    Passed,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PolicyEvaluationResult {
    Accepted,
    Failed,
    NoPolicy,
    NotApplicable,
    Passed,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RiskAcceptanceDefinitionStatus {
    Active,
    Expired,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RuleEvaluationResult {
    Accepted,
    Failed,
    NotApplicable,
    Passed,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RuleFailureType {
    ImageConfigFailure,
    PkgVulnFailure,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanResultResponseAssetType {
    ContainerImage,
    Host,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanResultResponseStage {
    Pipeline,
    Registry,
    Runtime,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub enum VulnSeverity {
    Critical,
    High,
    Low,
    Medium,
    Negligible,
}

pub type CreatedAt = String;
pub type UpdatedAt = String;
pub type Cursor = String;

#[derive(Debug, Deserialize)]
pub(super) struct BaseImage {
    #[serde(rename = "pullStrings", default)]
    pub pull_strings: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Bundle {
    #[serde(rename = "identifier", default)]
    pub identifier: Option<String>,
    #[serde(rename = "name", default)]
    pub name: Option<String>,
    #[serde(rename = "rules", default)]
    pub rules: Option<Vec<Rule>>,
    // “type” is a reserved word in Rust, so we need to rename it here.
    #[serde(rename = "type", default)]
    pub type_: Option<BundleType>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Context {
    #[serde(rename = "type")]
    pub type_: ContextType,
    #[serde(rename = "value")]
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct CvssScore {
    pub score: f32,
    #[serde(default)]
    pub vector: Option<String>,
    pub version: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct Error {
    #[serde(rename = "details", default)]
    pub details: Option<Vec<serde_json::Value>>,
    #[serde(rename = "message", default)]
    pub message: Option<String>,
    #[serde(rename = "type", default)]
    pub type_: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Exploit {
    pub links: Vec<String>,
    #[serde(rename = "publicationDate", default)]
    pub publication_date: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub(super) struct HostMetadata {
    #[serde(rename = "architecture", default)]
    pub architecture: Option<String>,
    #[serde(rename = "hostId", default)]
    pub host_id: Option<String>,
    #[serde(rename = "hostName", default)]
    pub host_name: Option<String>,
    #[serde(rename = "os")]
    pub os: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct ImageConfigFailure {
    pub arguments: HashMap<String, serde_json::Value>,
    #[serde(rename = "description", default)]
    pub description: Option<String>,
    #[serde(rename = "packageRef", default)]
    pub package_ref: Option<String>,
    pub remediation: String,
    #[serde(rename = "riskAcceptRefs", default)]
    pub risk_accept_refs: Option<Vec<String>>,
    #[serde(rename = "vulnerabilityRef", default)]
    pub vulnerability_ref: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ImageMetadata {
    #[serde(rename = "architecture", default)]
    pub architecture: Option<ImageMetadataArchitecture>,
    #[serde(rename = "author", default)]
    pub author: Option<String>,
    #[serde(rename = "baseOs")]
    pub base_os: String,
    #[serde(rename = "createdAt")]
    pub created_at: CreatedAt,
    #[serde(rename = "digest", default)]
    pub digest: Option<String>,
    #[serde(rename = "imageId")]
    pub image_id: String,
    #[serde(rename = "labels", default)]
    pub labels: Option<HashMap<String, serde_json::Value>>,
    #[serde(rename = "os")]
    pub os: String,
    #[serde(rename = "pullString")]
    pub pull_string: String,
    #[serde(rename = "size")]
    pub size: i64,
}

#[derive(Debug, Deserialize)]
pub(super) struct Layer {
    #[serde(rename = "baseImagesRef", default)]
    pub base_images_ref: Option<Vec<String>>,
    #[serde(rename = "command", default)]
    pub command: Option<String>,
    #[serde(rename = "digest")]
    pub digest: String,
    #[serde(rename = "index", default)]
    pub index: Option<i64>,
    #[serde(rename = "size", default)]
    pub size: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Package {
    #[serde(rename = "isRemoved", default)]
    pub is_removed: Option<bool>,
    #[serde(rename = "isRunning", default)]
    pub is_running: Option<bool>,
    #[serde(rename = "layerRef", default)]
    pub layer_ref: Option<String>,
    #[serde(rename = "license", default)]
    pub license: Option<String>,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "path", default)]
    pub path: Option<String>,
    #[serde(rename = "suggestedFix", default)]
    pub suggested_fix: Option<String>,
    #[serde(rename = "type")]
    pub package_type: String,
    #[serde(rename = "version")]
    pub version: String,
    #[serde(rename = "vulnerabilitiesRefs", default)]
    pub vulnerabilities_refs: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Page {
    #[serde(rename = "next", default)]
    pub next: Option<String>,
    #[serde(rename = "total", default)]
    pub total: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub(super) struct PipelineResult {
    #[serde(rename = "createdAt", default)]
    pub created_at: Option<CreatedAt>,
    #[serde(rename = "imageId", default)]
    pub image_id: Option<String>,
    #[serde(rename = "policyEvaluationResult", default)]
    pub policy_evaluation_result: Option<PolicyEvaluationResult>,
    #[serde(rename = "pullString", default)]
    pub pull_string: Option<String>,
    #[serde(rename = "resultId", default)]
    pub result_id: Option<String>,
    #[serde(rename = "vulnTotalBySeverity", default)]
    pub vuln_total_by_severity: Option<VulnTotalBySeverity>,
}

#[derive(Debug, Deserialize)]
pub(super) struct PkgVulnFailure {
    pub description: String,
    #[serde(rename = "packageRef", default)]
    pub package_ref: Option<String>,
    #[serde(rename = "riskAcceptRefs", default)]
    pub risk_accept_refs: Option<Vec<String>>,
    #[serde(rename = "vulnerabilityRef", default)]
    pub vulnerability_ref: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Policies {
    #[serde(rename = "evaluations", default)]
    pub evaluations: Option<Vec<PolicyEvaluation>>,
    #[serde(rename = "globalEvaluation", default)]
    pub global_evaluation: Option<PoliciesGlobalEvaluation>,
}

#[derive(Debug, Deserialize)]
pub(super) struct PolicyEvaluation {
    #[serde(rename = "bundles", default)]
    pub bundles: Option<Vec<Bundle>>,
    #[serde(rename = "createdAt")]
    pub created_at: CreatedAt,
    #[serde(rename = "description", default)]
    pub description: Option<String>,
    #[serde(rename = "evaluation")]
    pub evaluation: PolicyEvaluationEvaluation,
    #[serde(rename = "identifier")]
    pub identifier: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: UpdatedAt,
}

#[derive(Debug, Deserialize)]
pub(super) struct Predicate {
    #[serde(rename = "extra", default)]
    pub extra: Option<HashMap<String, serde_json::Value>>,
    #[serde(rename = "type", default)]
    pub type_: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Producer {
    #[serde(rename = "producedAt", default)]
    pub produced_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub(super) struct RiskAcceptanceDefinition {
    pub context: Vec<Context>,
    #[serde(rename = "createdAt")]
    pub created_at: CreatedAt,
    #[serde(rename = "description", default)]
    pub description: Option<String>,
    #[serde(rename = "entityType")]
    pub entity_type: String,
    #[serde(rename = "entityValue")]
    pub entity_value: String,
    #[serde(rename = "expirationDate", default)]
    pub expiration_date: Option<NaiveDate>,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "reason", default)]
    pub reason: Option<String>,
    #[serde(rename = "status")]
    pub status: RiskAcceptanceDefinitionStatus,
    #[serde(rename = "updatedAt")]
    pub updated_at: UpdatedAt,
}

#[derive(Debug, Deserialize)]
pub(super) struct Rule {
    #[serde(rename = "description")]
    pub description: String,
    #[serde(rename = "evaluationResult", default)]
    pub evaluation_result: Option<RuleEvaluationResult>,
    #[serde(rename = "failureType")]
    pub failure_type: RuleFailureType,
    #[serde(rename = "failures", default)]
    pub failures: Option<Vec<serde_json::Value>>,
    #[serde(rename = "predicates", default)]
    pub predicates: Option<Vec<Predicate>>,
    #[serde(rename = "ruleId", default)]
    pub rule_id: Option<String>,
    #[serde(rename = "ruleType")]
    pub rule_type: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct ScanResultResponse {
    #[serde(rename = "assetType")]
    pub asset_type: ScanResultResponseAssetType,
    #[serde(rename = "baseImages")]
    pub base_images: Option<HashMap<String, BaseImage>>,
    #[serde(rename = "layers", default)]
    pub layers: Option<HashMap<String, Layer>>,
    #[serde(rename = "metadata")]
    pub metadata: serde_json::Value,
    #[serde(rename = "packages")]
    pub packages: HashMap<String, Package>,
    #[serde(rename = "policies", default)]
    pub policies: Option<Policies>,
    #[serde(rename = "producer", default)]
    pub producer: Option<Producer>,
    #[serde(rename = "riskAccepts", default)]
    pub risk_accepts: Option<HashMap<String, RiskAcceptanceDefinition>>,
    #[serde(rename = "stage")]
    pub stage: ScanResultResponseStage,
    #[serde(rename = "vulnerabilities", default)]
    pub vulnerabilities: Option<HashMap<String, Vuln>>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Vuln {
    #[serde(rename = "cisaKev", default)]
    pub cisa_kev: Option<HashMap<String, serde_json::Value>>,
    #[serde(rename = "cvssScore")]
    pub cvss_score: CvssScore,
    #[serde(rename = "disclosureDate", default)]
    pub disclosure_date: Option<NaiveDate>,
    #[serde(rename = "exploit", default)]
    pub exploit: Option<Exploit>,
    #[serde(rename = "exploitable")]
    pub exploitable: bool,
    #[serde(rename = "fixVersion", default)]
    pub fix_version: Option<String>,
    #[serde(rename = "mainProvider", default)]
    pub main_provider: Option<String>,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "packageRef", default)]
    pub package_ref: Option<String>,
    #[serde(rename = "providersMetadata")]
    pub providers_metadata: HashMap<String, serde_json::Value>,
    #[serde(rename = "riskAcceptRefs")]
    pub risk_accept_refs: Option<Vec<String>>,
    #[serde(rename = "severity")]
    pub severity: VulnSeverity,
    #[serde(rename = "solutionDate", default)]
    pub solution_date: Option<NaiveDate>,
}

#[derive(Debug, Deserialize)]
pub(super) struct VulnTotalBySeverity {
    #[serde(rename = "critical", default)]
    pub critical: Option<i32>,
    #[serde(rename = "high", default)]
    pub high: Option<i32>,
    #[serde(rename = "low", default)]
    pub low: Option<i32>,
    #[serde(rename = "medium", default)]
    pub medium: Option<i32>,
    #[serde(rename = "negligible", default)]
    pub negligible: Option<i32>,
}

pub type BadRequest = Error;
pub type Conflict = Error;
pub type Forbidden = Error;
pub type InternalServerError = Error;
pub type TooManyRequests = Error;
pub type Unauthorized = Error;

#[derive(Debug, Deserialize)]
pub(super) struct GetSecureVulnerabilityV1PipelineResultsParams {
    #[serde(rename = "cursor", default)]
    pub cursor: Option<Cursor>,
    #[serde(rename = "limit", default)]
    pub limit: Option<i64>,
    #[serde(rename = "filter", default)]
    pub filter: Option<String>,
}
