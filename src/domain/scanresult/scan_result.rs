use crate::domain::scanresult::accepted_risk::AcceptedRisk;
use crate::domain::scanresult::accepted_risk_reason::AcceptedRiskReason;
use crate::domain::scanresult::architecture::Architecture;
use crate::domain::scanresult::evaluation_result::EvaluationResult;
use crate::domain::scanresult::layer::Layer;
use crate::domain::scanresult::metadata::Metadata;
use crate::domain::scanresult::operating_system::OperatingSystem;
use crate::domain::scanresult::package::Package;
use crate::domain::scanresult::package_type::PackageType;
use crate::domain::scanresult::policy::Policy;
use crate::domain::scanresult::policy_bundle::PolicyBundle;
use crate::domain::scanresult::scan_type::ScanType;
use crate::domain::scanresult::severity::Severity;
use crate::domain::scanresult::vulnerability::Vulnerability;
use chrono::{DateTime, NaiveDate, Utc};
use itertools::Itertools;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(PartialEq, Eq, Clone)]
pub struct ScanResult {
    scan_type: ScanType,
    metadata: Metadata,
    layers: Vec<Arc<Layer>>,
    packages: HashMap<Arc<Package>, ()>,
    vulnerabilities: HashMap<String, Arc<Vulnerability>>,
    policies: HashMap<String, Arc<Policy>>,
    policy_bundles: HashMap<String, Arc<PolicyBundle>>,
    accepted_risks: HashMap<String, Arc<AcceptedRisk>>,
    global_evaluation: EvaluationResult,
}

impl ScanResult {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scan_type: ScanType,
        pull_string: String,
        image_id: String,
        digest: Option<String>,
        base_os: OperatingSystem,
        size_in_bytes: u64,
        architecture: Architecture,
        labels: HashMap<String, String>,
        created_at: DateTime<Utc>,
        global_evaluation: EvaluationResult,
    ) -> Self {
        Self {
            scan_type,
            metadata: Metadata::new(
                pull_string,
                image_id,
                digest,
                base_os,
                size_in_bytes,
                architecture,
                labels,
                created_at,
            ),
            layers: Vec::new(),
            packages: HashMap::new(),
            vulnerabilities: HashMap::new(),
            policies: HashMap::new(),
            policy_bundles: HashMap::new(),
            accepted_risks: HashMap::new(),
            global_evaluation,
        }
    }

    pub fn scan_type(&self) -> &ScanType {
        &self.scan_type
    }

    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    pub fn add_layer(
        &mut self,
        digest: String,
        index: usize,
        size: Option<u64>,
        command: String,
    ) -> Arc<Layer> {
        let layer = Arc::new(Layer::new(digest.clone(), index, size, command));
        self.layers.push(layer.clone());
        layer
    }

    pub fn find_layer_by_digest(&self, digest: &str) -> Option<Arc<Layer>> {
        if digest.trim().is_empty() {
            return None;
        }

        self.layers
            .iter()
            .find(|l| l.digest() == Some(digest))
            .cloned()
    }

    pub fn layers(&self) -> Vec<Arc<Layer>> {
        self.layers
            .iter()
            .sorted_by(|a, b| a.index().cmp(&b.index()))
            .cloned()
            .collect()
    }

    pub fn add_package(
        &mut self,
        package_type: PackageType,
        name: String,
        version: String,
        path: String,
        found_in_layer: Arc<Layer>,
    ) -> Arc<Package> {
        let a_package = Arc::new(Package::new(
            package_type,
            name.clone(),
            version.clone(),
            path.clone(),
            found_in_layer.clone(),
        ));
        found_in_layer.add_package(a_package.clone());

        self.packages
            .entry(a_package)
            .insert_entry(())
            .key()
            .clone()
    }

    pub fn packages(&self) -> Vec<Arc<Package>> {
        self.packages.keys().cloned().collect()
    }

    pub fn add_vulnerability(
        &mut self,
        cve: String,
        severity: Severity,
        disclosure_date: NaiveDate,
        solution_date: Option<NaiveDate>,
        exploitable: bool,
        fix_version: Option<String>,
    ) -> Arc<Vulnerability> {
        self.vulnerabilities
            .entry(cve.clone())
            .or_insert_with(|| {
                Arc::new(Vulnerability::new(
                    cve,
                    severity,
                    disclosure_date,
                    solution_date,
                    exploitable,
                    fix_version,
                ))
            })
            .clone()
    }

    pub fn find_vulnerability_by_cve(&self, cve: &str) -> Option<Arc<Vulnerability>> {
        self.vulnerabilities.get(cve).cloned()
    }

    pub fn vulnerabilities(&self) -> Vec<Arc<Vulnerability>> {
        self.vulnerabilities.values().cloned().collect()
    }

    pub fn add_policy(
        &mut self,
        id: String,
        name: String,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Arc<Policy> {
        self.policies
            .entry(id.clone())
            .or_insert_with(|| Arc::new(Policy::new(id, name, created_at, updated_at)))
            .clone()
    }

    pub fn find_policy_by_id(&self, id: &str) -> Option<Arc<Policy>> {
        self.policies.get(id).cloned()
    }

    pub fn policies(&self) -> Vec<Arc<Policy>> {
        self.policies.values().cloned().collect()
    }

    pub fn add_policy_bundle(
        &mut self,
        id: String,
        name: String,
        policy: Arc<Policy>,
    ) -> Arc<PolicyBundle> {
        let policy_bundle = self
            .policy_bundles
            .entry(id.clone())
            .or_insert_with(|| Arc::new(PolicyBundle::new(id, name)))
            .clone();
        policy_bundle.add_policy(policy);
        policy_bundle
    }

    pub fn find_policy_bundle_by_id(&self, id: &str) -> Option<Arc<PolicyBundle>> {
        self.policy_bundles.get(id).cloned()
    }

    pub fn policy_bundles(&self) -> Vec<Arc<PolicyBundle>> {
        self.policy_bundles.values().cloned().collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_accepted_risk(
        &mut self,
        id: String,
        reason: AcceptedRiskReason,
        description: String,
        expiration_date: Option<NaiveDate>,
        is_active: bool,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Arc<AcceptedRisk> {
        self.accepted_risks
            .entry(id.clone())
            .or_insert_with(|| {
                Arc::new(AcceptedRisk::new(
                    id,
                    reason,
                    description,
                    expiration_date,
                    is_active,
                    created_at,
                    updated_at,
                ))
            })
            .clone()
    }

    pub fn find_accepted_risk_by_id(&self, id: &str) -> Option<Arc<AcceptedRisk>> {
        self.accepted_risks.get(id).cloned()
    }

    pub fn accepted_risks(&self) -> Vec<Arc<AcceptedRisk>> {
        self.accepted_risks.values().cloned().collect()
    }

    pub fn evaluation_result(&self) -> EvaluationResult {
        self.global_evaluation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::scanresult::architecture::Architecture;
    use crate::domain::scanresult::operating_system::{Family, OperatingSystem};
    use crate::domain::scanresult::package_type::PackageType;
    use crate::domain::scanresult::scan_type::ScanType;
    use crate::domain::scanresult::severity::Severity;
    use chrono::Utc;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn create_scan_result() -> ScanResult {
        ScanResult::new(
            ScanType::Docker,
            "alpine:latest".to_string(),
            "sha256:12345".to_string(),
            Some("sha256:67890".to_string()),
            OperatingSystem::new(Family::Linux, "alpine:3.18".to_string()),
            123456,
            Architecture::Amd64,
            HashMap::new(),
            Utc::now(),
            EvaluationResult::Failed,
        )
    }

    #[test]
    fn new_creates_scan_result() {
        let scan_result = create_scan_result();
        assert_eq!(scan_result.scan_type(), &ScanType::Docker);
        assert_eq!(scan_result.metadata().pull_string(), "alpine:latest");
        assert!(scan_result.layers().is_empty());
        assert!(scan_result.packages().is_empty());
        assert!(scan_result.vulnerabilities().is_empty());
        assert!(scan_result.policies().is_empty());
        assert!(scan_result.policy_bundles().is_empty());
        assert!(scan_result.accepted_risks().is_empty());
    }

    #[test]
    fn add_and_find_layer() {
        let mut scan_result = create_scan_result();
        let layer =
            scan_result.add_layer("sha256:abc".to_string(), 0, Some(100), "CMD".to_string());

        assert_eq!(scan_result.layers().len(), 1);
        assert_eq!(scan_result.layers()[0], layer);

        let found_layer = scan_result.find_layer_by_digest("sha256:abc");
        assert_eq!(found_layer, Some(layer));

        let not_found_layer = scan_result.find_layer_by_digest("sha256:def");
        assert!(not_found_layer.is_none());
    }

    #[test]
    fn add_package_test() {
        let mut scan_result = create_scan_result();
        let layer =
            scan_result.add_layer("sha256:abc".to_string(), 0, Some(100), "CMD".to_string());
        let package = scan_result.add_package(
            PackageType::Os,
            "musl".to_string(),
            "1.2.3".to_string(),
            "/lib/ld-musl-x86_64.so.1".to_string(),
            layer.clone(),
        );

        assert_eq!(scan_result.packages().len(), 1);
        assert_eq!(scan_result.packages()[0], package);
        assert_eq!(layer.packages().len(), 1);
        assert_eq!(layer.packages()[0], package);
        assert_eq!(package.found_in_layer(), &layer);
        assert_eq!(package.vulnerabilities().len(), 0);
        assert_eq!(package.accepted_risks().len(), 0);
    }

    #[test]
    fn add_and_find_vulnerability() {
        let mut scan_result = create_scan_result();
        let vuln = scan_result.add_vulnerability(
            "CVE-2023-1234".to_string(),
            Severity::High,
            Utc::now().naive_utc().date(),
            None,
            false,
            Some("1.2.4".to_string()),
        );

        assert_eq!(scan_result.vulnerabilities().len(), 1);
        assert_eq!(scan_result.vulnerabilities()[0], vuln);

        let found_vuln = scan_result.find_vulnerability_by_cve("CVE-2023-1234");
        assert_eq!(found_vuln, Some(vuln));

        let not_found_vuln = scan_result.find_vulnerability_by_cve("CVE-2023-5678");
        assert!(not_found_vuln.is_none());
    }

    #[test]
    fn mix_vulns_and_packages() {
        let mut scan_result = create_scan_result();
        let layer =
            scan_result.add_layer("sha256:abc".to_string(), 0, Some(100), "CMD".to_string());
        let package = scan_result.add_package(
            PackageType::Os,
            "musl".to_string(),
            "1.2.3".to_string(),
            "/lib/ld-musl-x86_64.so.1".to_string(),
            layer.clone(),
        );
        let vuln = scan_result.add_vulnerability(
            "CVE-2023-1234".to_string(),
            Severity::High,
            Utc::now().naive_utc().date(),
            None,
            false,
            Some("1.2.4".to_string()),
        );

        package.add_vulnerability_found(vuln.clone());

        assert!(vuln.found_in_packages().contains(&package));
        assert!(vuln.found_in_layers().contains(&layer));
        assert!(package.vulnerabilities().contains(&vuln));
        assert!(layer.vulnerabilities().contains(&vuln));
    }

    #[test]
    fn add_and_find_policy() {
        let mut scan_result = create_scan_result();
        let now = Utc::now();
        let policy =
            scan_result.add_policy("policy-1".to_string(), "My Policy".to_string(), now, now);

        assert_eq!(scan_result.policies().len(), 1);
        assert_eq!(scan_result.policies()[0], policy);

        let found_policy = scan_result.find_policy_by_id("policy-1");
        assert_eq!(found_policy, Some(policy));

        let not_found_policy = scan_result.find_policy_by_id("policy-2");
        assert!(not_found_policy.is_none());
    }

    #[test]
    fn add_and_find_policy_bundle() {
        let mut scan_result = create_scan_result();
        let policy = scan_result.add_policy(
            "policy-1".to_string(),
            "My Policy".to_string(),
            Utc::now(),
            Utc::now(),
        );
        let bundle = scan_result.add_policy_bundle(
            "bundle-1".to_string(),
            "My Bundle".to_string(),
            policy.clone(),
        );

        assert_eq!(scan_result.policy_bundles().len(), 1);
        assert_eq!(scan_result.policy_bundles()[0], bundle);
        assert!(bundle.found_in_policies().contains(&policy));

        let found_bundle = scan_result.find_policy_bundle_by_id("bundle-1");
        assert_eq!(found_bundle, Some(bundle));

        let not_found_bundle = scan_result.find_policy_bundle_by_id("bundle-2");
        assert!(not_found_bundle.is_none());
    }

    #[test]
    fn add_and_find_accepted_risk() {
        let mut scan_result = create_scan_result();
        let risk = scan_result.add_accepted_risk(
            "risk-1".to_string(),
            AcceptedRiskReason::RiskMitigated,
            "description".to_string(),
            None,
            true,
            Utc::now(),
            Utc::now(),
        );

        assert_eq!(scan_result.accepted_risks().len(), 1);
        assert_eq!(scan_result.accepted_risks()[0], risk);

        let found_risk = scan_result.find_accepted_risk_by_id("risk-1");
        assert_eq!(found_risk, Some(risk));

        let not_found_risk = scan_result.find_accepted_risk_by_id("risk-2");
        assert!(not_found_risk.is_none());
    }

    #[test]
    fn mix_accepted_risks_and_vulns() {
        let mut scan_result = create_scan_result();
        let risk = scan_result.add_accepted_risk(
            "risk-1".to_string(),
            AcceptedRiskReason::RiskMitigated,
            "description".to_string(),
            None,
            true,
            Utc::now(),
            Utc::now(),
        );
        let vuln = scan_result.add_vulnerability(
            "CVE-2023-1234".to_string(),
            Severity::High,
            Utc::now().naive_utc().date(),
            None,
            false,
            Some("1.2.4".to_string()),
        );

        vuln.add_accepted_risk(risk.clone());

        assert!(vuln.accepted_risks().contains(&risk));
        assert!(risk.assigned_to_vulnerabilities().contains(&vuln));
    }

    #[test]
    fn mix_accepted_risks_and_packages() {
        let mut scan_result = create_scan_result();
        let risk = scan_result.add_accepted_risk(
            "risk-1".to_string(),
            AcceptedRiskReason::RiskMitigated,
            "description".to_string(),
            None,
            true,
            Utc::now(),
            Utc::now(),
        );
        let layer =
            scan_result.add_layer("sha256:abc".to_string(), 0, Some(100), "CMD".to_string());
        let package = scan_result.add_package(
            PackageType::Os,
            "musl".to_string(),
            "1.2.3".to_string(),
            "/lib/ld-musl-x86_64.so.1".to_string(),
            layer.clone(),
        );

        package.add_accepted_risk(risk.clone());

        assert!(package.accepted_risks().contains(&risk));
        assert!(risk.assigned_to_packages().contains(&package));
    }

    #[test]
    fn evaluation_result_passed() {
        let mut scan_result = ScanResult::new(
            ScanType::Docker,
            "alpine:latest".to_string(),
            "sha256:12345".to_string(),
            Some("sha256:67890".to_string()),
            OperatingSystem::new(Family::Linux, "alpine:3.18".to_string()),
            123456,
            Architecture::Amd64,
            HashMap::new(),
            Utc::now(),
            EvaluationResult::Passed,
        );
        let now = Utc::now();
        let policy =
            scan_result.add_policy("policy-1".to_string(), "My Policy".to_string(), now, now);
        // No failures added, so it should pass
        assert_eq!(policy.evaluation_result(), EvaluationResult::Passed);
        assert_eq!(scan_result.evaluation_result(), EvaluationResult::Passed);
    }

    #[test]
    fn evaluation_result_failed() {
        let mut scan_result = create_scan_result();
        let now = Utc::now();
        let policy =
            scan_result.add_policy("policy-1".to_string(), "My Policy".to_string(), now, now);
        let bundle = scan_result.add_policy_bundle(
            "bundle-1".to_string(),
            "My Bundle".to_string(),
            policy.clone(),
        );
        bundle.add_rule(
            "rule-1".to_string(),
            "rule name".to_string(),
            EvaluationResult::Failed,
        );

        assert_eq!(policy.evaluation_result(), EvaluationResult::Failed);
        assert_eq!(scan_result.evaluation_result(), EvaluationResult::Failed);
    }

    #[test]
    fn test_entity_getters_and_debug() {
        let mut scan_result = create_scan_result();
        let now = Utc::now();

        // Metadata
        let metadata = scan_result.metadata();
        assert_eq!(metadata.image_id(), "sha256:12345");
        assert_eq!(metadata.digest(), Some("sha256:67890"));
        assert_eq!(metadata.base_os().family(), Family::Linux);
        assert_eq!(metadata.base_os().name(), "alpine:3.18");
        assert_eq!(*metadata.size_in_bytes(), 123456);
        assert_eq!(*metadata.architecture(), Architecture::Amd64);
        assert!(metadata.labels().is_empty());

        // Layer
        let layer =
            scan_result.add_layer("sha256:abc".to_string(), 0, Some(100), "CMD".to_string());
        assert_eq!(layer.digest(), Some("sha256:abc"));
        assert_eq!(layer.size(), Some(&100));
        assert_eq!(layer.command(), "CMD");
        assert!(format!("{:?}", layer).contains("sha256:abc"));
        let empty_digest_layer = scan_result.add_layer("".to_string(), 0, None, "ADD".to_string());
        assert!(empty_digest_layer.digest().is_none());

        // Package
        let package = scan_result.add_package(
            PackageType::Os,
            "musl".to_string(),
            "1.2.3".to_string(),
            "/path".to_string(),
            layer.clone(),
        );
        assert_eq!(package.package_type(), &PackageType::Os);
        assert_eq!(package.name(), "musl");
        assert_eq!(package.version(), "1.2.3");
        assert_eq!(package.path(), "/path");
        assert!(format!("{:?}", package).contains("musl"));
        assert_eq!(package.clone(), package);

        // Vulnerability
        let vuln = scan_result.add_vulnerability(
            "CVE-1".to_string(),
            Severity::High,
            now.naive_utc().date(),
            Some(now.naive_utc().date()),
            true,
            Some("1.2.4".to_string()),
        );
        assert_eq!(vuln.cve(), "CVE-1");
        assert_eq!(vuln.severity(), Severity::High);
        assert_eq!(vuln.disclosure_date(), now.naive_utc().date());
        assert_eq!(vuln.solution_date(), Some(now.naive_utc().date()));
        assert!(vuln.exploitable());
        assert!(vuln.fixable());
        assert_eq!(vuln.fix_version(), Some("1.2.4"));
        assert!(format!("{:?}", vuln).contains("CVE-1"));

        // AcceptedRisk
        let risk = scan_result.add_accepted_risk(
            "risk-1".to_string(),
            AcceptedRiskReason::Custom,
            "desc".to_string(),
            Some(now.naive_utc().date()),
            true,
            now,
            now,
        );
        assert_eq!(risk.reason(), &AcceptedRiskReason::Custom);
        assert_eq!(risk.description(), "desc");
        assert_eq!(risk.expiration_date(), Some(now.naive_utc().date()));
        assert!(risk.is_active());
        assert_eq!(risk.created_at(), now);
        assert_eq!(risk.updated_at(), now);
        assert!(format!("{:?}", risk).contains("risk-1"));

        // Policy
        let policy =
            scan_result.add_policy("policy-1".to_string(), "My Policy".to_string(), now, now);
        assert_eq!(policy.name(), "My Policy");
        assert_eq!(policy.created_at(), now);
        assert_eq!(policy.updated_at(), now);
        assert!(format!("{:?}", policy).contains("policy-1"));

        // PolicyBundle
        let bundle = scan_result.add_policy_bundle(
            "bundle-1".to_string(),
            "My Bundle".to_string(),
            policy.clone(),
        );
        assert_eq!(bundle.id(), "bundle-1");
        assert_eq!(bundle.name(), "My Bundle");
        assert!(format!("{:?}", bundle).contains("bundle-1"));
    }

    #[test]
    fn test_idempotent_adds() {
        let mut scan_result = create_scan_result();
        let now = Utc::now();

        // Add vulnerability twice
        let vuln = scan_result.add_vulnerability(
            "CVE-1".to_string(),
            Severity::High,
            now.naive_utc().date(),
            None,
            false,
            None,
        );
        let vuln2 = scan_result.add_vulnerability(
            "CVE-1".to_string(),
            Severity::High,
            now.naive_utc().date(),
            None,
            false,
            None,
        );
        assert_eq!(Arc::as_ptr(&vuln), Arc::as_ptr(&vuln2));
        assert_eq!(scan_result.vulnerabilities().len(), 1);

        // Add layer twice
        let layer = scan_result.add_layer("layer-1".to_string(), 0, None, "CMD".to_string());
        let layer2 = scan_result.add_layer("layer-1".to_string(), 0, None, "CMD".to_string());
        assert_ne!(Arc::as_ptr(&layer), Arc::as_ptr(&layer2)); // It creates a new Arc and adds it.
        assert_eq!(scan_result.layers().len(), 2);

        // Add package twice
        let pkg = scan_result.add_package(
            PackageType::Os,
            "pkg".to_string(),
            "1.0".to_string(),
            "/path".to_string(),
            layer.clone(),
        );
        let pkg2 = scan_result.add_package(
            PackageType::Os,
            "pkg".to_string(),
            "1.0".to_string(),
            "/path".to_string(),
            layer.clone(),
        );
        assert_eq!(Arc::as_ptr(&pkg), Arc::as_ptr(&pkg2));
        assert_eq!(scan_result.packages().len(), 1);

        // Add policy twice
        let policy = scan_result.add_policy("policy-1".to_string(), "p1".to_string(), now, now);
        let policy2 = scan_result.add_policy("policy-1".to_string(), "p1".to_string(), now, now);
        assert_eq!(Arc::as_ptr(&policy), Arc::as_ptr(&policy2));
        assert_eq!(scan_result.policies().len(), 1);

        // Add policy bundle twice
        let bundle =
            scan_result.add_policy_bundle("bundle-1".to_string(), "b1".to_string(), policy.clone());
        let bundle2 =
            scan_result.add_policy_bundle("bundle-1".to_string(), "b1".to_string(), policy.clone());
        assert_eq!(Arc::as_ptr(&bundle), Arc::as_ptr(&bundle2));
        assert_eq!(scan_result.policy_bundles().len(), 1);

        // Add accepted risk twice
        let risk = scan_result.add_accepted_risk(
            "risk-1".to_string(),
            AcceptedRiskReason::Custom,
            "".to_string(),
            None,
            true,
            now,
            now,
        );
        let risk2 = scan_result.add_accepted_risk(
            "risk-1".to_string(),
            AcceptedRiskReason::Custom,
            "".to_string(),
            None,
            true,
            now,
            now,
        );
        assert_eq!(Arc::as_ptr(&risk), Arc::as_ptr(&risk2));
        assert_eq!(scan_result.accepted_risks().len(), 1);

        // Test linking existing items
        pkg.add_vulnerability_found(vuln.clone());
        pkg.add_vulnerability_found(vuln.clone()); // second time
        assert_eq!(pkg.vulnerabilities().len(), 1);
        assert_eq!(vuln.found_in_packages().len(), 1);

        pkg.add_accepted_risk(risk.clone());
        pkg.add_accepted_risk(risk.clone());
        assert_eq!(pkg.accepted_risks().len(), 1);
        assert_eq!(risk.assigned_to_packages().len(), 1);

        vuln.add_accepted_risk(risk.clone());
        vuln.add_accepted_risk(risk.clone());
        assert_eq!(vuln.accepted_risks().len(), 1);
        assert_eq!(risk.assigned_to_vulnerabilities().len(), 1);

        bundle.add_policy(policy.clone());
        bundle.add_policy(policy.clone());
        assert_eq!(bundle.found_in_policies().len(), 1);
        assert_eq!(policy.bundles().len(), 1);
    }

    #[test]
    fn test_policy_evaluation_and_failures() {
        let mut scan_result = create_scan_result();
        let policy =
            scan_result.add_policy("p1".to_string(), "p1".to_string(), Utc::now(), Utc::now());
        let bundle =
            scan_result.add_policy_bundle("b1".to_string(), "b1".to_string(), policy.clone());

        let passed_rule = bundle.add_rule(
            "rule-passed".to_string(),
            "desc".to_string(),
            EvaluationResult::Passed,
        );
        assert_eq!(passed_rule.id(), "rule-passed");
        assert_eq!(passed_rule.description(), "desc");
        assert!(passed_rule.evaluation_result().is_passed());
        assert!(!passed_rule.evaluation_result().is_failed());
        assert!(passed_rule.parent().upgrade().is_some());

        assert_eq!(bundle.evaluation_result(), EvaluationResult::Passed);
        assert_eq!(policy.evaluation_result(), EvaluationResult::Passed);
        assert_eq!(
            scan_result.evaluation_result(),
            EvaluationResult::Failed,
            "Global evaluation should remain Failed"
        );

        let failed_rule = bundle.add_rule(
            "rule-failed".to_string(),
            "desc".to_string(),
            EvaluationResult::Failed,
        );
        assert!(failed_rule.evaluation_result().is_failed());
        assert!(!failed_rule.evaluation_result().is_passed());

        let img_fail = failed_rule.add_image_config_failure("remediation".to_string());
        assert_eq!(img_fail.description(), "remediation");
        assert!(img_fail.parent().upgrade().is_some());

        let pkg_fail = failed_rule.add_pkg_vuln_failure("description".to_string());
        assert_eq!(pkg_fail.remediation(), "description");
        assert!(pkg_fail.parent().upgrade().is_some());

        assert_eq!(failed_rule.failures().len(), 2);

        assert_eq!(bundle.evaluation_result(), EvaluationResult::Failed);
        assert_eq!(policy.evaluation_result(), EvaluationResult::Failed);
        assert_eq!(
            scan_result.evaluation_result(),
            EvaluationResult::Failed,
            "Global evaluation should remain Failed"
        );
    }
}
