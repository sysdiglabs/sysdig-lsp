use crate::domain::scanresult::accepted_risk::AcceptedRisk;
use crate::domain::scanresult::layer::Layer;
use crate::domain::scanresult::package_type::PackageType;
use crate::domain::scanresult::severity::Severity;
use crate::domain::scanresult::vulnerability::Vulnerability;
use crate::domain::scanresult::weak_hash::WeakHash;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, RwLock};

pub struct Package {
    package_type: PackageType,
    name: String,
    version: String,
    path: String,
    found_in_layer: Arc<Layer>,
    vulnerabilities: RwLock<HashSet<WeakHash<Vulnerability>>>,
    accepted_risks: RwLock<HashSet<WeakHash<AcceptedRisk>>>,
}

impl Debug for Package {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Package")
            .field("package_type", &self.package_type)
            .field("name", &self.name)
            .field("version", &self.version)
            .field("path", &self.path)
            .field("found_in_layer", &self.found_in_layer)
            .finish()
    }
}

impl Package {
    pub(in crate::domain::scanresult) fn new(
        package_type: PackageType,
        name: String,
        version: String,
        path: String,
        found_in_layer: Arc<Layer>,
    ) -> Self {
        Self {
            package_type,
            name,
            version,
            path,
            found_in_layer,
            vulnerabilities: RwLock::new(HashSet::new()),
            accepted_risks: RwLock::new(HashSet::new()),
        }
    }

    pub fn package_type(&self) -> &PackageType {
        &self.package_type
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> &String {
        &self.version
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn found_in_layer(&self) -> &Arc<Layer> {
        &self.found_in_layer
    }

    pub fn add_vulnerability_found(self: &Arc<Self>, vulnerability: Arc<Vulnerability>) {
        if self
            .vulnerabilities
            .write()
            .unwrap_or_else(|e| panic!("RwLock poisoned in package.rs: {}", e))
            .insert(WeakHash(Arc::downgrade(&vulnerability)))
        {
            vulnerability.add_found_in_package(self.clone());
        }
    }

    pub fn vulnerabilities(&self) -> Vec<Arc<Vulnerability>> {
        self.vulnerabilities
            .read()
            .unwrap_or_else(|e| panic!("RwLock poisoned in package.rs: {}", e))
            .iter()
            .filter_map(|v| v.0.upgrade())
            .collect()
    }

    pub fn add_accepted_risk(self: &Arc<Self>, accepted_risk: Arc<AcceptedRisk>) {
        if self
            .accepted_risks
            .write()
            .unwrap_or_else(|e| panic!("RwLock poisoned in package.rs: {}", e))
            .insert(WeakHash(Arc::downgrade(&accepted_risk)))
        {
            accepted_risk.add_for_package(self.clone());
        }
    }

    pub fn accepted_risks(&self) -> Vec<Arc<AcceptedRisk>> {
        self.accepted_risks
            .read()
            .unwrap_or_else(|e| panic!("RwLock poisoned in package.rs: {}", e))
            .iter()
            .filter_map(|r| r.0.upgrade())
            .collect()
    }

    pub fn suggested_fix_version(&self) -> Option<String> {
        let vulnerabilities = self.vulnerabilities();
        if vulnerabilities.is_empty() {
            return None;
        }

        let candidate_versions: Vec<String> = vulnerabilities
            .iter()
            .filter_map(|vuln| vuln.fix_version().cloned())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        if candidate_versions.is_empty() {
            return None;
        }

        let severity_order = [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Negligible,
            Severity::Unknown,
        ];

        let mut scores: HashMap<String, HashMap<Severity, usize>> = HashMap::new();

        for candidate in &candidate_versions {
            let mut score: HashMap<Severity, usize> = HashMap::new();
            for severity in &severity_order {
                score.insert(*severity, 0);
            }
            for vuln in &vulnerabilities {
                if let Some(fix_version) = vuln.fix_version()
                    && fix_version == candidate
                {
                    *score.entry(vuln.severity()).or_insert(0) += 1;
                }
            }
            scores.insert(candidate.clone(), score);
        }

        let mut sorted_candidates = candidate_versions;
        sorted_candidates.sort_by(|a, b| {
            // These unwrap_or calls should never execute since we populated scores
            // for all candidate versions above, but we handle the case defensively
            let empty_score = HashMap::new();
            let score_a = scores.get(a).unwrap_or(&empty_score);
            let score_b = scores.get(b).unwrap_or(&empty_score);

            for severity in &severity_order {
                let count_a = score_a.get(severity).unwrap_or(&0);
                let count_b = score_b.get(severity).unwrap_or(&0);
                if count_a != count_b {
                    return count_b.cmp(count_a); // Higher count is better
                }
            }

            // If scores are identical, lower version is better
            if version_compare::compare_to(a, b, version_compare::Cmp::Eq).unwrap_or(false) {
                return Ordering::Equal;
            }
            if version_compare::compare_to(a, b, version_compare::Cmp::Le).unwrap_or(false) {
                return Ordering::Less;
            }
            if version_compare::compare_to(a, b, version_compare::Cmp::Ge).unwrap_or(false) {
                return Ordering::Greater;
            }
            Ordering::Less
        });

        sorted_candidates.first().cloned()
    }
}

impl PartialEq for Package {
    fn eq(&self, other: &Self) -> bool {
        self.package_type == other.package_type
            && self.name == other.name
            && self.version == other.version
            && self.path == other.path
    }
}

impl Eq for Package {}

impl Hash for Package {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.package_type.hash(state);
        self.name.hash(state);
        self.version.hash(state);
        self.path.hash(state);
    }
}

impl Clone for Package {
    fn clone(&self) -> Self {
        Self {
            package_type: self.package_type,
            name: self.name.clone(),
            version: self.version.clone(),
            path: self.path.clone(),
            found_in_layer: self.found_in_layer.clone(),
            vulnerabilities: RwLock::new(
                self.vulnerabilities
                    .read()
                    .unwrap_or_else(|e| panic!("RwLock poisoned in package.rs: {}", e))
                    .clone(),
            ),
            accepted_risks: RwLock::new(
                self.accepted_risks
                    .read()
                    .unwrap_or_else(|e| panic!("RwLock poisoned in package.rs: {}", e))
                    .clone(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::scanresult::layer::Layer;
    use crate::domain::scanresult::package_type::PackageType;
    use crate::domain::scanresult::severity::Severity;
    use crate::domain::scanresult::vulnerability::Vulnerability;
    use chrono::NaiveDate;
    use rstest::{fixture, rstest};
    use std::sync::Arc;

    #[fixture]
    fn layer() -> Arc<Layer> {
        Arc::new(Layer::new(
            "a_digest".to_string(),
            0,
            None,
            "a_command".to_string(),
        ))
    }

    #[fixture]
    fn package(#[default("")] version: &str, layer: Arc<Layer>) -> Arc<Package> {
        Arc::new(Package::new(
            PackageType::Os,
            "a_name".to_string(),
            version.to_string(),
            "a_path".to_string(),
            layer,
        ))
    }

    fn a_vulnerability(
        cve: &str,
        severity: Severity,
        fix_version: Option<&str>,
    ) -> Arc<Vulnerability> {
        Arc::new(Vulnerability::new(
            cve.to_string(),
            severity,
            NaiveDate::from_ymd_opt(2023, 1, 1).unwrap(),
            None,
            false,
            fix_version.map(|v| v.to_string()),
        ))
    }

    #[rstest]
    #[case("is_none_when_no_vulnerabilities", "1.0.0", vec![], None)]
    #[case("is_none_when_no_fixable_vulnerabilities", "1.0.0", vec![a_vulnerability("CVE-1", Severity::High, None)], None)]
    #[case("returns_only_available_fix", "1.0.0", vec![a_vulnerability("CVE-1", Severity::High, Some("1.0.1"))], Some("1.0.1"))]
    #[case("chooses_version_with_more_critical_fixes", "1.0.0", vec![
        a_vulnerability("CVE-1", Severity::Critical, Some("1.0.1")),
        a_vulnerability("CVE-2", Severity::Critical, Some("1.0.2")),
        a_vulnerability("CVE-3", Severity::High, Some("1.0.2")),
    ], Some("1.0.2"))]
    #[case("chooses_version_with_more_high_fixes_when_criticals_tied", "1.0.0", vec![
        a_vulnerability("CVE-1", Severity::Critical, Some("1.0.1")),
        a_vulnerability("CVE-5", Severity::Medium, Some("1.0.1")),
        a_vulnerability("CVE-2", Severity::Critical, Some("1.0.2")),
        a_vulnerability("CVE-3", Severity::High, Some("1.0.2")),
        a_vulnerability("CVE-4", Severity::High, Some("1.0.2")),
    ], Some("1.0.2"))]
    #[case("chooses_lower_version_when_counts_are_tied", "1.0.0", vec![
        a_vulnerability("CVE-1", Severity::Critical, Some("1.0.1")),
        a_vulnerability("CVE-3", Severity::High, Some("1.0.1")),
        a_vulnerability("CVE-2", Severity::Critical, Some("1.0.2")),
        a_vulnerability("CVE-4", Severity::High, Some("1.0.2")),
    ], Some("1.0.1"))]
    #[case("handles_complex_scenario", "2.8.1", vec![
        a_vulnerability("CVE-2022-25857", Severity::High, Some("2.8.2")),
        a_vulnerability("CVE-2022-39253", Severity::High, Some("2.8.2")),
        a_vulnerability("CVE-2022-0536", Severity::Medium, Some("2.8.2")),
        a_vulnerability("CVE-2022-41724", Severity::Medium, Some("2.8.2")),
        a_vulnerability("CVE-2022-41725", Severity::Medium, Some("2.8.2")),

        a_vulnerability("CVE-2021-33574", Severity::Critical, Some("2.9.0")),
        a_vulnerability("CVE-2022-25857", Severity::High, Some("2.9.0")),
        a_vulnerability("CVE-2022-39253", Severity::High, Some("2.9.0")),
        a_vulnerability("CVE-2022-0536", Severity::Medium, Some("2.9.0")),
        a_vulnerability("CVE-2022-41724", Severity::Medium, Some("2.9.0")),
        a_vulnerability("CVE-2022-41725", Severity::Medium, Some("2.9.0")),
    ], Some("2.9.0"))]
    #[case("handles_debian_version", "1.1.35-1.2+deb13u2", vec![
        a_vulnerability("CVE-1", Severity::High, Some("1.1.35-1.2+deb13u3")),
        a_vulnerability("CVE-2", Severity::High, Some("1.1.35-1.3")),
    ], Some("1.1.35-1.2+deb13u3"))]
    #[case("chooses_lower_version_with_debian_tilde", "257.8-1~deb13u1", vec![
        a_vulnerability("CVE-1", Severity::High, Some("257.8-1~deb13u2")),
        a_vulnerability("CVE-2", Severity::High, Some("257.8-1~deb13u3")),
    ], Some("257.8-1~deb13u2"))]
    #[case("handles_jre_and_android_versions", "31.1-jre", vec![
        a_vulnerability("CVE-1", Severity::High, Some("32.0.0-android")),
    ], Some("32.0.0-android"))]
    #[case("handles_api_version", "31.0-api", vec![a_vulnerability("CVE-1", Severity::High, Some("31.1-api"))], Some("31.1-api"))]
    #[case("handles_build_metadata_version", "1.0.15-1+b3", vec![a_vulnerability("CVE-1", Severity::High, Some("1.0.15-2"))], Some("1.0.15-2"))]
    #[case("handles_simple_float_version", "2.6", vec![a_vulnerability("CVE-1", Severity::High, Some("2.7"))], Some("2.7"))]
    #[case("handles_revision_version", "1.7.0-5", vec![a_vulnerability("CVE-1", Severity::High, Some("1.7.0-6"))], Some("1.7.0-6"))]
    #[case("handles_date_based_version", "6.5+20250216-2", vec![a_vulnerability("CVE-1", Severity::High, Some("6.5+20250216-3"))], Some("6.5+20250216-3"))]
    #[case("handles_jenkins_version", "3107.v665000b_51092", vec![a_vulnerability("CVE-1", Severity::High, Some("3107.v665000b_51093"))], Some("3107.v665000b_51093"))]
    #[case("handles_dot_separated_version", "3206.3208", vec![a_vulnerability("CVE-1", Severity::High, Some("3206.3209"))], Some("3206.3209"))]
    #[case("handles_complex_debian_version", "2.12.7+dfsg+really2.9.14-2.1+deb13u1", vec![a_vulnerability("CVE-1", Severity::High, Some("2.12.7+dfsg+really2.9.14-2.1+deb13u2"))], Some("2.12.7+dfsg+really2.9.14-2.1+deb13u2"))]
    fn test_suggested_fix_version(
        #[case] _description: &str,
        #[case] version: &str,
        #[with(version)] package: Arc<Package>,
        #[case] vulnerabilities: Vec<Arc<Vulnerability>>,
        #[case] expected_fix: Option<&str>,
    ) {
        assert_eq!(package.version(), &version);

        for vuln in &vulnerabilities {
            package.add_vulnerability_found(vuln.clone());
        }

        assert_eq!(
            package.suggested_fix_version(),
            expected_fix.map(|x| x.to_string())
        );
    }
}
