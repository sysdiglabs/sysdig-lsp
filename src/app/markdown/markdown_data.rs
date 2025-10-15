use std::fmt::{Display, Formatter};

use crate::domain::scanresult::scan_result::ScanResult;

use super::{
    markdown_fixable_package_table::FixablePackageTable,
    markdown_policy_evaluated_table::PolicyEvaluatedTable, markdown_summary::MarkdownSummary,
    markdown_vulnerability_evaluated_table::VulnerabilityEvaluatedTable,
};

#[derive(Clone, Debug, Default)]
pub struct MarkdownData {
    pub summary: MarkdownSummary,
    pub fixable_packages: FixablePackageTable,
    pub policies: PolicyEvaluatedTable,
    pub vulnerabilities: VulnerabilityEvaluatedTable,
}

impl From<ScanResult> for MarkdownData {
    fn from(value: ScanResult) -> Self {
        Self {
            summary: MarkdownSummary::from(&value),
            fixable_packages: FixablePackageTable::from(&value),
            policies: PolicyEvaluatedTable::from(&value),
            vulnerabilities: VulnerabilityEvaluatedTable::from(&value),
        }
    }
}

impl Display for MarkdownData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let summary_section = self.summary.to_string();
        let fixable_packages_section = self.fixable_packages.to_string();
        let policy_evaluation_section = self.policies.to_string();
        let vulnerability_detail_section = self.vulnerabilities.to_string();

        write!(
            f,
            "## Sysdig Scan Result\n{}\n{}\n{}\n{}",
            summary_section,
            fixable_packages_section,
            policy_evaluation_section,
            vulnerability_detail_section
        )
    }
}

#[cfg(test)]
mod test {
    use super::super::markdown_fixable_package_table::{
        FixablePackage, FixablePackageTable, FixablePackageVulnerabilities,
    };
    use super::super::markdown_policy_evaluated_table::{PolicyEvaluated, PolicyEvaluatedTable};
    use super::super::markdown_summary::MarkdownSummary;
    use super::super::markdown_summary_table::MarkdownSummaryTable;
    use super::super::markdown_vulnerability_evaluated_table::{
        VulnerabilityEvaluated, VulnerabilityEvaluatedTable,
    };

    use super::*;

    #[test]
    fn converts_markdown_data_to_markdown_text() {
        let markdown_data = MarkdownData {
            summary: MarkdownSummary {
                pull_string: "ubuntu:23.04".to_string(),
                image_id: "sha256:f4cdeba72b994748f5eb1f525a70a9cc553b66037ec37e23645fbf3f0f5c160d"
                    .to_string(),
                digest: Some(
                    "sha256:5a828e28de105c3d7821c4442f0f5d1c52dc16acf4999d5f31a3bc0f03f06edd"
                        .to_string(),
                ),
                base_os: "ubuntu 23.04".to_string(),

                total_vulns_found: MarkdownSummaryTable {
                    total_found: 11,
                    critical: 0,
                    critical_fixable: 0,
                    high: 0,
                    high_fixable: 0,
                    medium: 9,
                    medium_fixable: 9,
                    low: 2,
                    low_fixable: 2,
                    negligible: 0,
                    negligible_fixable: 0,
                },
            },
            fixable_packages: FixablePackageTable(vec![
                FixablePackage {
                    name: "libgnutls30".to_string(),
                    package_type: "os".to_string(),
                    version: "3.7.8-5ubuntu1.1".to_string(),
                    suggested_fix: Some("3.7.8-5ubuntu1.2".to_string()),
                    vulnerabilities: FixablePackageVulnerabilities {
                        critical: 0,
                        high: 0,
                        medium: 2,
                        low: 0,
                        negligible: 0,
                    },
                    exploits: 0,
                },
                FixablePackage {
                    name: "libc-bin".to_string(),
                    package_type: "os".to_string(),
                    version: "2.37-0ubuntu2.1".to_string(),
                    suggested_fix: Some("2.37-0ubuntu2.2".to_string()),
                    vulnerabilities: FixablePackageVulnerabilities {
                        critical: 0,
                        high: 0,
                        medium: 1,
                        low: 1,
                        negligible: 0,
                    },
                    exploits: 0,
                },
                FixablePackage {
                    name: "libc6".to_string(),
                    package_type: "os".to_string(),
                    version: "2.37-0ubuntu2.1".to_string(),
                    suggested_fix: Some("2.37-0ubuntu2.2".to_string()),
                    vulnerabilities: FixablePackageVulnerabilities {
                        critical: 0,
                        high: 0,
                        medium: 1,
                        low: 1,
                        negligible: 0,
                    },
                    exploits: 0,
                },
                FixablePackage {
                    name: "libpam-modules".to_string(),
                    package_type: "os".to_string(),
                    version: "1.5.2-5ubuntu1".to_string(),
                    suggested_fix: Some("1.5.2-5ubuntu1.1".to_string()),
                    vulnerabilities: FixablePackageVulnerabilities {
                        critical: 0,
                        high: 0,
                        medium: 1,
                        low: 0,
                        negligible: 0,
                    },
                    exploits: 0,
                },
                FixablePackage {
                    name: "libpam-modules-bin".to_string(),
                    package_type: "os".to_string(),
                    version: "1.5.2-5ubuntu1".to_string(),
                    suggested_fix: Some("1.5.2-5ubuntu1.1".to_string()),
                    vulnerabilities: FixablePackageVulnerabilities {
                        critical: 0,
                        high: 0,
                        medium: 1,
                        low: 0,
                        negligible: 0,
                    },
                    exploits: 0,
                },
                FixablePackage {
                    name: "libpam-runtime".to_string(),
                    package_type: "os".to_string(),
                    version: "1.5.2-5ubuntu1".to_string(),
                    suggested_fix: Some("1.5.2-5ubuntu1.1".to_string()),
                    vulnerabilities: FixablePackageVulnerabilities {
                        critical: 0,
                        high: 0,
                        medium: 1,
                        low: 0,
                        negligible: 0,
                    },
                    exploits: 0,
                },
                FixablePackage {
                    name: "libpam0g".to_string(),
                    package_type: "os".to_string(),
                    version: "1.5.2-5ubuntu1".to_string(),
                    suggested_fix: Some("1.5.2-5ubuntu1.1".to_string()),
                    vulnerabilities: FixablePackageVulnerabilities {
                        critical: 0,
                        high: 0,
                        medium: 1,
                        low: 0,
                        negligible: 0,
                    },
                    exploits: 0,
                },
                FixablePackage {
                    name: "tar".to_string(),
                    package_type: "os".to_string(),
                    version: "1.34+dfsg-1.2ubuntu0.1".to_string(),
                    suggested_fix: Some("1.34+dfsg-1.2ubuntu0.2".to_string()),
                    vulnerabilities: FixablePackageVulnerabilities {
                        critical: 0,
                        high: 0,
                        medium: 1,
                        low: 0,
                        negligible: 0,
                    },
                    exploits: 0,
                },
            ]),
            policies: PolicyEvaluatedTable(vec![
                PolicyEvaluated {
                    name: "carholder policy - pk".to_string(),
                    passed: false,
                    failures: 1,
                    risks_accepted: 0,
                },
                PolicyEvaluated {
                    name: "Critical Vulnerability Found".to_string(),
                    passed: true,
                    failures: 0,
                    risks_accepted: 0,
                },
                PolicyEvaluated {
                    name: "Forbid Secrets in Images".to_string(),
                    passed: true,
                    failures: 0,
                    risks_accepted: 0,
                },
                PolicyEvaluated {
                    name: "NIST SP 800-Star".to_string(),
                    passed: false,
                    failures: 14,
                    risks_accepted: 0,
                },
                PolicyEvaluated {
                    name: "PolicyCardHolder".to_string(),
                    passed: false,
                    failures: 1,
                    risks_accepted: 0,
                },
                PolicyEvaluated {
                    name: "Sensitive Information or Secret Found".to_string(),
                    passed: true,
                    failures: 0,
                    risks_accepted: 0,
                },
                PolicyEvaluated {
                    name: "Sysdig Best Practices".to_string(),
                    passed: true,
                    failures: 0,
                    risks_accepted: 0,
                },
            ]),

            vulnerabilities: VulnerabilityEvaluatedTable(vec![
                VulnerabilityEvaluated {
                    cve: "CVE-2023-39804".to_string(),
                    severity: "Medium".to_string(),
                    packages_found: 1,
                    fixable: true,
                    exploitable: false,
                    accepted_risk: false,
                },
                VulnerabilityEvaluated {
                    cve: "CVE-2023-4806".to_string(),
                    severity: "Low".to_string(),
                    packages_found: 2,
                    fixable: true,
                    exploitable: false,
                    accepted_risk: false,
                },
                VulnerabilityEvaluated {
                    cve: "CVE-2023-5156".to_string(),
                    severity: "Medium".to_string(),
                    packages_found: 2,
                    fixable: true,
                    exploitable: false,
                    accepted_risk: false,
                },
                VulnerabilityEvaluated {
                    cve: "CVE-2024-0553".to_string(),
                    severity: "Medium".to_string(),
                    packages_found: 1,
                    fixable: true,
                    exploitable: false,
                    accepted_risk: false,
                },
                VulnerabilityEvaluated {
                    cve: "CVE-2024-0567".to_string(),
                    severity: "Medium".to_string(),
                    packages_found: 1,
                    fixable: true,
                    exploitable: false,
                    accepted_risk: false,
                },
                VulnerabilityEvaluated {
                    cve: "CVE-2024-22365".to_string(),
                    severity: "Medium".to_string(),
                    packages_found: 4,
                    fixable: true,
                    exploitable: false,
                    accepted_risk: false,
                },
            ]),
        };
        let expected_markdown_output = r#"## Sysdig Scan Result
### Summary
* **PullString**: ubuntu:23.04
* **ImageID**: `sha256:f4cdeba72b994748f5eb1f525a70a9cc553b66037ec37e23645fbf3f0f5c160d`
* **Digest**: `sha256:5a828e28de105c3d7821c4442f0f5d1c52dc16acf4999d5f31a3bc0f03f06edd`
* **BaseOS**: ubuntu 23.04

| TOTAL VULNS FOUND | CRITICAL | HIGH | MEDIUM      | LOW         | NEGLIGIBLE |
| :-------------: | :----: | :-: | :---------: | :---------: | :------: |
| 11              | 0      | 0   | 9 (9 Fixable) | 2 (2 Fixable) | 0        |


### Fixable Packages
| PACKAGE          | TYPE | VERSION              | SUGGESTED FIX        | CRITICAL | HIGH | MEDIUM | LOW | NEGLIGIBLE | EXPLOIT |
| :--------------- | :-: | :------------------- | :------------------- | :----: | :-: | :--: | :-: | :------: | :---: |
| libgnutls30      | os  | 3.7.8-5ubuntu1.1     | 3.7.8-5ubuntu1.2     | -      | -   | 2    | -   | -        | -     |
| libc-bin         | os  | 2.37-0ubuntu2.1      | 2.37-0ubuntu2.2      | -      | -   | 1    | 1   | -        | -     |
| libc6            | os  | 2.37-0ubuntu2.1      | 2.37-0ubuntu2.2      | -      | -   | 1    | 1   | -        | -     |
| libpam-modules   | os  | 1.5.2-5ubuntu1       | 1.5.2-5ubuntu1.1     | -      | -   | 1    | -   | -        | -     |
| libpam-modules-bin | os  | 1.5.2-5ubuntu1       | 1.5.2-5ubuntu1.1     | -      | -   | 1    | -   | -        | -     |
| libpam-runtime   | os  | 1.5.2-5ubuntu1       | 1.5.2-5ubuntu1.1     | -      | -   | 1    | -   | -        | -     |
| libpam0g         | os  | 1.5.2-5ubuntu1       | 1.5.2-5ubuntu1.1     | -      | -   | 1    | -   | -        | -     |
| tar              | os  | 1.34+dfsg-1.2ubuntu0.1 | 1.34+dfsg-1.2ubuntu0.2 | -      | -   | 1    | -   | -        | -     |


### Policy Evaluation

| POLICY                              | STATUS | FAILURES | RISKS ACCEPTED |
| :---------------------------------- | :--: | :----: | :----------: |
| carholder policy - pk               | ❌   | 1      | 0            |
| Critical Vulnerability Found        | ✅   | 0      | 0            |
| Forbid Secrets in Images            | ✅   | 0      | 0            |
| NIST SP 800-Star                    | ❌   | 14     | 0            |
| PolicyCardHolder                    | ❌   | 1      | 0            |
| Sensitive Information or Secret Found | ✅   | 0      | 0            |
| Sysdig Best Practices               | ✅   | 0      | 0            |


### Vulnerability Detail

| VULN CVE     | SEVERITY | PACKAGES | FIXABLE | EXPLOITABLE | ACCEPTED RISK |
| :----------- | :----- | :----- | :---- | :-------- | :---------- |
| CVE-2023-39804 | Medium | 1      | ✅    | ❌        | ❌          |
| CVE-2023-4806 | Low    | 2      | ✅    | ❌        | ❌          |
| CVE-2023-5156 | Medium | 2      | ✅    | ❌        | ❌          |
| CVE-2024-0553 | Medium | 1      | ✅    | ❌        | ❌          |
| CVE-2024-0567 | Medium | 1      | ✅    | ❌        | ❌          |
| CVE-2024-22365 | Medium | 4      | ✅    | ❌        | ❌          |"#;

        assert_eq!(
            markdown_data.to_string().trim(),
            expected_markdown_output.trim()
        );
    }
}
