use crate::domain::scanresult::scan_result::ScanResult;
use crate::domain::scanresult::severity::Severity;
use itertools::Itertools;
use markdown_table::{Heading, HeadingAlignment, MarkdownTable};
use std::fmt::{Display, Formatter};

impl From<ScanResult> for MarkdownData {
    fn from(value: ScanResult) -> Self {
        Self {
            summary: summary_from(&value),
            fixable_packages: fixable_packages_from(&value),
            policies: policies_from(&value),
            vulnerabilities: vulnerabilities_from(&value),
        }
    }
}

impl Display for MarkdownData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let summary_section = self.summary_section();
        let fixable_packages_section = self.fixable_packages_section();
        let policy_evaluation_section = self.policy_evaluation_section();
        let vulnerability_detail_section = self.vulnerability_detail_section();

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

impl MarkdownData {
    fn summary_vulns_line(&self, total_vulns: u32, fixable_vulns: u32) -> String {
        if fixable_vulns > 0 {
            format!("{} ({} Fixable)", total_vulns, fixable_vulns)
        } else {
            total_vulns.to_string()
        }
    }

    fn summary_section(&self) -> String {
        let summary = &self.summary;
        let total_vulns_found = &summary.total_vulns_found;

        let headers = vec![
            Heading::new(
                "TOTAL VULNS FOUND".to_string(),
                Some(HeadingAlignment::Center),
            ),
            Heading::new("CRITICAL".to_string(), Some(HeadingAlignment::Center)),
            Heading::new("HIGH".to_string(), Some(HeadingAlignment::Center)),
            Heading::new("MEDIUM".to_string(), Some(HeadingAlignment::Center)),
            Heading::new("LOW".to_string(), Some(HeadingAlignment::Center)),
            Heading::new("NEGLIGIBLE".to_string(), Some(HeadingAlignment::Center)),
        ];

        let data = vec![vec![
            total_vulns_found.total_found.to_string(),
            self.summary_vulns_line(
                total_vulns_found.critical,
                total_vulns_found.critical_fixable,
            ),
            self.summary_vulns_line(total_vulns_found.high, total_vulns_found.high_fixable),
            self.summary_vulns_line(total_vulns_found.medium, total_vulns_found.medium_fixable),
            self.summary_vulns_line(total_vulns_found.low, total_vulns_found.low_fixable),
            self.summary_vulns_line(
                total_vulns_found.negligible,
                total_vulns_found.negligible_fixable,
            ),
        ]];

        let mut table = MarkdownTable::new(data);
        table.with_headings(headers);

        format!(
            "### Summary\n* **PullString**: {}\n* **ImageID**: `{}`\n* **Digest**: `{}`\n* **BaseOS**: {}\n\n{}",
            summary.pull_string,
            summary.image_id,
            summary.digest,
            summary.base_os,
            table.as_markdown().unwrap_or_default()
        )
    }

    fn fixable_packages_section(&self) -> String {
        if self.fixable_packages.is_empty() {
            return "".to_string();
        }
        let headers = vec![
            Heading::new("PACKAGE".to_string(), Some(HeadingAlignment::Left)),
            Heading::new("TYPE".to_string(), Some(HeadingAlignment::Center)),
            Heading::new("VERSION".to_string(), Some(HeadingAlignment::Left)),
            Heading::new("SUGGESTED FIX".to_string(), Some(HeadingAlignment::Left)),
            Heading::new("CRITICAL".to_string(), Some(HeadingAlignment::Center)),
            Heading::new("HIGH".to_string(), Some(HeadingAlignment::Center)),
            Heading::new("MEDIUM".to_string(), Some(HeadingAlignment::Center)),
            Heading::new("LOW".to_string(), Some(HeadingAlignment::Center)),
            Heading::new("NEGLIGIBLE".to_string(), Some(HeadingAlignment::Center)),
            Heading::new("EXPLOIT".to_string(), Some(HeadingAlignment::Center)),
        ];

        let data = self
            .fixable_packages
            .iter()
            .map(|p| {
                vec![
                    p.name.clone(),
                    p.package_type.clone(),
                    p.version.clone(),
                    p.suggested_fix.clone().unwrap_or_default(),
                    if p.vulnerabilities.critical > 0 {
                        p.vulnerabilities.critical.to_string()
                    } else {
                        "-".to_string()
                    },
                    if p.vulnerabilities.high > 0 {
                        p.vulnerabilities.high.to_string()
                    } else {
                        "-".to_string()
                    },
                    if p.vulnerabilities.medium > 0 {
                        p.vulnerabilities.medium.to_string()
                    } else {
                        "-".to_string()
                    },
                    if p.vulnerabilities.low > 0 {
                        p.vulnerabilities.low.to_string()
                    } else {
                        "-".to_string()
                    },
                    if p.vulnerabilities.negligible > 0 {
                        p.vulnerabilities.negligible.to_string()
                    } else {
                        "-".to_string()
                    },
                    if p.exploits > 0 {
                        p.exploits.to_string()
                    } else {
                        "-".to_string()
                    },
                ]
            })
            .collect();

        let mut table = MarkdownTable::new(data);
        table.with_headings(headers);

        format!(
            "\n### Fixable Packages\n{}",
            table.as_markdown().unwrap_or_default()
        )
    }

    fn policy_evaluation_section(&self) -> String {
        if self.policies.is_empty() {
            return "".to_string();
        }
        let headers = vec![
            Heading::new("POLICY".to_string(), Some(HeadingAlignment::Left)),
            Heading::new("STATUS".to_string(), Some(HeadingAlignment::Center)),
            Heading::new("FAILURES".to_string(), Some(HeadingAlignment::Center)),
            Heading::new("RISKS ACCEPTED".to_string(), Some(HeadingAlignment::Center)),
        ];

        let data = self
            .policies
            .iter()
            .map(|p| {
                vec![
                    p.name.clone(),
                    if p.passed { "✅" } else { "❌" }.to_string(),
                    p.failures.to_string(),
                    p.risks_accepted.to_string(),
                ]
            })
            .collect();

        let mut table = MarkdownTable::new(data);
        table.with_headings(headers);

        format!(
            "\n### Policy Evaluation\n\n{}",
            table.as_markdown().unwrap_or_default()
        )
    }

    fn vulnerability_detail_section(&self) -> String {
        if self.vulnerabilities.is_empty() {
            return "".to_string();
        }
        let headers = vec![
            Heading::new("VULN CVE".to_string(), Some(HeadingAlignment::Left)),
            Heading::new("SEVERITY".to_string(), Some(HeadingAlignment::Left)),
            Heading::new("PACKAGES".to_string(), Some(HeadingAlignment::Left)),
            Heading::new("FIXABLE".to_string(), Some(HeadingAlignment::Left)),
            Heading::new("EXPLOITABLE".to_string(), Some(HeadingAlignment::Left)),
            Heading::new("ACCEPTED RISK".to_string(), Some(HeadingAlignment::Left)),
        ];

        let data = self
            .vulnerabilities
            .iter()
            .map(|v| {
                vec![
                    v.cve.clone(),
                    v.severity.clone(),
                    v.packages_found.to_string(),
                    if v.fixable { "✅" } else { "❌" }.to_string(),
                    if v.exploitable { "✅" } else { "❌" }.to_string(),
                    if v.accepted_risk { "✅" } else { "❌" }.to_string(),
                ]
            })
            .collect();

        let mut table = MarkdownTable::new(data);
        table.with_headings(headers);

        format!(
            "\n### Vulnerability Detail\n\n{}",
            table.as_markdown().unwrap_or_default()
        )
    }
}

fn summary_from(value: &ScanResult) -> MarkdownSummary {
    MarkdownSummary {
        pull_string: value.metadata().pull_string().to_string(),
        image_id: value.metadata().image_id().to_string(),
        digest: value.metadata().digest().unwrap_or("").to_string(),
        base_os: value.metadata().base_os().name().to_string(),
        total_vulns_found: summary_vulns_from(value),
    }
}

fn summary_vulns_from(value: &ScanResult) -> MarkdownSummaryVulns {
    let mut summary = MarkdownSummaryVulns::default();

    for vuln in value.vulnerabilities() {
        summary.total_found += 1;
        let fixable = vuln.fixable();
        match vuln.severity() {
            Severity::Critical => {
                summary.critical += 1;
                if fixable {
                    summary.critical_fixable += 1;
                }
            }
            Severity::High => {
                summary.high += 1;
                if fixable {
                    summary.high_fixable += 1;
                }
            }
            Severity::Medium => {
                summary.medium += 1;
                if fixable {
                    summary.medium_fixable += 1;
                }
            }
            Severity::Low => {
                summary.low += 1;
                if fixable {
                    summary.low_fixable += 1;
                }
            }
            Severity::Negligible => {
                summary.negligible += 1;
                if fixable {
                    summary.negligible_fixable += 1;
                }
            }
            Severity::Unknown => {}
        }
    }
    summary
}

fn fixable_packages_from(value: &ScanResult) -> Vec<FixablePackage> {
    value
        .packages()
        .into_iter()
        .filter(|p| p.vulnerabilities().iter().any(|v| v.fixable()))
        .map(|p| {
            let mut vulns = FixablePackageVulnerabilities::default();
            let mut exploits = 0;
            for v in p.vulnerabilities() {
                if v.exploitable() {
                    exploits += 1;
                }
                match v.severity() {
                    Severity::Critical => vulns.critical += 1,
                    Severity::High => vulns.high += 1,
                    Severity::Medium => vulns.medium += 1,
                    Severity::Low => vulns.low += 1,
                    Severity::Negligible => vulns.negligible += 1,
                    Severity::Unknown => {}
                }
            }

            FixablePackage {
                name: p.name().to_string(),
                package_type: p.package_type().to_string(),
                version: p.version().to_string(),
                suggested_fix: p
                    .vulnerabilities()
                    .iter()
                    .find_map(|v| v.fix_version().map(|s| s.to_string())),
                vulnerabilities: vulns,
                exploits,
            }
        })
        .collect()
}

fn policies_from(value: &ScanResult) -> Vec<PolicyEvaluated> {
    value
        .policies()
        .iter()
        .map(|p| PolicyEvaluated {
            name: p.name().to_string(),
            passed: p.evaluation_result().is_passed(),
            failures: p.bundles().iter().map(|b| b.rules().len()).sum::<usize>() as u32,
            risks_accepted: 0, // Cannot determine this from the current data model
        })
        .sorted_by(|a, b| b.failures.cmp(&a.failures))
        .sorted_by_key(|p| p.passed)
        .collect()
}

fn vulnerabilities_from(value: &ScanResult) -> Vec<VulnerabilityEvaluated> {
    value
        .vulnerabilities()
        .iter()
        .sorted_by_key(|v| v.cve())
        .sorted_by(|a, b| {
            b.found_in_packages()
                .len()
                .cmp(&a.found_in_packages().len())
        })
        .sorted_by(|a, b| b.fixable().cmp(&a.fixable()))
        .sorted_by(|a, b| b.exploitable().cmp(&a.exploitable()))
        .sorted_by_key(|v| v.severity())
        .map(|v| VulnerabilityEvaluated {
            cve: v.cve().to_string(),
            severity: v.severity().to_string(),
            packages_found: v.found_in_packages().len() as u32,
            fixable: v.fixable(),
            exploitable: v.exploitable(),
            accepted_risk: !v.accepted_risks().is_empty(),
        })
        .collect()
}

#[derive(Clone, Debug, Default)]
pub struct MarkdownData {
    pub summary: MarkdownSummary,
    pub fixable_packages: Vec<FixablePackage>,
    pub policies: Vec<PolicyEvaluated>,
    pub vulnerabilities: Vec<VulnerabilityEvaluated>,
}

#[derive(Clone, Debug, Default)]
pub struct MarkdownSummary {
    pub pull_string: String,
    pub image_id: String,
    pub digest: String,
    pub base_os: String,
    pub total_vulns_found: MarkdownSummaryVulns,
}

#[derive(Clone, Debug, Default)]
pub struct MarkdownSummaryVulns {
    pub total_found: u32,
    pub critical: u32,
    pub critical_fixable: u32,
    pub high: u32,
    pub high_fixable: u32,
    pub medium: u32,
    pub medium_fixable: u32,
    pub low: u32,
    pub low_fixable: u32,
    pub negligible: u32,
    pub negligible_fixable: u32,
}

#[derive(Clone, Debug, Default)]
pub struct FixablePackage {
    pub name: String,
    pub package_type: String,
    pub version: String,
    pub suggested_fix: Option<String>,
    pub vulnerabilities: FixablePackageVulnerabilities,
    pub exploits: u32,
}

#[derive(Clone, Debug, Default)]
pub struct FixablePackageVulnerabilities {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub negligible: u32,
}

#[derive(Clone, Debug, Default)]
pub struct PolicyEvaluated {
    pub name: String,
    pub passed: bool,
    pub failures: u32,
    pub risks_accepted: u32,
}

#[derive(Clone, Debug, Default)]
pub struct VulnerabilityEvaluated {
    pub cve: String,
    pub severity: String,
    pub packages_found: u32,
    pub fixable: bool,
    pub exploitable: bool,
    pub accepted_risk: bool,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn converts_markdown_data_to_markdown_text() {
        let markdown_data = MarkdownData {
            summary: MarkdownSummary {
                pull_string: "ubuntu:23.04".to_string(),
                image_id: "sha256:f4cdeba72b994748f5eb1f525a70a9cc553b66037ec37e23645fbf3f0f5c160d"
                    .to_string(),
                digest: "sha256:5a828e28de105c3d7821c4442f0f5d1c52dc16acf4999d5f31a3bc0f03f06edd"
                    .to_string(),
                base_os: "ubuntu 23.04".to_string(),

                total_vulns_found: MarkdownSummaryVulns {
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
            fixable_packages: vec![
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
            ],
            policies: vec![
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
            ],

            vulnerabilities: vec![
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
            ],
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
