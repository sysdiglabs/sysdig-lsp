use std::{
    fmt::{Display, Formatter},
    sync::Arc,
};

use markdown_table::{Heading, HeadingAlignment, MarkdownTable};

use crate::domain::scanresult::{layer::Layer, scan_result::ScanResult, severity::Severity};

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
pub struct FixablePackageTable(pub Vec<FixablePackage>);

impl From<&ScanResult> for FixablePackageTable {
    fn from(value: &ScanResult) -> Self {
        FixablePackageTable(
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
                        suggested_fix: p.suggested_fix_version().map(|v| v.to_string()),
                        vulnerabilities: vulns,
                        exploits,
                    }
                })
                .collect(),
        )
    }
}

impl From<&Arc<Layer>> for FixablePackageTable {
    fn from(value: &Arc<Layer>) -> Self {
        FixablePackageTable(
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
                        suggested_fix: p.suggested_fix_version().map(|v| v.to_string()),
                        vulnerabilities: vulns,
                        exploits,
                    }
                })
                .collect(),
        )
    }
}

impl Display for FixablePackageTable {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            return f.write_str("");
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
            .0
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

        let format = format!(
            "\n### Fixable Packages\n{}",
            table.as_markdown().unwrap_or_default()
        );

        f.write_str(&format)
    }
}
