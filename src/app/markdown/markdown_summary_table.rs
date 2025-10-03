use std::fmt::{Display, Formatter};

use markdown_table::{Heading, HeadingAlignment, MarkdownTable};

use crate::domain::scanresult::{scan_result::ScanResult, severity::Severity};

#[derive(Clone, Debug, Default)]
pub struct MarkdownSummaryTable {
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

impl From<&ScanResult> for MarkdownSummaryTable {
    fn from(value: &ScanResult) -> Self {
        let mut summary = MarkdownSummaryTable::default();

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
}

impl Display for MarkdownSummaryTable {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
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

        let summary_vulns_line = |total_vulns: u32, fixable_vulns: u32| {
            if fixable_vulns > 0 {
                format!("{} ({} Fixable)", total_vulns, fixable_vulns)
            } else {
                total_vulns.to_string()
            }
        };

        let data = vec![vec![
            self.total_found.to_string(),
            summary_vulns_line(self.critical, self.critical_fixable),
            summary_vulns_line(self.high, self.high_fixable),
            summary_vulns_line(self.medium, self.medium_fixable),
            summary_vulns_line(self.low, self.low_fixable),
            summary_vulns_line(self.negligible, self.negligible_fixable),
        ]];

        let mut table = MarkdownTable::new(data);
        table.with_headings(headers);

        f.write_str(&table.as_markdown().unwrap_or_default())
    }
}
