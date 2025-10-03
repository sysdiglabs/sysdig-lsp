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
