use std::{
    fmt::{Display, Formatter},
    sync::Arc,
};

use crate::domain::scanresult::layer::Layer;

use super::{
    markdown_fixable_package_table::FixablePackageTable,
    markdown_vulnerability_evaluated_table::VulnerabilityEvaluatedTable,
};

pub struct MarkdownLayerData {
    pub fixable_packages: FixablePackageTable,
    pub vulnerabilities: VulnerabilityEvaluatedTable,
}

impl From<Arc<Layer>> for MarkdownLayerData {
    fn from(value: Arc<Layer>) -> Self {
        Self {
            fixable_packages: FixablePackageTable::from(&value),
            vulnerabilities: VulnerabilityEvaluatedTable::from(&value),
        }
    }
}

impl Display for MarkdownLayerData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let fixable_packages_section = self.fixable_packages.to_string();
        let vulnerability_detail_section = self.vulnerabilities.to_string();

        write!(
            f,
            "## Sysdig Scan Result for Layer\n{}\n{}",
            fixable_packages_section, vulnerability_detail_section
        )
    }
}
