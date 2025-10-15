use std::fmt::{Display, Formatter};

use crate::domain::scanresult::scan_result::ScanResult;

use super::markdown_summary_table::MarkdownSummaryTable;

#[derive(Clone, Debug, Default)]
pub struct MarkdownSummary {
    pub pull_string: String,
    pub image_id: String,
    pub digest: Option<String>,
    pub base_os: String,
    pub total_vulns_found: MarkdownSummaryTable,
}

impl From<&ScanResult> for MarkdownSummary {
    fn from(value: &ScanResult) -> Self {
        MarkdownSummary {
            pull_string: value.metadata().pull_string().to_string(),
            image_id: value.metadata().image_id().to_string(),
            digest: value.metadata().digest().map(|s| s.to_string()),
            base_os: value.metadata().base_os().name().to_string(),
            total_vulns_found: MarkdownSummaryTable::from(value),
        }
    }
}

impl Display for MarkdownSummary {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "### Summary")?;
        writeln!(f, "* **PullString**: {}", self.pull_string)?;
        writeln!(f, "* **ImageID**: `{}`", self.image_id)?;
        match &self.digest {
            Some(digest) => writeln!(f, "* **Digest**: `{}`", digest)?,
            None => writeln!(f, "* **Digest**: None")?,
        }
        writeln!(f, "* **BaseOS**: {}", self.base_os)?;
        writeln!(f)?;
        write!(f, "{}", self.total_vulns_found)
    }
}
