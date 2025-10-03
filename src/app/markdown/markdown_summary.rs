use std::fmt::{Display, Formatter};

use crate::domain::scanresult::scan_result::ScanResult;

use super::markdown_summary_table::MarkdownSummaryTable;

#[derive(Clone, Debug, Default)]
pub struct MarkdownSummary {
    pub pull_string: String,
    pub image_id: String,
    pub digest: String,
    pub base_os: String,
    pub total_vulns_found: MarkdownSummaryTable,
}

impl From<&ScanResult> for MarkdownSummary {
    fn from(value: &ScanResult) -> Self {
        MarkdownSummary {
            pull_string: value.metadata().pull_string().to_string(),
            image_id: value.metadata().image_id().to_string(),
            digest: value.metadata().digest().unwrap_or("").to_string(),
            base_os: value.metadata().base_os().name().to_string(),
            total_vulns_found: MarkdownSummaryTable::from(value),
        }
    }
}

impl Display for MarkdownSummary {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let format = format!(
            "### Summary\n* **PullString**: {}\n* **ImageID**: `{}`\n* **Digest**: `{}`\n* **BaseOS**: {}\n\n{}",
            &self.pull_string, &self.image_id, &self.digest, &self.base_os, &self.total_vulns_found
        );

        f.write_str(&format)
    }
}
