use std::fmt::{Display, Formatter};

use itertools::Itertools;
use markdown_table::{Heading, HeadingAlignment, MarkdownTable};

use crate::domain::scanresult::scan_result::ScanResult;

#[derive(Clone, Debug, Default)]
pub struct PolicyEvaluated {
    pub name: String,
    pub passed: bool,
    pub failures: u32,
    pub risks_accepted: u32,
}

#[derive(Clone, Debug, Default)]
pub struct PolicyEvaluatedTable(pub Vec<PolicyEvaluated>);

impl Display for PolicyEvaluatedTable {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            return f.write_str("");
        }

        let headers = vec![
            Heading::new("POLICY".to_string(), Some(HeadingAlignment::Left)),
            Heading::new("STATUS".to_string(), Some(HeadingAlignment::Center)),
            Heading::new("FAILURES".to_string(), Some(HeadingAlignment::Center)),
            Heading::new("RISKS ACCEPTED".to_string(), Some(HeadingAlignment::Center)),
        ];

        let data = self
            .0
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

        let format = format!(
            "\n### Policy Evaluation\n\n{}",
            table.as_markdown().unwrap_or_default()
        );

        f.write_str(&format)
    }
}

impl From<&ScanResult> for PolicyEvaluatedTable {
    fn from(value: &ScanResult) -> Self {
        PolicyEvaluatedTable(
            value
                .policies()
                .iter()
                .map(|p| PolicyEvaluated {
                    name: p.name().to_string(),
                    passed: p.evaluation_result().is_passed(),
                    failures: p.bundles().iter().map(|b| b.rules().len()).sum::<usize>() as u32,
                    risks_accepted: 0, // FIXME(fede): Cannot determine this from the current data model
                })
                .sorted_by(|a, b| b.failures.cmp(&a.failures))
                .sorted_by_key(|p| p.passed)
                .collect(),
        )
    }
}
