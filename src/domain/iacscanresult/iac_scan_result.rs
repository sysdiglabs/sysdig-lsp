use crate::domain::iacscanresult::iac_finding::IacFinding;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IacScanResult {
    pub findings: Vec<IacFinding>,
}
