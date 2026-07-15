use crate::domain::iacscanresult::{iac_resource::IacResource, iac_severity::IacSeverity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IacFinding {
    pub name: String,
    pub severity: IacSeverity,
    pub resources: Vec<IacResource>,
}
