#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AcceptedRiskReason {
    RiskOwned,
    RiskTransferred,
    RiskAvoided,
    RiskMitigated,
    RiskNotRelevant,
    Custom,
    Unknown,
}
