#[derive(PartialEq, Eq, Hash, Clone, Copy, PartialOrd, Ord, Debug)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Negligible,
    Unknown,
}
