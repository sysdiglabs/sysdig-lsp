#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum EvaluationResult {
    Passed,
    Failed,
}

impl EvaluationResult {
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed)
    }

    pub fn is_passed(&self) -> bool {
        matches!(self, Self::Passed)
    }
}
