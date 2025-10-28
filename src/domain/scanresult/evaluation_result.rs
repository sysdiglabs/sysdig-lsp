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

impl From<&str> for EvaluationResult {
    fn from(value: &str) -> Self {
        if value.eq_ignore_ascii_case("failed") {
            EvaluationResult::Failed
        } else {
            EvaluationResult::Passed
        }
    }
}
