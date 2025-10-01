#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum Architecture {
    Amd64,
    Arm64,
    Unknown,
}
