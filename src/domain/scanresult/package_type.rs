#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum PackageType {
    Unknown,
    Os,
    Python,
    Java,
    Javascript,
    Golang,
    Rust,
    Ruby,
    Php,
    CSharp,
}
