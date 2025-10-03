use std::fmt::{Display, Formatter};

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

impl Display for PackageType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                PackageType::Unknown => "unknown",
                PackageType::Os => "os",
                PackageType::Python => "python",
                PackageType::Java => "java",
                PackageType::Javascript => "javascript",
                PackageType::Golang => "golang",
                PackageType::Rust => "rust",
                PackageType::Ruby => "ruby",
                PackageType::Php => "php",
                PackageType::CSharp => "csharp",
            }
        )
    }
}
