#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum Family {
    Linux,
    Darwin,
    Windows,
    Unknown,
}

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct OperatingSystem {
    family: Family,
    name: String,
}

impl OperatingSystem {
    pub fn new(family: Family, name: String) -> Self {
        Self { family, name }
    }

    pub fn family(&self) -> Family {
        self.family
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}
