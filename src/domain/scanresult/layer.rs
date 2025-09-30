use crate::domain::scanresult::package::Package;
use crate::domain::scanresult::vulnerability::Vulnerability;
use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, RwLock};

pub struct Layer {
    digest: String,
    index: usize,
    size: Option<u64>,
    command: String,
    packages: RwLock<HashSet<Arc<Package>>>,
}

impl Debug for Layer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Layer")
            .field("digest", &self.digest)
            .field("size", &self.size)
            .field("command", &self.command)
            .finish()
    }
}

impl Layer {
    pub(in crate::domain::scanresult) fn new(
        digest: String,
        index: usize,
        size: Option<u64>,
        command: String,
    ) -> Self {
        Self {
            digest,
            index,
            size,
            command,
            packages: RwLock::new(HashSet::new()),
        }
    }

    pub fn digest(&self) -> Option<&str> {
        if self.digest.is_empty() {
            None
        } else {
            Some(&self.digest)
        }
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn size(&self) -> Option<&u64> {
        self.size.as_ref()
    }

    pub fn command(&self) -> &str {
        &self.command
    }

    pub(in crate::domain::scanresult) fn add_package(&self, a_package: Arc<Package>) {
        self.packages.write().unwrap().insert(a_package);
    }

    pub fn packages(&self) -> Vec<Arc<Package>> {
        self.packages.read().unwrap().iter().cloned().collect()
    }

    pub fn vulnerabilities(&self) -> Vec<Arc<Vulnerability>> {
        self.packages
            .read()
            .unwrap()
            .iter()
            .flat_map(|p| p.vulnerabilities())
            .collect()
    }
}

impl PartialEq for Layer {
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest
    }
}

impl Eq for Layer {}

impl Hash for Layer {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.digest.hash(state);
    }
}
