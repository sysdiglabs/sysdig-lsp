use crate::domain::scanresult::architecture::Architecture;
use crate::domain::scanresult::operating_system::OperatingSystem;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(PartialEq, Eq, Clone)]
pub struct Metadata {
    pull_string: String,
    image_id: String,
    digest: Option<String>,
    base_os: OperatingSystem,
    size_in_bytes: u64,
    architecture: Architecture,
    labels: HashMap<String, String>,
    created_at: DateTime<Utc>,
}

impl Metadata {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::domain::scanresult) fn new(
        pull_string: String,
        image_id: String,
        digest: Option<String>,
        base_os: OperatingSystem,
        size_in_bytes: u64,
        architecture: Architecture,
        labels: HashMap<String, String>,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            pull_string,
            image_id,
            digest,
            base_os,
            size_in_bytes,
            architecture,
            labels,
            created_at,
        }
    }

    pub fn pull_string(&self) -> &str {
        &self.pull_string
    }

    pub fn image_id(&self) -> &str {
        &self.image_id
    }

    pub fn digest(&self) -> Option<&str> {
        self.digest.as_deref()
    }

    pub fn base_os(&self) -> &OperatingSystem {
        &self.base_os
    }

    pub fn size_in_bytes(&self) -> &u64 {
        &self.size_in_bytes
    }

    pub fn architecture(&self) -> &Architecture {
        &self.architecture
    }

    pub fn labels(&self) -> &HashMap<String, String> {
        &self.labels
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}
