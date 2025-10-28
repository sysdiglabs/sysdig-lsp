use crate::domain::scanresult::accepted_risk::AcceptedRisk;
use crate::domain::scanresult::layer::Layer;
use crate::domain::scanresult::package_type::PackageType;
use crate::domain::scanresult::vulnerability::Vulnerability;
use crate::domain::scanresult::weak_hash::WeakHash;
use semver::Version;
use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, RwLock};

pub struct Package {
    package_type: PackageType,
    name: String,
    version: Version,
    path: String,
    found_in_layer: Arc<Layer>,
    vulnerabilities: RwLock<HashSet<WeakHash<Vulnerability>>>,
    accepted_risks: RwLock<HashSet<WeakHash<AcceptedRisk>>>,
}

impl Debug for Package {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Package")
            .field("package_type", &self.package_type)
            .field("name", &self.name)
            .field("version", &self.version)
            .field("path", &self.path)
            .field("found_in_layer", &self.found_in_layer)
            .finish()
    }
}

impl Package {
    pub(in crate::domain::scanresult) fn new(
        package_type: PackageType,
        name: String,
        version: Version,
        path: String,
        found_in_layer: Arc<Layer>,
    ) -> Self {
        Self {
            package_type,
            name,
            version,
            path,
            found_in_layer,
            vulnerabilities: RwLock::new(HashSet::new()),
            accepted_risks: RwLock::new(HashSet::new()),
        }
    }

    pub fn package_type(&self) -> &PackageType {
        &self.package_type
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> &Version {
        &self.version
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn found_in_layer(&self) -> &Arc<Layer> {
        &self.found_in_layer
    }

    pub fn add_vulnerability_found(self: &Arc<Self>, vulnerability: Arc<Vulnerability>) {
        if self
            .vulnerabilities
            .write()
            .unwrap()
            .insert(WeakHash(Arc::downgrade(&vulnerability)))
        {
            vulnerability.add_found_in_package(self.clone());
        }
    }

    pub fn vulnerabilities(&self) -> Vec<Arc<Vulnerability>> {
        self.vulnerabilities
            .read()
            .unwrap()
            .iter()
            .filter_map(|v| v.0.upgrade())
            .collect()
    }

    pub fn add_accepted_risk(self: &Arc<Self>, accepted_risk: Arc<AcceptedRisk>) {
        if self
            .accepted_risks
            .write()
            .unwrap()
            .insert(WeakHash(Arc::downgrade(&accepted_risk)))
        {
            accepted_risk.add_for_package(self.clone());
        }
    }

    pub fn accepted_risks(&self) -> Vec<Arc<AcceptedRisk>> {
        self.accepted_risks
            .read()
            .unwrap()
            .iter()
            .filter_map(|r| r.0.upgrade())
            .collect()
    }
}

impl PartialEq for Package {
    fn eq(&self, other: &Self) -> bool {
        self.package_type == other.package_type
            && self.name == other.name
            && self.version == other.version
            && self.path == other.path
    }
}

impl Eq for Package {}

impl Hash for Package {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.package_type.hash(state);
        self.name.hash(state);
        self.version.hash(state);
        self.path.hash(state);
    }
}

impl Clone for Package {
    fn clone(&self) -> Self {
        Self {
            package_type: self.package_type,
            name: self.name.clone(),
            version: self.version.clone(),
            path: self.path.clone(),
            found_in_layer: self.found_in_layer.clone(),
            vulnerabilities: RwLock::new(self.vulnerabilities.read().unwrap().clone()),
            accepted_risks: RwLock::new(self.accepted_risks.read().unwrap().clone()),
        }
    }
}
