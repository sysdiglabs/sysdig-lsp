use crate::domain::scanresult::accepted_risk_reason::AcceptedRiskReason;
use crate::domain::scanresult::package::Package;
use crate::domain::scanresult::vulnerability::Vulnerability;
use crate::domain::scanresult::weak_hash::WeakHash;
use chrono::{DateTime, NaiveDate, Utc};
use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, RwLock};

pub struct AcceptedRisk {
    id: String,
    reason: AcceptedRiskReason,
    description: String,
    expiration_date: Option<NaiveDate>,
    is_active: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    assigned_to_vulnerabilities: RwLock<HashSet<WeakHash<Vulnerability>>>,
    assigned_to_packages: RwLock<HashSet<WeakHash<Package>>>,
}

impl Debug for AcceptedRisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcceptedRisk")
            .field("id", &self.id)
            .field("reason", &self.reason)
            .field("description", &self.description)
            .field("expiration_date", &self.expiration_date)
            .field("is_active", &self.is_active)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl AcceptedRisk {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::domain::scanresult) fn new(
        id: String,
        reason: AcceptedRiskReason,
        description: String,
        expiration_date: Option<NaiveDate>,
        is_active: bool,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            reason,
            description,
            expiration_date,
            is_active,
            created_at,
            updated_at,
            assigned_to_vulnerabilities: RwLock::new(HashSet::new()),
            assigned_to_packages: RwLock::new(HashSet::new()),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn reason(&self) -> &AcceptedRiskReason {
        &self.reason
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn expiration_date(&self) -> Option<NaiveDate> {
        self.expiration_date
    }

    pub fn is_active(&self) -> bool {
        self.is_active
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    pub fn add_for_vulnerability(self: &Arc<Self>, vulnerability: Arc<Vulnerability>) {
        if self
            .assigned_to_vulnerabilities
            .write()
            .unwrap_or_else(|e| panic!("RwLock poisoned in accepted_risk.rs: {}", e))
            .insert(WeakHash(Arc::downgrade(&vulnerability)))
        {
            vulnerability.add_accepted_risk(self.clone());
        }
    }

    pub fn assigned_to_vulnerabilities(self: &Arc<Self>) -> Vec<Arc<Vulnerability>> {
        self.assigned_to_vulnerabilities
            .read()
            .unwrap_or_else(|e| panic!("RwLock poisoned in accepted_risk.rs: {}", e))
            .iter()
            .filter_map(|v| v.0.upgrade())
            .collect()
    }

    pub fn add_for_package(self: &Arc<Self>, a_package: Arc<Package>) {
        if self
            .assigned_to_packages
            .write()
            .unwrap_or_else(|e| panic!("RwLock poisoned in accepted_risk.rs: {}", e))
            .insert(WeakHash(Arc::downgrade(&a_package)))
        {
            a_package.add_accepted_risk(self.clone());
        }
    }

    pub fn assigned_to_packages(self: &Arc<Self>) -> Vec<Arc<Package>> {
        self.assigned_to_packages
            .read()
            .unwrap_or_else(|e| panic!("RwLock poisoned in accepted_risk.rs: {}", e))
            .iter()
            .filter_map(|p| p.0.upgrade())
            .collect()
    }
}

impl PartialEq for AcceptedRisk {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for AcceptedRisk {}

impl Hash for AcceptedRisk {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}
