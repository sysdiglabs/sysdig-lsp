use crate::domain::scanresult::evaluation_result::EvaluationResult;
use crate::domain::scanresult::policy_bundle::PolicyBundle;
use crate::domain::scanresult::weak_hash::WeakHash;
use chrono::{DateTime, Utc};
use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, RwLock};

pub struct Policy {
    id: String,
    name: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    bundles: RwLock<HashSet<WeakHash<PolicyBundle>>>,
}

impl Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Policy")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl Policy {
    pub(in crate::domain::scanresult) fn new(
        id: String,
        name: String,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            name,
            created_at,
            updated_at,
            bundles: RwLock::new(HashSet::new()),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    pub fn add_bundle(self: &Arc<Self>, policy_bundle: &Arc<PolicyBundle>) {
        if self
            .bundles
            .write()
            .unwrap()
            .insert(WeakHash(Arc::downgrade(policy_bundle)))
        {
            policy_bundle.add_policy(self.clone());
        }
    }

    pub fn bundles(&self) -> Vec<Arc<PolicyBundle>> {
        self.bundles
            .read()
            .unwrap()
            .iter()
            .filter_map(|b| b.0.upgrade())
            .collect()
    }

    pub fn evaluation_result(&self) -> EvaluationResult {
        if self
            .bundles()
            .iter()
            .all(|b| b.evaluation_result().is_passed())
        {
            EvaluationResult::Passed
        } else {
            EvaluationResult::Failed
        }
    }
}

impl PartialEq for Policy {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Policy {}

impl Hash for Policy {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}
