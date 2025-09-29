use crate::domain::scanresult::evaluation_result::EvaluationResult;
use crate::domain::scanresult::policy::Policy;
use crate::domain::scanresult::policy_bundle_rule::PolicyBundleRule;
use crate::domain::scanresult::weak_hash::WeakHash;
use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, RwLock};

pub struct PolicyBundle {
    id: String,
    name: String,
    rules: RwLock<HashSet<Arc<PolicyBundleRule>>>,
    found_in_policies: RwLock<HashSet<WeakHash<Policy>>>,
}

impl Debug for PolicyBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyBundle")
            .field("id", &self.id)
            .field("name", &self.name)
            .finish()
    }
}

impl PolicyBundle {
    pub(in crate::domain::scanresult) fn new(id: String, name: String) -> Self {
        Self {
            id,
            name,
            rules: RwLock::new(HashSet::new()),
            found_in_policies: RwLock::new(HashSet::new()),
        }
    }

    pub fn add_policy(self: &Arc<Self>, policy: Arc<Policy>) {
        if self
            .found_in_policies
            .write()
            .unwrap()
            .insert(WeakHash(Arc::downgrade(&policy)))
        {
            policy.add_bundle(self);
        }
    }

    pub fn add_rule(
        self: &Arc<Self>,
        id: String,
        description: String,
        evaluation_result: EvaluationResult,
    ) -> Arc<PolicyBundleRule> {
        let rule = Arc::new(PolicyBundleRule::new(
            id,
            description,
            evaluation_result,
            Arc::downgrade(self),
        ));
        self.rules.write().unwrap().insert(rule.clone());
        rule
    }

    pub fn found_in_policies(&self) -> Vec<Arc<Policy>> {
        self.found_in_policies
            .read()
            .unwrap()
            .iter()
            .filter_map(|p| p.0.upgrade())
            .collect()
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn rules(&self) -> Vec<Arc<PolicyBundleRule>> {
        self.rules.read().unwrap().iter().cloned().collect()
    }

    pub fn evaluation_result(&self) -> EvaluationResult {
        if self
            .rules()
            .iter()
            .all(|r| r.evaluation_result().is_passed())
        {
            EvaluationResult::Passed
        } else {
            EvaluationResult::Failed
        }
    }
}

impl PartialEq for PolicyBundle {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for PolicyBundle {}

impl Hash for PolicyBundle {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}
