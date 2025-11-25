use crate::domain::scanresult::evaluation_result::EvaluationResult;
use crate::domain::scanresult::policy_bundle::PolicyBundle;
use crate::domain::scanresult::policy_bundle_rule_failure::PolicyBundleRuleFailure;
use crate::domain::scanresult::policy_bundle_rule_image_config_failure::PolicyBundleRuleImageConfigFailure;
use crate::domain::scanresult::policy_bundle_rule_pkg_vuln_failure::PolicyBundleRulePkgVulnFailure;
use crate::domain::scanresult::weak_hash::WeakHash;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, RwLock, Weak};

pub struct PolicyBundleRule {
    id: String,
    description: String,
    evaluation_result: EvaluationResult,
    parent: WeakHash<PolicyBundle>,
    failures: RwLock<Vec<PolicyBundleRuleFailure>>,
}

impl PartialEq for PolicyBundleRule {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.description == other.description
            && self.evaluation_result == other.evaluation_result
            && self.parent == other.parent
    }
}

impl Eq for PolicyBundleRule {}

impl Hash for PolicyBundleRule {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.description.hash(state);
        self.evaluation_result.hash(state);
        self.parent.hash(state);
    }
}

impl Clone for PolicyBundleRule {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            description: self.description.clone(),
            evaluation_result: self.evaluation_result,
            parent: self.parent.clone(),
            failures: RwLock::new(
                self.failures
                    .read()
                    .unwrap_or_else(|e| panic!("RwLock poisoned in policy_bundle_rule.rs: {}", e))
                    .clone(),
            ),
        }
    }
}

impl PolicyBundleRule {
    pub(in crate::domain::scanresult) fn new(
        id: String,
        description: String,
        evaluation_result: EvaluationResult,
        parent: Weak<PolicyBundle>,
    ) -> Self {
        Self {
            id,
            description,
            evaluation_result,
            parent: WeakHash(parent),
            failures: RwLock::new(Vec::new()),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn evaluation_result(&self) -> &EvaluationResult {
        &self.evaluation_result
    }

    pub fn parent(&self) -> &Weak<PolicyBundle> {
        &self.parent.0
    }

    pub fn add_image_config_failure(
        self: &Arc<Self>,
        remediation: String,
    ) -> PolicyBundleRuleImageConfigFailure {
        let failure = PolicyBundleRuleImageConfigFailure::new(remediation, Arc::downgrade(self));
        self.failures
            .write()
            .unwrap_or_else(|e| panic!("RwLock poisoned in policy_bundle_rule.rs: {}", e))
            .push(PolicyBundleRuleFailure::ImageConfig(failure.clone()));
        failure
    }

    pub fn add_pkg_vuln_failure(
        self: &Arc<Self>,
        description: String,
    ) -> PolicyBundleRulePkgVulnFailure {
        let failure = PolicyBundleRulePkgVulnFailure::new(description, Arc::downgrade(self));
        self.failures
            .write()
            .unwrap_or_else(|e| panic!("RwLock poisoned in policy_bundle_rule.rs: {}", e))
            .push(PolicyBundleRuleFailure::PkgVuln(failure.clone()));
        failure
    }

    pub fn failures(&self) -> Vec<PolicyBundleRuleFailure> {
        self.failures
            .read()
            .unwrap_or_else(|e| panic!("RwLock poisoned in policy_bundle_rule.rs: {}", e))
            .clone()
    }
}
