use crate::domain::scanresult::policy_bundle_rule::PolicyBundleRule;
use crate::domain::scanresult::weak_hash::WeakHash;
use std::sync::Weak;

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct PolicyBundleRuleImageConfigFailure {
    description: String,
    parent: WeakHash<PolicyBundleRule>,
}

impl PolicyBundleRuleImageConfigFailure {
    pub(in crate::domain::scanresult) fn new(
        description: String,
        parent: Weak<PolicyBundleRule>,
    ) -> Self {
        Self {
            description,
            parent: WeakHash(parent),
        }
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn parent(&self) -> &Weak<PolicyBundleRule> {
        &self.parent.0
    }
}
