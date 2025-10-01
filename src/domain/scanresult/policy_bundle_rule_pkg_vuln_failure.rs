use crate::domain::scanresult::policy_bundle_rule::PolicyBundleRule;
use crate::domain::scanresult::weak_hash::WeakHash;
use std::sync::Weak;

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct PolicyBundleRulePkgVulnFailure {
    remediation: String,
    parent: WeakHash<PolicyBundleRule>,
}

impl PolicyBundleRulePkgVulnFailure {
    pub(in crate::domain::scanresult) fn new(
        remediation: String,
        parent: Weak<PolicyBundleRule>,
    ) -> Self {
        Self {
            remediation,
            parent: WeakHash(parent),
        }
    }

    pub fn remediation(&self) -> &str {
        &self.remediation
    }

    pub fn parent(&self) -> &Weak<PolicyBundleRule> {
        &self.parent.0
    }
}
