use crate::domain::scanresult::policy_bundle_rule_image_config_failure::PolicyBundleRuleImageConfigFailure;
use crate::domain::scanresult::policy_bundle_rule_pkg_vuln_failure::PolicyBundleRulePkgVulnFailure;

#[derive(PartialEq, Eq, Hash, Clone)]
pub enum PolicyBundleRuleFailure {
    ImageConfig(PolicyBundleRuleImageConfigFailure),
    PkgVuln(PolicyBundleRulePkgVulnFailure),
}
