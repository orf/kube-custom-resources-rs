// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/istio/istio/security.istio.io/v1beta1/authorizationpolicies.yaml --derive=Default --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use std::collections::BTreeMap;
}
use self::prelude::*;

/// Configuration for access control on workloads. See more details at: https://istio.io/docs/reference/config/security/authorization-policy.html
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "security.istio.io", version = "v1beta1", kind = "AuthorizationPolicy", plural = "authorizationpolicies")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
#[kube(derive="Default")]
#[kube(derive="PartialEq")]
pub struct AuthorizationPolicySpec {
    /// Optional.
    /// 
    /// Valid Options: ALLOW, DENY, AUDIT, CUSTOM
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<AuthorizationPolicyAction>,
    /// Specifies detailed configuration of the CUSTOM action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<AuthorizationPolicyProvider>,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<AuthorizationPolicyRules>>,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<AuthorizationPolicySelector>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "targetRef")]
    pub target_ref: Option<AuthorizationPolicyTargetRef>,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "targetRefs")]
    pub target_refs: Option<Vec<AuthorizationPolicyTargetRefs>>,
}

/// Configuration for access control on workloads. See more details at: https://istio.io/docs/reference/config/security/authorization-policy.html
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum AuthorizationPolicyAction {
    #[serde(rename = "ALLOW")]
    Allow,
    #[serde(rename = "DENY")]
    Deny,
    #[serde(rename = "AUDIT")]
    Audit,
    #[serde(rename = "CUSTOM")]
    Custom,
}

/// Specifies detailed configuration of the CUSTOM action.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AuthorizationPolicyProvider {
    /// Specifies the name of the extension provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AuthorizationPolicyRules {
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<Vec<AuthorizationPolicyRulesFrom>>,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<Vec<AuthorizationPolicyRulesTo>>,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<Vec<AuthorizationPolicyRulesWhen>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AuthorizationPolicyRulesFrom {
    /// Source specifies the source of a request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<AuthorizationPolicyRulesFromSource>,
}

/// Source specifies the source of a request.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AuthorizationPolicyRulesFromSource {
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ipBlocks")]
    pub ip_blocks: Option<Vec<String>>,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<Vec<String>>,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "notIpBlocks")]
    pub not_ip_blocks: Option<Vec<String>>,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "notNamespaces")]
    pub not_namespaces: Option<Vec<String>>,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "notPrincipals")]
    pub not_principals: Option<Vec<String>>,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "notRemoteIpBlocks")]
    pub not_remote_ip_blocks: Option<Vec<String>>,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "notRequestPrincipals")]
    pub not_request_principals: Option<Vec<String>>,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principals: Option<Vec<String>>,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "remoteIpBlocks")]
    pub remote_ip_blocks: Option<Vec<String>>,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "requestPrincipals")]
    pub request_principals: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AuthorizationPolicyRulesTo {
    /// Operation specifies the operation of a request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<AuthorizationPolicyRulesToOperation>,
}

/// Operation specifies the operation of a request.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AuthorizationPolicyRulesToOperation {
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts: Option<Vec<String>>,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<String>>,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "notHosts")]
    pub not_hosts: Option<Vec<String>>,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "notMethods")]
    pub not_methods: Option<Vec<String>>,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "notPaths")]
    pub not_paths: Option<Vec<String>>,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "notPorts")]
    pub not_ports: Option<Vec<String>>,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<String>>,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AuthorizationPolicyRulesWhen {
    /// The name of an Istio attribute.
    pub key: String,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "notValues")]
    pub not_values: Option<Vec<String>>,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// Optional.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AuthorizationPolicySelector {
    /// One or more labels that indicate a specific set of pods/VMs on which a policy should be applied.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AuthorizationPolicyTargetRef {
    /// group is the group of the target resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// kind is kind of the target resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// name is the name of the target resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// namespace is the namespace of the referent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AuthorizationPolicyTargetRefs {
    /// group is the group of the target resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// kind is kind of the target resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// name is the name of the target resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// namespace is the namespace of the referent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

