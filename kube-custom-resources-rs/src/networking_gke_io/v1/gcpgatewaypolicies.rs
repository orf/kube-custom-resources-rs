// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/GoogleCloudPlatform/gke-networking-recipes/networking.gke.io/v1/gcpgatewaypolicies.yaml --derive=Default --derive=PartialEq --smart-derive-elision
// kopium version: 0.21.1

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
}
use self::prelude::*;

/// Spec defines the desired state of GCPGatewayPolicy.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "networking.gke.io", version = "v1", kind = "GCPGatewayPolicy", plural = "gcpgatewaypolicies")]
#[kube(namespaced)]
#[kube(status = "GCPGatewayPolicyStatus")]
#[kube(schema = "disabled")]
#[kube(derive="Default")]
#[kube(derive="PartialEq")]
pub struct GCPGatewayPolicySpec {
    /// Default defines default gateway policy configuration for the targeted resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<GCPGatewayPolicyDefault>,
    /// TargetRef identifies an API object to apply policy to.
    #[serde(rename = "targetRef")]
    pub target_ref: GCPGatewayPolicyTargetRef,
}

/// Default defines default gateway policy configuration for the targeted resource.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct GCPGatewayPolicyDefault {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "allowGlobalAccess")]
    pub allow_global_access: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sslPolicy")]
    pub ssl_policy: Option<String>,
}

/// TargetRef identifies an API object to apply policy to.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct GCPGatewayPolicyTargetRef {
    /// Group is the group of the target resource.
    pub group: String,
    /// Kind is kind of the target resource.
    pub kind: String,
    /// Name is the name of the target resource.
    pub name: String,
    /// Namespace is the namespace of the referent. When unspecified, the local namespace is inferred. Even when policy targets a resource in a different namespace, it MUST only apply to traffic originating from the same namespace as the policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// Status defines the current state of GCPGatewayPolicy.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct GCPGatewayPolicyStatus {
    /// Conditions describe the current conditions of the GatewayPolicy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
}
