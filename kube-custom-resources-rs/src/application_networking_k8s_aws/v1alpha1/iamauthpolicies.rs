// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws/aws-application-networking-k8s/application-networking.k8s.aws/v1alpha1/iamauthpolicies.yaml --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// IAMAuthPolicySpec defines the desired state of IAMAuthPolicy. When the controller handles IAMAuthPolicy creation, if the targetRef k8s and VPC Lattice resource exists, the controller will change the auth_type of that VPC Lattice resource to AWS_IAM and attach this policy. When the controller handles IAMAuthPolicy deletion, if the targetRef k8s and VPC Lattice resource exists, the controller will change the auth_type of that VPC Lattice resource to NONE and detach this policy.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "application-networking.k8s.aws", version = "v1alpha1", kind = "IAMAuthPolicy", plural = "iamauthpolicies")]
#[kube(namespaced)]
#[kube(status = "IAMAuthPolicyStatus")]
#[kube(schema = "disabled")]
pub struct IAMAuthPolicySpec {
    /// IAM auth policy content. It is a JSON string that uses the same syntax as AWS IAM policies. Please check the VPC Lattice documentation to get [the common elements in an auth policy](https://docs.aws.amazon.com/vpc-lattice/latest/ug/auth-policies.html#auth-policies-common-elements)
    pub policy: String,
    /// TargetRef points to the Kubernetes Gateway, HTTPRoute, or GRPCRoute resource that will have this policy attached. 
    ///  This field is following the guidelines of Kubernetes Gateway API policy attachment.
    #[serde(rename = "targetRef")]
    pub target_ref: IAMAuthPolicyTargetRef,
}

/// TargetRef points to the Kubernetes Gateway, HTTPRoute, or GRPCRoute resource that will have this policy attached. 
///  This field is following the guidelines of Kubernetes Gateway API policy attachment.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IAMAuthPolicyTargetRef {
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

/// Status defines the current state of IAMAuthPolicy.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IAMAuthPolicyStatus {
    /// Conditions describe the current conditions of the IAMAuthPolicy. 
    ///  Implementations should prefer to express Policy conditions using the `PolicyConditionType` and `PolicyConditionReason` constants so that operators and tools can converge on a common vocabulary to describe IAMAuthPolicy state. 
    ///  Known condition types are: 
    ///  * "Accepted" * "Ready"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
}

