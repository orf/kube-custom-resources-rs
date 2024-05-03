// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/cilium/cilium/cilium.io/v2alpha1/ciliumloadbalancerippools.yaml --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use std::collections::BTreeMap;
    pub use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
}
use self::prelude::*;

/// Spec is a human readable description for a BGP load balancer ip pool.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "cilium.io", version = "v2alpha1", kind = "CiliumLoadBalancerIPPool", plural = "ciliumloadbalancerippools")]
#[kube(status = "CiliumLoadBalancerIPPoolStatus")]
#[kube(schema = "disabled")]
#[kube(derive="PartialEq")]
pub struct CiliumLoadBalancerIPPoolSpec {
    /// AllowFirstLastIPs, if set to `yes` means that the first and last IPs of each CIDR will be allocatable. If `no` or undefined, these IPs will be reserved. This field is ignored for /{31,32} and /{127,128} CIDRs since reserving the first and last IPs would make the CIDRs unusable.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "allowFirstLastIPs")]
    pub allow_first_last_i_ps: Option<CiliumLoadBalancerIPPoolAllowFirstLastIPs>,
    /// Blocks is a list of CIDRs comprising this IP Pool
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocks: Option<Vec<CiliumLoadBalancerIPPoolBlocks>>,
    /// Cidrs is a list of CIDRs comprising this IP Pool Deprecated: please use the `blocks` field instead. This field will be removed in a future release. https://github.com/cilium/cilium/issues/28590
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidrs: Option<Vec<CiliumLoadBalancerIPPoolCidrs>>,
    /// Disabled, if set to true means that no new IPs will be allocated from this pool. Existing allocations will not be removed from services.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    /// ServiceSelector selects a set of services which are eligible to receive IPs from this
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "serviceSelector")]
    pub service_selector: Option<CiliumLoadBalancerIPPoolServiceSelector>,
}

/// Spec is a human readable description for a BGP load balancer ip pool.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum CiliumLoadBalancerIPPoolAllowFirstLastIPs {
    Yes,
    No,
}

/// CiliumLoadBalancerIPPoolIPBlock describes a single IP block.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CiliumLoadBalancerIPPoolBlocks {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<String>,
}

/// CiliumLoadBalancerIPPoolIPBlock describes a single IP block.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CiliumLoadBalancerIPPoolCidrs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<String>,
}

/// ServiceSelector selects a set of services which are eligible to receive IPs from this
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CiliumLoadBalancerIPPoolServiceSelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<CiliumLoadBalancerIPPoolServiceSelectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CiliumLoadBalancerIPPoolServiceSelectorMatchExpressions {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: CiliumLoadBalancerIPPoolServiceSelectorMatchExpressionsOperator,
    /// values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum CiliumLoadBalancerIPPoolServiceSelectorMatchExpressionsOperator {
    In,
    NotIn,
    Exists,
    DoesNotExist,
}

/// Status is the status of the IP Pool. 
///  It might be possible for users to define overlapping IP Pools, we can't validate or enforce non-overlapping pools during object creation. The Cilium operator will do this validation and update the status to reflect the ability to allocate IPs from this pool.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CiliumLoadBalancerIPPoolStatus {
    /// Current service state
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
}

