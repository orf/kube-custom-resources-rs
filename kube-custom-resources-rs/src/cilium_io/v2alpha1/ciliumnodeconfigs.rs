// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/cilium/cilium/cilium.io/v2alpha1/ciliumnodeconfigs.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// Spec is the desired Cilium configuration overrides for a given node
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "cilium.io", version = "v2alpha1", kind = "CiliumNodeConfig", plural = "ciliumnodeconfigs")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct CiliumNodeConfigSpec {
    /// Defaults is treated the same as the cilium-config ConfigMap - a set of key-value pairs parsed by the agent and operator processes. Each key must be a valid config-map data field (i.e. a-z, A-Z, -, _, and .)
    pub defaults: BTreeMap<String, String>,
    /// NodeSelector is a label selector that determines to which nodes this configuration applies. If not supplied, then this config applies to no nodes. If empty, then it applies to all nodes.
    #[serde(rename = "nodeSelector")]
    pub node_selector: CiliumNodeConfigNodeSelector,
}

/// NodeSelector is a label selector that determines to which nodes this configuration applies. If not supplied, then this config applies to no nodes. If empty, then it applies to all nodes.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeConfigNodeSelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<CiliumNodeConfigNodeSelectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeConfigNodeSelectorMatchExpressions {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

