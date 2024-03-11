// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kumahq/kuma/kuma.io/v1alpha1/meshtcproutes.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// Spec is the specification of the Kuma MeshTCPRoute resource.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "kuma.io", version = "v1alpha1", kind = "MeshTCPRoute", plural = "meshtcproutes")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct MeshTCPRouteSpec {
    /// TargetRef is a reference to the resource the policy takes an effect on.
    /// The resource could be either a real store object or virtual resource
    /// defined in-place.
    #[serde(rename = "targetRef")]
    pub target_ref: MeshTCPRouteTargetRef,
    /// To list makes a match between the consumed services and corresponding
    /// configurations
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<Vec<MeshTCPRouteTo>>,
}

/// TargetRef is a reference to the resource the policy takes an effect on.
/// The resource could be either a real store object or virtual resource
/// defined in-place.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MeshTCPRouteTargetRef {
    /// Kind of the referenced resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<MeshTCPRouteTargetRefKind>,
    /// Mesh is reserved for future use to identify cross mesh resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh: Option<String>,
    /// Name of the referenced resource. Can only be used with kinds: `MeshService`,
    /// `MeshServiceSubset` and `MeshGatewayRoute`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// ProxyTypes specifies the data plane types that are subject to the policy. When not specified,
    /// all data plane types are targeted by the policy.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "proxyTypes")]
    pub proxy_types: Option<Vec<String>>,
    /// Tags used to select a subset of proxies by tags. Can only be used with kinds
    /// `MeshSubset` and `MeshServiceSubset`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,
}

/// TargetRef is a reference to the resource the policy takes an effect on.
/// The resource could be either a real store object or virtual resource
/// defined in-place.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum MeshTCPRouteTargetRefKind {
    Mesh,
    MeshSubset,
    MeshGateway,
    MeshService,
    MeshServiceSubset,
    #[serde(rename = "MeshHTTPRoute")]
    MeshHttpRoute,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MeshTCPRouteTo {
    /// Rules contains the routing rules applies to a combination of top-level
    /// targetRef and the targetRef in this entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<MeshTCPRouteToRules>>,
    /// TargetRef is a reference to the resource that represents a group of
    /// destinations.
    #[serde(rename = "targetRef")]
    pub target_ref: MeshTCPRouteToTargetRef,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MeshTCPRouteToRules {
    /// Default holds routing rules that can be merged with rules from other
    /// policies.
    pub default: MeshTCPRouteToRulesDefault,
}

/// Default holds routing rules that can be merged with rules from other
/// policies.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MeshTCPRouteToRulesDefault {
    #[serde(rename = "backendRefs")]
    pub backend_refs: Vec<MeshTCPRouteToRulesDefaultBackendRefs>,
}

/// BackendRef defines where to forward traffic.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MeshTCPRouteToRulesDefaultBackendRefs {
    /// Kind of the referenced resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<MeshTCPRouteToRulesDefaultBackendRefsKind>,
    /// Mesh is reserved for future use to identify cross mesh resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh: Option<String>,
    /// Name of the referenced resource. Can only be used with kinds: `MeshService`,
    /// `MeshServiceSubset` and `MeshGatewayRoute`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// ProxyTypes specifies the data plane types that are subject to the policy. When not specified,
    /// all data plane types are targeted by the policy.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "proxyTypes")]
    pub proxy_types: Option<Vec<String>>,
    /// Tags used to select a subset of proxies by tags. Can only be used with kinds
    /// `MeshSubset` and `MeshServiceSubset`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<i64>,
}

/// BackendRef defines where to forward traffic.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum MeshTCPRouteToRulesDefaultBackendRefsKind {
    Mesh,
    MeshSubset,
    MeshGateway,
    MeshService,
    MeshServiceSubset,
    #[serde(rename = "MeshHTTPRoute")]
    MeshHttpRoute,
}

/// TargetRef is a reference to the resource that represents a group of
/// destinations.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MeshTCPRouteToTargetRef {
    /// Kind of the referenced resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<MeshTCPRouteToTargetRefKind>,
    /// Mesh is reserved for future use to identify cross mesh resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh: Option<String>,
    /// Name of the referenced resource. Can only be used with kinds: `MeshService`,
    /// `MeshServiceSubset` and `MeshGatewayRoute`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// ProxyTypes specifies the data plane types that are subject to the policy. When not specified,
    /// all data plane types are targeted by the policy.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "proxyTypes")]
    pub proxy_types: Option<Vec<String>>,
    /// Tags used to select a subset of proxies by tags. Can only be used with kinds
    /// `MeshSubset` and `MeshServiceSubset`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,
}

/// TargetRef is a reference to the resource that represents a group of
/// destinations.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum MeshTCPRouteToTargetRefKind {
    Mesh,
    MeshSubset,
    MeshGateway,
    MeshService,
    MeshServiceSubset,
    #[serde(rename = "MeshHTTPRoute")]
    MeshHttpRoute,
}

