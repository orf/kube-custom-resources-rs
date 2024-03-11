// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/rook/rook/ceph.rook.io/v1/cephclients.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// Spec represents the specification of a Ceph Client
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "ceph.rook.io", version = "v1", kind = "CephClient", plural = "cephclients")]
#[kube(namespaced)]
#[kube(status = "CephClientStatus")]
#[kube(schema = "disabled")]
pub struct CephClientSpec {
    pub caps: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Status represents the status of a Ceph Client
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CephClientStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info: Option<BTreeMap<String, String>>,
    /// ObservedGeneration is the latest generation observed by the controller.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
    /// ConditionType represent a resource's status
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
}

