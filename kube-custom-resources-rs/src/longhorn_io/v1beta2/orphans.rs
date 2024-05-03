// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/longhorn/longhorn/longhorn.io/v1beta2/orphans.yaml --derive=Default --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use std::collections::BTreeMap;
    pub use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
}
use self::prelude::*;

/// OrphanSpec defines the desired state of the Longhorn orphaned data
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "longhorn.io", version = "v1beta2", kind = "Orphan", plural = "orphans")]
#[kube(namespaced)]
#[kube(status = "OrphanStatus")]
#[kube(schema = "disabled")]
#[kube(derive="Default")]
#[kube(derive="PartialEq")]
pub struct OrphanSpec {
    /// The node ID on which the controller is responsible to reconcile this orphan CR.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nodeID")]
    pub node_id: Option<String>,
    /// The type of the orphaned data. Can be "replica".
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "orphanType")]
    pub orphan_type: Option<String>,
    /// The parameters of the orphaned data
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<BTreeMap<String, String>>,
}

/// OrphanStatus defines the observed state of the Longhorn orphaned data
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct OrphanStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ownerID")]
    pub owner_id: Option<String>,
}

