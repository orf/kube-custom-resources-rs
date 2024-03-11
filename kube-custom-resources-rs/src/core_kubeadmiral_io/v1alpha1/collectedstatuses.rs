// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kubewharf/kubeadmiral/core.kubeadmiral.io/v1alpha1/collectedstatuses.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// CollectedFieldsWithCluster stores the collected fields of a Kubernetes object in a member cluster.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CollectedStatusClusters {
    /// Cluster is the name of the member cluster.
    pub cluster: String,
    /// CollectedFields is the the set of fields collected for the Kubernetes object.
    #[serde(rename = "collectedFields")]
    pub collected_fields: HashMap<String, serde_json::Value>,
    /// Error records any errors encountered while collecting fields from the cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

