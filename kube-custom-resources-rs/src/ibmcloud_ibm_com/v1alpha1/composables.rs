// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/composable-operator/composable/ibmcloud.ibm.com/v1alpha1/composables.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// ComposableSpec defines the desired state of Composable
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "ibmcloud.ibm.com", version = "v1alpha1", kind = "Composable", plural = "composables")]
#[kube(namespaced)]
#[kube(status = "ComposableStatus")]
#[kube(schema = "disabled")]
pub struct ComposableSpec {
    /// Template defines the underlying object
    pub template: BTreeMap<String, serde_json::Value>,
}

/// ComposableStatus defines the observed state of Composable
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ComposableStatus {
    /// Message - provides human readable explanation of the Composable status
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// State shows the composable object state
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<ComposableStatusState>,
}

/// ComposableStatus defines the observed state of Composable
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ComposableStatusState {
    Failed,
    Pending,
    Online,
}

