// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/1Password/onepassword-operator/onepassword.com/v1/onepassworditems.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// OnePasswordItemSpec defines the desired state of OnePasswordItem
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "onepassword.com", version = "v1", kind = "OnePasswordItem", plural = "onepassworditems")]
#[kube(namespaced)]
#[kube(status = "OnePasswordItemStatus")]
#[kube(schema = "disabled")]
pub struct OnePasswordItemSpec {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "itemPath")]
    pub item_path: Option<String>,
}

/// OnePasswordItemStatus defines the observed state of OnePasswordItem
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct OnePasswordItemStatus {
    pub conditions: Vec<OnePasswordItemStatusConditions>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct OnePasswordItemStatusConditions {
    /// Last time the condition transit from one status to another.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastTransitionTime")]
    pub last_transition_time: Option<String>,
    /// Human-readable message indicating details about last transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Status of the condition, one of True, False, Unknown.
    pub status: String,
    /// Type of job condition, Completed.
    #[serde(rename = "type")]
    pub r#type: String,
}

