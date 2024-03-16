// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/longhorn/longhorn/longhorn.io/v1beta2/backingimages.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// BackingImageSpec defines the desired state of the Longhorn backing image
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "longhorn.io", version = "v1beta2", kind = "BackingImage", plural = "backingimages")]
#[kube(namespaced)]
#[kube(status = "BackingImageStatus")]
#[kube(schema = "disabled")]
pub struct BackingImageSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disks: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sourceParameters")]
    pub source_parameters: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sourceType")]
    pub source_type: Option<BackingImageSourceType>,
}

/// BackingImageSpec defines the desired state of the Longhorn backing image
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum BackingImageSourceType {
    #[serde(rename = "download")]
    Download,
    #[serde(rename = "upload")]
    Upload,
    #[serde(rename = "export-from-volume")]
    ExportFromVolume,
    #[serde(rename = "restore")]
    Restore,
}

/// BackingImageStatus defines the observed state of the Longhorn backing image status
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackingImageStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "diskFileStatusMap")]
    pub disk_file_status_map: Option<BTreeMap<String, BackingImageStatusDiskFileStatusMap>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "diskLastRefAtMap")]
    pub disk_last_ref_at_map: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ownerID")]
    pub owner_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackingImageStatusDiskFileStatusMap {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastStateTransitionTime")]
    pub last_state_transition_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

