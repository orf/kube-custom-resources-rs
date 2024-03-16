// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/longhorn/longhorn/longhorn.io/v1beta2/backupbackingimages.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// BackupBackingImageSpec defines the desired state of the Longhorn backing image backup
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "longhorn.io", version = "v1beta2", kind = "BackupBackingImage", plural = "backupbackingimages")]
#[kube(namespaced)]
#[kube(status = "BackupBackingImageStatus")]
#[kube(schema = "disabled")]
pub struct BackupBackingImageSpec {
    /// The labels of backing image backup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    /// The time to request run sync the remote backing image backup.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "syncRequestedAt")]
    pub sync_requested_at: Option<String>,
    /// Is this CR created by user through API or UI. Required
    #[serde(rename = "userCreated")]
    pub user_created: bool,
}

/// BackupBackingImageStatus defines the observed state of the Longhorn backing image backup
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackupBackingImageStatus {
    /// The backing image name.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "backingImage")]
    pub backing_image: Option<String>,
    /// The backing image backup upload finished time.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "backupCreatedAt")]
    pub backup_created_at: Option<String>,
    /// The checksum of the backing image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
    /// Compression method
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "compressionMethod")]
    pub compression_method: Option<String>,
    /// The error message when taking the backing image backup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The labels of backing image backup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    /// The last time that the backing image backup was synced with the remote backup target.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastSyncedAt")]
    pub last_synced_at: Option<String>,
    /// The address of the backing image manager that runs backing image backup.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "managerAddress")]
    pub manager_address: Option<String>,
    /// The error messages when listing or inspecting backing image backup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub messages: Option<BTreeMap<String, String>>,
    /// The node ID on which the controller is responsible to reconcile this CR.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ownerID")]
    pub owner_id: Option<String>,
    /// The backing image backup progress.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<i64>,
    /// The backing image size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,
    /// The backing image backup creation state. Can be "", "InProgress", "Completed", "Error", "Unknown".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// The backing image backup URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

