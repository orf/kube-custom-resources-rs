// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/vmware-tanzu/velero/velero.io/v1/deletebackuprequests.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// DeleteBackupRequestSpec is the specification for which backups to delete.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "velero.io", version = "v1", kind = "DeleteBackupRequest", plural = "deletebackuprequests")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct DeleteBackupRequestSpec {
    #[serde(rename = "backupName")]
    pub backup_name: String,
}

/// DeleteBackupRequestStatus is the current status of a DeleteBackupRequest.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct DeleteBackupRequestStatus {
    /// Errors contains any errors that were encountered during the deletion process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    /// Phase is the current state of the DeleteBackupRequest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<DeleteBackupRequestStatusPhase>,
}

/// DeleteBackupRequestStatus is the current status of a DeleteBackupRequest.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum DeleteBackupRequestStatusPhase {
    New,
    InProgress,
    Processed,
}

