// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/percona/everest-operator/everest.percona.com/v1alpha1/databaseclusterbackups.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// DatabaseClusterBackupSpec defines the desired state of DatabaseClusterBackup.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "everest.percona.com", version = "v1alpha1", kind = "DatabaseClusterBackup", plural = "databaseclusterbackups")]
#[kube(namespaced)]
#[kube(status = "DatabaseClusterBackupStatus")]
#[kube(schema = "disabled")]
pub struct DatabaseClusterBackupSpec {
    /// BackupStorageName is the name of the BackupStorage used for backups.
    #[serde(rename = "backupStorageName")]
    pub backup_storage_name: String,
    /// DBClusterName is the original database cluster name.
    #[serde(rename = "dbClusterName")]
    pub db_cluster_name: String,
}

/// DatabaseClusterBackupStatus defines the observed state of DatabaseClusterBackup.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct DatabaseClusterBackupStatus {
    /// Completed is the time when the job was completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed: Option<String>,
    /// Created is the timestamp of the upstream backup's creation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    /// Destination is the full path to the backup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    /// Gaps identifies if there are gaps detected in the PITR logs
    pub gaps: bool,
    /// State is the DatabaseBackup state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

