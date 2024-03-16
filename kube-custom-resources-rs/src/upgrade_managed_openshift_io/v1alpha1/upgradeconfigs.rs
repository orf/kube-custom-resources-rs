// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/openshift/managed-upgrade-operator/upgrade.managed.openshift.io/v1alpha1/upgradeconfigs.yaml --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// UpgradeConfigSpec defines the desired state of UpgradeConfig and upgrade window and freeze window
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "upgrade.managed.openshift.io", version = "v1alpha1", kind = "UpgradeConfig", plural = "upgradeconfigs")]
#[kube(namespaced)]
#[kube(status = "UpgradeConfigStatus")]
#[kube(schema = "disabled")]
pub struct UpgradeConfigSpec {
    /// The maximum grace period granted to a node whose drain is blocked by a Pod Disruption Budget, before that drain is forced. Measured in minutes. The minimum accepted value is 0 and in this case it will trigger force drain after the expectedNodeDrainTime lapsed.
    #[serde(rename = "PDBForceDrainTimeout")]
    pub pdb_force_drain_timeout: i32,
    /// Specify if scaling up an extra node for capacity reservation before upgrade starts is needed
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "capacityReservation")]
    pub capacity_reservation: Option<bool>,
    /// Specify the desired OpenShift release
    pub desired: UpgradeConfigDesired,
    /// Type indicates the ClusterUpgrader implementation to use to perform an upgrade of the cluster
    #[serde(rename = "type")]
    pub r#type: UpgradeConfigType,
    /// Specify the upgrade start time
    #[serde(rename = "upgradeAt")]
    pub upgrade_at: String,
}

/// Specify the desired OpenShift release
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct UpgradeConfigDesired {
    /// Channel used for upgrades
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// Image reference used for upgrades
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Version of openshift release
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// UpgradeConfigSpec defines the desired state of UpgradeConfig and upgrade window and freeze window
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum UpgradeConfigType {
    #[serde(rename = "OSD")]
    Osd,
    #[serde(rename = "ARO")]
    Aro,
}

/// UpgradeConfigStatus defines the observed state of UpgradeConfig
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct UpgradeConfigStatus {
    /// This record history of every upgrade
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<Vec<UpgradeConfigStatusHistory>>,
}

/// UpgradeHistory record history of upgrade
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct UpgradeConfigStatusHistory {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "completeTime")]
    pub complete_time: Option<String>,
    /// Conditions is a set of Condition instances.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// This describe the status of the upgrade process
    pub phase: UpgradeConfigStatusHistoryPhase,
    /// Version preceding this upgrade
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "precedingVersion")]
    pub preceding_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "startTime")]
    pub start_time: Option<String>,
    /// Desired version of this upgrade
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "workerCompleteTime")]
    pub worker_complete_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "workerStartTime")]
    pub worker_start_time: Option<String>,
}

/// UpgradeHistory record history of upgrade
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum UpgradeConfigStatusHistoryPhase {
    New,
    Pending,
    Upgrading,
    Upgraded,
    Failed,
}

