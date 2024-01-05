// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/backube/snapscheduler/snapscheduler.backube/v1/snapshotschedules.yaml --derive=Default --derive=PartialEq
// kopium version: 0.16.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// SnapshotScheduleSpec defines the desired state of SnapshotSchedule
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "snapscheduler.backube", version = "v1", kind = "SnapshotSchedule", plural = "snapshotschedules")]
#[kube(namespaced)]
#[kube(status = "SnapshotScheduleStatus")]
#[kube(schema = "disabled")]
pub struct SnapshotScheduleSpec {
    /// A filter to select which PVCs to snapshot via this schedule
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "claimSelector")]
    pub claim_selector: Option<SnapshotScheduleClaimSelector>,
    /// Indicates that this schedule should be temporarily disabled
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    /// Retention determines how long this schedule's snapshots will be kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<SnapshotScheduleRetention>,
    /// Schedule is a Cronspec specifying when snapshots should be taken. See https://en.wikipedia.org/wiki/Cron for a description of the format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
    /// A template to customize the Snapshots.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "snapshotTemplate")]
    pub snapshot_template: Option<SnapshotScheduleSnapshotTemplate>,
}

/// A filter to select which PVCs to snapshot via this schedule
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SnapshotScheduleClaimSelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<SnapshotScheduleClaimSelectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SnapshotScheduleClaimSelectorMatchExpressions {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// Retention determines how long this schedule's snapshots will be kept.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SnapshotScheduleRetention {
    /// The length of time (time.Duration) after which a given Snapshot will be deleted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    /// The maximum number of snapshots to retain per PVC
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxCount")]
    pub max_count: Option<i32>,
}

/// A template to customize the Snapshots.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SnapshotScheduleSnapshotTemplate {
    /// A list of labels that should be added to each Snapshot created by this schedule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    /// The name of the VolumeSnapshotClass to be used when creating Snapshots.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "snapshotClassName")]
    pub snapshot_class_name: Option<String>,
}

/// SnapshotScheduleStatus defines the observed state of SnapshotSchedule
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SnapshotScheduleStatus {
    /// Conditions is a list of conditions related to operator reconciliation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<SnapshotScheduleStatusConditions>>,
    /// The time of the most recent snapshot taken by this schedule
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastSnapshotTime")]
    pub last_snapshot_time: Option<String>,
    /// The time of the next scheduled snapshot
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nextSnapshotTime")]
    pub next_snapshot_time: Option<String>,
}

/// Condition represents the state of the operator's reconciliation functionality.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SnapshotScheduleStatusConditions {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastHeartbeatTime")]
    pub last_heartbeat_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastTransitionTime")]
    pub last_transition_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub status: String,
    /// ConditionType is the state of the operator's reconciliation functionality.
    #[serde(rename = "type")]
    pub r#type: String,
}
