// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/volcano-sh/volcano/scheduling.volcano.sh/v1beta1/queues.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

/// Specification of the desired behavior of the queue. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#spec-and-status
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "scheduling.volcano.sh", version = "v1beta1", kind = "Queue", plural = "queues")]
#[kube(status = "QueueStatus")]
#[kube(schema = "disabled")]
pub struct QueueSpec {
    /// If specified, the pod owned by the queue will be scheduled with constraint
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affinity: Option<QueueAffinity>,
    /// ResourceList is a set of (resource name, quantity) pairs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<BTreeMap<String, IntOrString>>,
    /// extendCluster indicate the jobs in this Queue will be dispatched to these clusters.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "extendClusters")]
    pub extend_clusters: Option<Vec<QueueExtendClusters>>,
    /// Guarantee indicate configuration about resource reservation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guarantee: Option<QueueGuarantee>,
    /// Parent define the parent of queue
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// Reclaimable indicate whether the queue can be reclaimed by other queue
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reclaimable: Option<bool>,
    /// Type define the type of queue
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<i32>,
}

/// If specified, the pod owned by the queue will be scheduled with constraint
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct QueueAffinity {
    /// Describes nodegroup affinity scheduling rules for the queue(e.g. putting pods of the queue in the nodes of the nodegroup)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nodeGroupAffinity")]
    pub node_group_affinity: Option<QueueAffinityNodeGroupAffinity>,
    /// Describes nodegroup anti-affinity scheduling rules for the queue(e.g. avoid putting pods of the queue in the nodes of the nodegroup).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nodeGroupAntiAffinity")]
    pub node_group_anti_affinity: Option<QueueAffinityNodeGroupAntiAffinity>,
}

/// Describes nodegroup affinity scheduling rules for the queue(e.g. putting pods of the queue in the nodes of the nodegroup)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct QueueAffinityNodeGroupAffinity {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "preferredDuringSchedulingIgnoredDuringExecution")]
    pub preferred_during_scheduling_ignored_during_execution: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "requiredDuringSchedulingIgnoredDuringExecution")]
    pub required_during_scheduling_ignored_during_execution: Option<Vec<String>>,
}

/// Describes nodegroup anti-affinity scheduling rules for the queue(e.g. avoid putting pods of the queue in the nodes of the nodegroup).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct QueueAffinityNodeGroupAntiAffinity {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "preferredDuringSchedulingIgnoredDuringExecution")]
    pub preferred_during_scheduling_ignored_during_execution: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "requiredDuringSchedulingIgnoredDuringExecution")]
    pub required_during_scheduling_ignored_during_execution: Option<Vec<String>>,
}

/// CluterSpec represents the template of Cluster
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct QueueExtendClusters {
    /// ResourceList is a set of (resource name, quantity) pairs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity: Option<BTreeMap<String, IntOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<i32>,
}

/// Guarantee indicate configuration about resource reservation
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct QueueGuarantee {
    /// The amount of cluster resource reserved for queue. Just set either `percentage` or `resource`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<BTreeMap<String, IntOrString>>,
}

/// The status of queue.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct QueueStatus {
    /// Allocated is allocated resources in queue
    pub allocated: BTreeMap<String, IntOrString>,
    /// The number of `Completed` PodGroup in this queue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed: Option<i32>,
    /// The number of `Inqueue` PodGroup in this queue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inqueue: Option<i32>,
    /// The number of 'Pending' PodGroup in this queue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<i32>,
    /// Reservation is the profile of resource reservation for queue
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reservation: Option<QueueStatusReservation>,
    /// The number of 'Running' PodGroup in this queue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub running: Option<i32>,
    /// State is state of queue
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// The number of 'Unknown' PodGroup in this queue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unknown: Option<i32>,
}

/// Reservation is the profile of resource reservation for queue
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct QueueStatusReservation {
    /// Nodes are Locked nodes for queue
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodes: Option<Vec<String>>,
    /// Resource is a list of total idle resource in locked nodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<BTreeMap<String, IntOrString>>,
}

