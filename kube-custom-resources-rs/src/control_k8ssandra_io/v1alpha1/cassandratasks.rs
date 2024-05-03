// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/k8ssandra/cass-operator/control.k8ssandra.io/v1alpha1/cassandratasks.yaml --derive=Default --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use std::collections::BTreeMap;
    pub use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
}
use self::prelude::*;

/// CassandraTaskSpec defines the desired state of CassandraTask
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "control.k8ssandra.io", version = "v1alpha1", kind = "CassandraTask", plural = "cassandratasks")]
#[kube(namespaced)]
#[kube(status = "CassandraTaskStatus")]
#[kube(schema = "disabled")]
#[kube(derive="Default")]
#[kube(derive="PartialEq")]
pub struct CassandraTaskSpec {
    /// Specifics if this task can be run concurrently with other active tasks. Valid values are:
    /// - "Allow": allows multiple Tasks to run concurrently on Cassandra cluster
    /// - "Forbid" (default): only a single task is executed at once
    /// The "Allow" property is only valid if all the other active Tasks have "Allow" as well.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "concurrencyPolicy")]
    pub concurrency_policy: Option<String>,
    /// Which datacenter this task is targetting. Note, this must be a datacenter which the current cass-operator
    /// can access
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub datacenter: Option<CassandraTaskDatacenter>,
    /// Jobs defines the jobs this task will execute (and their order)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jobs: Option<Vec<CassandraTaskJobs>>,
    /// RestartPolicy indicates the behavior n case of failure. Default is Never.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "restartPolicy")]
    pub restart_policy: Option<String>,
    /// ScheduledTime indicates the earliest possible time this task is executed. This does not necessarily
    /// equal to the time it is actually executed (if other tasks are blocking for example). If not set,
    /// the task will be executed immediately.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "scheduledTime")]
    pub scheduled_time: Option<String>,
    /// TTLSecondsAfterFinished defines how long the completed job will kept before being cleaned up. If set to 0
    /// the task will not be cleaned up by the cass-operator. If unset, the default time (86400s) is used.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ttlSecondsAfterFinished")]
    pub ttl_seconds_after_finished: Option<i32>,
}

/// Which datacenter this task is targetting. Note, this must be a datacenter which the current cass-operator
/// can access
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CassandraTaskDatacenter {
    /// API version of the referent.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiVersion")]
    pub api_version: Option<String>,
    /// If referring to a piece of an object instead of an entire object, this string
    /// should contain a valid JSON/Go field access statement, such as desiredState.manifest.containers[2].
    /// For example, if the object reference is to a container within a pod, this would take on a value like:
    /// "spec.containers{name}" (where "name" refers to the name of the container that triggered
    /// the event) or if no container name is specified "spec.containers[2]" (container with
    /// index 2 in this pod). This syntax is chosen only to have some well-defined way of
    /// referencing a part of an object.
    /// TODO: this design is not final and this field is subject to change in the future.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "fieldPath")]
    pub field_path: Option<String>,
    /// Kind of the referent.
    /// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Name of the referent.
    /// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Namespace of the referent.
    /// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Specific resourceVersion to which this reference is made, if any.
    /// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#concurrency-control-and-consistency
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "resourceVersion")]
    pub resource_version: Option<String>,
    /// UID of the referent.
    /// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#uids
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CassandraTaskJobs {
    /// Arguments are additional parameters for the command
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<CassandraTaskJobsArgs>,
    /// Command defines what is run against Cassandra pods
    pub command: String,
    pub name: String,
}

/// Arguments are additional parameters for the command
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CassandraTaskJobsArgs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jobs: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyspace_name: Option<String>,
    /// NewTokens is a map of pod names to their newly-assigned tokens. Required for the move
    /// command, ignored otherwise. Pods referenced in this map must exist; any existing pod not
    /// referenced in this map will not be moved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_tokens: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_snapshot: Option<bool>,
    /// Scrub arguments
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_validate: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rack: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_corrupted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_datacenter: Option<String>,
    /// Compaction arguments
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split_output: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tables: Option<Vec<String>>,
}

/// CassandraTaskStatus defines the observed state of CassandraJob
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CassandraTaskStatus {
    /// The number of actively running pods.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<i64>,
    /// Represents time when the job was completed. It is not guaranteed to
    /// be set in happens-before order across separate operations.
    /// It is represented in RFC3339 form and is in UTC.
    /// The completion time is only set when the job finishes successfully.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "completionTime")]
    pub completion_time: Option<String>,
    /// The latest available observations of an object's current state. When a Job
    /// fails, one of the conditions will have type "Failed" and status true. When
    /// a Job is suspended, one of the conditions will have type "Suspended" and
    /// status true; when the Job is resumed, the status of this condition will
    /// become false. When a Job is completed, one of the conditions will have
    /// type "Complete" and status true.
    /// More info: https://kubernetes.io/docs/concepts/workloads/controllers/jobs-run-to-completion/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// The number of pods which reached phase Failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<i64>,
    /// Represents time when the job controller started processing a job. When a
    /// Job is created in the suspended state, this field is not set until the
    /// first time it is resumed. This field is reset every time a Job is resumed
    /// from suspension. It is represented in RFC3339 form and is in UTC.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "startTime")]
    pub start_time: Option<String>,
    /// The number of pods which reached phase Succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub succeeded: Option<i64>,
}

