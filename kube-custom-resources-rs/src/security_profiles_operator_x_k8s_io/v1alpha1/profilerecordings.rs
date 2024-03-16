// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kubernetes-sigs/security-profiles-operator/security-profiles-operator.x-k8s.io/v1alpha1/profilerecordings.yaml --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// ProfileRecordingSpec defines the desired state of ProfileRecording.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "security-profiles-operator.x-k8s.io", version = "v1alpha1", kind = "ProfileRecording", plural = "profilerecordings")]
#[kube(namespaced)]
#[kube(status = "ProfileRecordingStatus")]
#[kube(schema = "disabled")]
pub struct ProfileRecordingSpec {
    /// Containers is a set of containers to record. This allows to select
    /// only specific containers to record instead of all containers present
    /// in the pod.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub containers: Option<Vec<String>>,
    /// DisableProfileAfterRecording indicates whether the profile should be disabled
    /// after recording and thus skipped during reconcile. In case of SELinux profiles,
    /// reconcile can take a significant amount of time and for all profiles might not be needed.
    /// This Defaults to false.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "disableProfileAfterRecording")]
    pub disable_profile_after_recording: Option<bool>,
    /// Kind of object to be recorded.
    pub kind: ProfileRecordingKind,
    /// Whether or how to merge recorded profiles. Can be one of "none" or "containers".
    /// Default is "none".
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "mergeStrategy")]
    pub merge_strategy: Option<ProfileRecordingMergeStrategy>,
    /// PodSelector selects the pods to record. This field follows standard
    /// label selector semantics. An empty podSelector matches all pods in this
    /// namespace.
    #[serde(rename = "podSelector")]
    pub pod_selector: ProfileRecordingPodSelector,
    /// Recorder to be used.
    pub recorder: ProfileRecordingRecorder,
}

/// ProfileRecordingSpec defines the desired state of ProfileRecording.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ProfileRecordingKind {
    SeccompProfile,
    SelinuxProfile,
}

/// ProfileRecordingSpec defines the desired state of ProfileRecording.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ProfileRecordingMergeStrategy {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "containers")]
    Containers,
}

/// PodSelector selects the pods to record. This field follows standard
/// label selector semantics. An empty podSelector matches all pods in this
/// namespace.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ProfileRecordingPodSelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<ProfileRecordingPodSelectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels
    /// map is equivalent to an element of matchExpressions, whose key field is "key", the
    /// operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that
/// relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ProfileRecordingPodSelectorMatchExpressions {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values.
    /// Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn,
    /// the values array must be non-empty. If the operator is Exists or DoesNotExist,
    /// the values array must be empty. This array is replaced during a strategic
    /// merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// ProfileRecordingSpec defines the desired state of ProfileRecording.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ProfileRecordingRecorder {
    #[serde(rename = "bpf")]
    Bpf,
    #[serde(rename = "logs")]
    Logs,
}

/// ProfileRecordingStatus contains status of the ProfileRecording.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ProfileRecordingStatus {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "activeWorkloads")]
    pub active_workloads: Option<Vec<String>>,
}

