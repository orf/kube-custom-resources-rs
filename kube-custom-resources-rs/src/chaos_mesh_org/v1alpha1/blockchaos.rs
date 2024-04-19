// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/chaos-mesh/chaos-mesh/chaos-mesh.org/v1alpha1/blockchaos.yaml --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// BlockChaosSpec is the content of the specification for a BlockChaos
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "chaos-mesh.org", version = "v1alpha1", kind = "BlockChaos", plural = "blockchaos")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct BlockChaosSpec {
    /// Action defines the specific block chaos action. Supported action: delay
    pub action: BlockChaosAction,
    /// ContainerNames indicates list of the name of affected container. If not set, the first container will be injected
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "containerNames")]
    pub container_names: Option<Vec<String>>,
    /// Delay defines the delay distribution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay: Option<BlockChaosDelay>,
    /// Duration represents the duration of the chaos action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration: Option<String>,
    /// Mode defines the mode to run chaos action. Supported mode: one / all / fixed / fixed-percent / random-max-percent
    pub mode: BlockChaosMode,
    /// RemoteCluster represents the remote cluster where the chaos will be deployed
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "remoteCluster")]
    pub remote_cluster: Option<String>,
    /// Selector is used to select pods that are used to inject chaos action.
    pub selector: BlockChaosSelector,
    /// Value is required when the mode is set to `FixedMode` / `FixedPercentMode` / `RandomMaxPercentMode`. If `FixedMode`, provide an integer of pods to do chaos action. If `FixedPercentMode`, provide a number from 0-100 to specify the percent of pods the server can do chaos action. IF `RandomMaxPercentMode`,  provide a number from 0-100 to specify the max percent of pods to do chaos action
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(rename = "volumeName")]
    pub volume_name: String,
}

/// BlockChaosSpec is the content of the specification for a BlockChaos
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum BlockChaosAction {
    #[serde(rename = "delay")]
    Delay,
}

/// Delay defines the delay distribution.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BlockChaosDelay {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jitter: Option<String>,
    /// Latency defines the latency of every io request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency: Option<String>,
}

/// BlockChaosSpec is the content of the specification for a BlockChaos
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum BlockChaosMode {
    #[serde(rename = "one")]
    One,
    #[serde(rename = "all")]
    All,
    #[serde(rename = "fixed")]
    Fixed,
    #[serde(rename = "fixed-percent")]
    FixedPercent,
    #[serde(rename = "random-max-percent")]
    RandomMaxPercent,
}

/// Selector is used to select pods that are used to inject chaos action.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BlockChaosSelector {
    /// Map of string keys and values that can be used to select objects. A selector based on annotations.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "annotationSelectors")]
    pub annotation_selectors: Option<BTreeMap<String, String>>,
    /// a slice of label selector expressions that can be used to select objects. A list of selectors based on set-based label expressions.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "expressionSelectors")]
    pub expression_selectors: Option<Vec<BlockChaosSelectorExpressionSelectors>>,
    /// Map of string keys and values that can be used to select objects. A selector based on fields.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "fieldSelectors")]
    pub field_selectors: Option<BTreeMap<String, String>>,
    /// Map of string keys and values that can be used to select objects. A selector based on labels.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "labelSelectors")]
    pub label_selectors: Option<BTreeMap<String, String>>,
    /// Namespaces is a set of namespace to which objects belong.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<Vec<String>>,
    /// Map of string keys and values that can be used to select nodes. Selector which must match a node's labels, and objects must belong to these selected nodes.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nodeSelectors")]
    pub node_selectors: Option<BTreeMap<String, String>>,
    /// Nodes is a set of node name and objects must belong to these nodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodes: Option<Vec<String>>,
    /// PodPhaseSelectors is a set of condition of a pod at the current time. supported value: Pending / Running / Succeeded / Failed / Unknown
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "podPhaseSelectors")]
    pub pod_phase_selectors: Option<Vec<String>>,
    /// Pods is a map of string keys and a set values that used to select pods. The key defines the namespace which pods belong, and the each values is a set of pod names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pods: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BlockChaosSelectorExpressionSelectors {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// BlockChaosStatus represents the status of a BlockChaos
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BlockChaosStatus {
    /// Conditions represents the current global condition of the chaos
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<BlockChaosStatusConditions>>,
    /// Experiment records the last experiment state.
    pub experiment: BlockChaosStatusExperiment,
    /// InjectionIds always specifies the number of injected chaos action
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ids: Option<BTreeMap<String, i64>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BlockChaosStatusConditions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub status: String,
    #[serde(rename = "type")]
    pub r#type: String,
}

/// Experiment records the last experiment state.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BlockChaosStatusExperiment {
    /// Records are used to track the running status
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "containerRecords")]
    pub container_records: Option<Vec<BlockChaosStatusExperimentContainerRecords>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "desiredPhase")]
    pub desired_phase: Option<BlockChaosStatusExperimentDesiredPhase>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BlockChaosStatusExperimentContainerRecords {
    /// Events are the essential details about the injections and recoveries
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<BlockChaosStatusExperimentContainerRecordsEvents>>,
    pub id: String,
    /// InjectedCount is a counter to record the sum of successful injections
    #[serde(rename = "injectedCount")]
    pub injected_count: i64,
    pub phase: String,
    /// RecoveredCount is a counter to record the sum of successful recoveries
    #[serde(rename = "recoveredCount")]
    pub recovered_count: i64,
    #[serde(rename = "selectorKey")]
    pub selector_key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BlockChaosStatusExperimentContainerRecordsEvents {
    /// Message is the detail message, e.g. the reason why we failed to inject the chaos
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Operation represents the operation we are doing, when we crate this event
    pub operation: String,
    /// Timestamp is time when we create this event
    pub timestamp: String,
    /// Type means the stage of this event
    #[serde(rename = "type")]
    pub r#type: String,
}

/// Experiment records the last experiment state.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum BlockChaosStatusExperimentDesiredPhase {
    Run,
    Stop,
}

