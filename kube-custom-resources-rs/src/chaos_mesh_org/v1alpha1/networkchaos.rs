// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/chaos-mesh/chaos-mesh/chaos-mesh.org/v1alpha1/networkchaos.yaml --derive=PartialEq
// kopium version: 0.16.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// Spec defines the behavior of a pod chaos experiment
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "chaos-mesh.org", version = "v1alpha1", kind = "NetworkChaos", plural = "networkchaos")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct NetworkChaosSpec {
    /// Action defines the specific network chaos action. Supported action: partition, netem, delay, loss, duplicate, corrupt Default action: delay
    pub action: NetworkChaosAction,
    /// Bandwidth represents the detail about bandwidth control action
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bandwidth: Option<NetworkChaosBandwidth>,
    /// Corrupt represents the detail about corrupt action
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corrupt: Option<NetworkChaosCorrupt>,
    /// Delay represents the detail about delay action
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay: Option<NetworkChaosDelay>,
    /// Device represents the network device to be affected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// Direction represents the direction, this applies on netem and network partition action
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<NetworkChaosDirection>,
    /// DuplicateSpec represents the detail about loss action
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duplicate: Option<NetworkChaosDuplicate>,
    /// Duration represents the duration of the chaos action
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration: Option<String>,
    /// ExternalTargets represents network targets outside k8s
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "externalTargets")]
    pub external_targets: Option<Vec<String>>,
    /// Loss represents the detail about loss action
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss: Option<NetworkChaosLoss>,
    /// Mode defines the mode to run chaos action. Supported mode: one / all / fixed / fixed-percent / random-max-percent
    pub mode: NetworkChaosMode,
    /// RemoteCluster represents the remote cluster where the chaos will be deployed
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "remoteCluster")]
    pub remote_cluster: Option<String>,
    /// Selector is used to select pods that are used to inject chaos action.
    pub selector: NetworkChaosSelector,
    /// Target represents network target, this applies on netem and network partition action
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<NetworkChaosTarget>,
    /// TargetDevice represents the network device to be affected in target scope.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "targetDevice")]
    pub target_device: Option<String>,
    /// Value is required when the mode is set to `FixedMode` / `FixedPercentMode` / `RandomMaxPercentMode`. If `FixedMode`, provide an integer of pods to do chaos action. If `FixedPercentMode`, provide a number from 0-100 to specify the percent of pods the server can do chaos action. IF `RandomMaxPercentMode`,  provide a number from 0-100 to specify the max percent of pods to do chaos action
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// Spec defines the behavior of a pod chaos experiment
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum NetworkChaosAction {
    #[serde(rename = "netem")]
    Netem,
    #[serde(rename = "delay")]
    Delay,
    #[serde(rename = "loss")]
    Loss,
    #[serde(rename = "duplicate")]
    Duplicate,
    #[serde(rename = "corrupt")]
    Corrupt,
    #[serde(rename = "partition")]
    Partition,
    #[serde(rename = "bandwidth")]
    Bandwidth,
}

/// Bandwidth represents the detail about bandwidth control action
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NetworkChaosBandwidth {
    /// Buffer is the maximum amount of bytes that tokens can be available for instantaneously.
    pub buffer: i32,
    /// Limit is the number of bytes that can be queued waiting for tokens to become available.
    pub limit: i32,
    /// Minburst specifies the size of the peakrate bucket. For perfect accuracy, should be set to the MTU of the interface.  If a peakrate is needed, but some burstiness is acceptable, this size can be raised. A 3000 byte minburst allows around 3mbit/s of peakrate, given 1000 byte packets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minburst: Option<i32>,
    /// Peakrate is the maximum depletion rate of the bucket. The peakrate does not need to be set, it is only necessary if perfect millisecond timescale shaping is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peakrate: Option<i64>,
    /// Rate is the speed knob. Allows bit, kbit, mbit, gbit, tbit, bps, kbps, mbps, gbps, tbps unit. bps means bytes per second.
    pub rate: String,
}

/// Corrupt represents the detail about corrupt action
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NetworkChaosCorrupt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation: Option<String>,
    pub corrupt: String,
}

/// Delay represents the detail about delay action
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NetworkChaosDelay {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jitter: Option<String>,
    pub latency: String,
    /// ReorderSpec defines details of packet reorder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reorder: Option<NetworkChaosDelayReorder>,
}

/// ReorderSpec defines details of packet reorder.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NetworkChaosDelayReorder {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation: Option<String>,
    pub gap: i64,
    pub reorder: String,
}

/// Spec defines the behavior of a pod chaos experiment
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum NetworkChaosDirection {
    #[serde(rename = "to")]
    To,
    #[serde(rename = "from")]
    From,
    #[serde(rename = "both")]
    Both,
}

/// DuplicateSpec represents the detail about loss action
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NetworkChaosDuplicate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation: Option<String>,
    pub duplicate: String,
}

/// Loss represents the detail about loss action
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NetworkChaosLoss {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation: Option<String>,
    pub loss: String,
}

/// Spec defines the behavior of a pod chaos experiment
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum NetworkChaosMode {
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
pub struct NetworkChaosSelector {
    /// Map of string keys and values that can be used to select objects. A selector based on annotations.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "annotationSelectors")]
    pub annotation_selectors: Option<BTreeMap<String, String>>,
    /// a slice of label selector expressions that can be used to select objects. A list of selectors based on set-based label expressions.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "expressionSelectors")]
    pub expression_selectors: Option<Vec<NetworkChaosSelectorExpressionSelectors>>,
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
pub struct NetworkChaosSelectorExpressionSelectors {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// Target represents network target, this applies on netem and network partition action
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NetworkChaosTarget {
    /// Mode defines the mode to run chaos action. Supported mode: one / all / fixed / fixed-percent / random-max-percent
    pub mode: NetworkChaosTargetMode,
    /// Selector is used to select pods that are used to inject chaos action.
    pub selector: NetworkChaosTargetSelector,
    /// Value is required when the mode is set to `FixedMode` / `FixedPercentMode` / `RandomMaxPercentMode`. If `FixedMode`, provide an integer of pods to do chaos action. If `FixedPercentMode`, provide a number from 0-100 to specify the percent of pods the server can do chaos action. IF `RandomMaxPercentMode`,  provide a number from 0-100 to specify the max percent of pods to do chaos action
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// Target represents network target, this applies on netem and network partition action
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum NetworkChaosTargetMode {
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
pub struct NetworkChaosTargetSelector {
    /// Map of string keys and values that can be used to select objects. A selector based on annotations.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "annotationSelectors")]
    pub annotation_selectors: Option<BTreeMap<String, String>>,
    /// a slice of label selector expressions that can be used to select objects. A list of selectors based on set-based label expressions.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "expressionSelectors")]
    pub expression_selectors: Option<Vec<NetworkChaosTargetSelectorExpressionSelectors>>,
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
pub struct NetworkChaosTargetSelectorExpressionSelectors {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// Most recently observed status of the chaos experiment about pods
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NetworkChaosStatus {
    /// Conditions represents the current global condition of the chaos
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<NetworkChaosStatusConditions>>,
    /// Experiment records the last experiment state.
    pub experiment: NetworkChaosStatusExperiment,
    /// Instances always specifies podnetworkchaos generation or empty
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instances: Option<BTreeMap<String, i64>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NetworkChaosStatusConditions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub status: String,
    #[serde(rename = "type")]
    pub r#type: String,
}

/// Experiment records the last experiment state.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NetworkChaosStatusExperiment {
    /// Records are used to track the running status
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "containerRecords")]
    pub container_records: Option<Vec<NetworkChaosStatusExperimentContainerRecords>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "desiredPhase")]
    pub desired_phase: Option<NetworkChaosStatusExperimentDesiredPhase>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NetworkChaosStatusExperimentContainerRecords {
    /// Events are the essential details about the injections and recoveries
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<NetworkChaosStatusExperimentContainerRecordsEvents>>,
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
pub struct NetworkChaosStatusExperimentContainerRecordsEvents {
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
pub enum NetworkChaosStatusExperimentDesiredPhase {
    Run,
    Stop,
}
