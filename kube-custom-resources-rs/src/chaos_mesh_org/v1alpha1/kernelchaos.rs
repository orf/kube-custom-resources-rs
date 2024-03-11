// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/chaos-mesh/chaos-mesh/chaos-mesh.org/v1alpha1/kernelchaos.yaml --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// Spec defines the behavior of a kernel chaos experiment
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "chaos-mesh.org", version = "v1alpha1", kind = "KernelChaos", plural = "kernelchaos")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct KernelChaosSpec {
    /// ContainerNames indicates list of the name of affected container. If not set, the first container will be injected
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "containerNames")]
    pub container_names: Option<Vec<String>>,
    /// Duration represents the duration of the chaos action
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration: Option<String>,
    /// FailKernRequest defines the request of kernel injection
    #[serde(rename = "failKernRequest")]
    pub fail_kern_request: KernelChaosFailKernRequest,
    /// Mode defines the mode to run chaos action. Supported mode: one / all / fixed / fixed-percent / random-max-percent
    pub mode: KernelChaosMode,
    /// RemoteCluster represents the remote cluster where the chaos will be deployed
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "remoteCluster")]
    pub remote_cluster: Option<String>,
    /// Selector is used to select pods that are used to inject chaos action.
    pub selector: KernelChaosSelector,
    /// Value is required when the mode is set to `FixedMode` / `FixedPercentMode` / `RandomMaxPercentMode`. If `FixedMode`, provide an integer of pods to do chaos action. If `FixedPercentMode`, provide a number from 0-100 to specify the percent of pods the server can do chaos action. IF `RandomMaxPercentMode`,  provide a number from 0-100 to specify the max percent of pods to do chaos action
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// FailKernRequest defines the request of kernel injection
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KernelChaosFailKernRequest {
    /// Callchain indicate a special call chain, such as: ext4_mount -> mount_subtree -> ... -> should_failslab With an optional set of predicates and an optional set of parameters, which used with predicates. You can read call chan and predicate examples from https://github.com/chaos-mesh/bpfki/tree/develop/examples to learn more. If no special call chain, just keep Callchain empty, which means it will fail at any call chain with slab alloc (eg: kmalloc).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callchain: Option<Vec<KernelChaosFailKernRequestCallchain>>,
    /// FailType indicates what to fail, can be set to '0' / '1' / '2' If `0`, indicates slab to fail (should_failslab) If `1`, indicates alloc_page to fail (should_fail_alloc_page) If `2`, indicates bio to fail (should_fail_bio) You can read: 1. https://www.kernel.org/doc/html/latest/fault-injection/fault-injection.html 2. http://github.com/iovisor/bcc/blob/master/tools/inject_example.txt to learn more
    pub failtype: i32,
    /// Headers indicates the appropriate kernel headers you need. Eg: "linux/mmzone.h", "linux/blkdev.h" and so on
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<Vec<String>>,
    /// Probability indicates the fails with probability. If you want 1%, please set this field with 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probability: Option<i32>,
    /// Times indicates the max times of fails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub times: Option<i32>,
}

/// Frame defines the function signature and predicate in function's body
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KernelChaosFailKernRequestCallchain {
    /// Funcname can be find from kernel source or `/proc/kallsyms`, such as `ext4_mount`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub funcname: Option<String>,
    /// Parameters is used with predicate, for example, if you want to inject slab error in `d_alloc_parallel(struct dentry *parent, const struct qstr *name)` with a special name `bananas`, you need to set it to `struct dentry *parent, const struct qstr *name` otherwise omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<String>,
    /// Predicate will access the arguments of this Frame, example with Parameters's, you can set it to `STRNCMP(name->name, "bananas", 8)` to make inject only with it, or omit it to inject for all d_alloc_parallel call chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate: Option<String>,
}

/// Spec defines the behavior of a kernel chaos experiment
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum KernelChaosMode {
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
pub struct KernelChaosSelector {
    /// Map of string keys and values that can be used to select objects. A selector based on annotations.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "annotationSelectors")]
    pub annotation_selectors: Option<BTreeMap<String, String>>,
    /// a slice of label selector expressions that can be used to select objects. A list of selectors based on set-based label expressions.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "expressionSelectors")]
    pub expression_selectors: Option<Vec<KernelChaosSelectorExpressionSelectors>>,
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
pub struct KernelChaosSelectorExpressionSelectors {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// Most recently observed status of the kernel chaos experiment
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KernelChaosStatus {
    /// Conditions represents the current global condition of the chaos
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<KernelChaosStatusConditions>>,
    /// Experiment records the last experiment state.
    pub experiment: KernelChaosStatusExperiment,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KernelChaosStatusConditions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub status: String,
    #[serde(rename = "type")]
    pub r#type: String,
}

/// Experiment records the last experiment state.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KernelChaosStatusExperiment {
    /// Records are used to track the running status
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "containerRecords")]
    pub container_records: Option<Vec<KernelChaosStatusExperimentContainerRecords>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "desiredPhase")]
    pub desired_phase: Option<KernelChaosStatusExperimentDesiredPhase>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KernelChaosStatusExperimentContainerRecords {
    /// Events are the essential details about the injections and recoveries
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<KernelChaosStatusExperimentContainerRecordsEvents>>,
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
pub struct KernelChaosStatusExperimentContainerRecordsEvents {
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
pub enum KernelChaosStatusExperimentDesiredPhase {
    Run,
    Stop,
}

