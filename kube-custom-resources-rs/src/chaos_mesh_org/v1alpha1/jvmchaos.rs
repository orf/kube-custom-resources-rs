// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/chaos-mesh/chaos-mesh/chaos-mesh.org/v1alpha1/jvmchaos.yaml --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// JVMChaosSpec defines the desired state of JVMChaos
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "chaos-mesh.org", version = "v1alpha1", kind = "JVMChaos", plural = "jvmchaos")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct JVMChaosSpec {
    /// Action defines the specific jvm chaos action. Supported action: latency;return;exception;stress;gc;ruleData
    pub action: JVMChaosAction,
    /// Java class
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    /// ContainerNames indicates list of the name of affected container. If not set, the first container will be injected
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "containerNames")]
    pub container_names: Option<Vec<String>>,
    /// the CPU core number needs to use, only set it when action is stress
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "cpuCount")]
    pub cpu_count: Option<i64>,
    /// the match database default value is "", means match all database
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    /// Duration represents the duration of the chaos action
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration: Option<String>,
    /// the exception which needs to throw for action `exception` or the exception message needs to throw in action `mysql`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exception: Option<String>,
    /// the latency duration for action 'latency', unit ms or the latency duration in action `mysql`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency: Option<i64>,
    /// the memory type needs to locate, only set it when action is stress, the value can be 'stack' or 'heap'
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "memType")]
    pub mem_type: Option<String>,
    /// the method in Java class
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Mode defines the mode to run chaos action. Supported mode: one / all / fixed / fixed-percent / random-max-percent
    pub mode: JVMChaosMode,
    /// the version of mysql-connector-java, only support 5.X.X(set to "5") and 8.X.X(set to "8") now
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "mysqlConnectorVersion")]
    pub mysql_connector_version: Option<String>,
    /// byteman rule name, should be unique, and will generate one if not set
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// the pid of Java process which needs to attach
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<i64>,
    /// the port of agent server, default 9277
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<i32>,
    /// RemoteCluster represents the remote cluster where the chaos will be deployed
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "remoteCluster")]
    pub remote_cluster: Option<String>,
    /// the byteman rule's data for action 'ruleData'
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ruleData")]
    pub rule_data: Option<String>,
    /// Selector is used to select pods that are used to inject chaos action.
    pub selector: JVMChaosSelector,
    /// the match sql type default value is "", means match all SQL type. The value can be 'select', 'insert', 'update', 'delete', 'replace'.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sqlType")]
    pub sql_type: Option<String>,
    /// the match table default value is "", means match all table
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    /// Value is required when the mode is set to `FixedMode` / `FixedPercentMode` / `RandomMaxPercentMode`. If `FixedMode`, provide an integer of pods to do chaos action. If `FixedPercentMode`, provide a number from 0-100 to specify the percent of pods the server can do chaos action. IF `RandomMaxPercentMode`,  provide a number from 0-100 to specify the max percent of pods to do chaos action
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// JVMChaosSpec defines the desired state of JVMChaos
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum JVMChaosAction {
    #[serde(rename = "latency")]
    Latency,
    #[serde(rename = "return")]
    Return,
    #[serde(rename = "exception")]
    Exception,
    #[serde(rename = "stress")]
    Stress,
    #[serde(rename = "gc")]
    Gc,
    #[serde(rename = "ruleData")]
    RuleData,
    #[serde(rename = "mysql")]
    Mysql,
}

/// JVMChaosSpec defines the desired state of JVMChaos
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum JVMChaosMode {
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
pub struct JVMChaosSelector {
    /// Map of string keys and values that can be used to select objects. A selector based on annotations.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "annotationSelectors")]
    pub annotation_selectors: Option<BTreeMap<String, String>>,
    /// a slice of label selector expressions that can be used to select objects. A list of selectors based on set-based label expressions.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "expressionSelectors")]
    pub expression_selectors: Option<Vec<JVMChaosSelectorExpressionSelectors>>,
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
pub struct JVMChaosSelectorExpressionSelectors {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// JVMChaosStatus defines the observed state of JVMChaos
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct JVMChaosStatus {
    /// Conditions represents the current global condition of the chaos
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<JVMChaosStatusConditions>>,
    /// Experiment records the last experiment state.
    pub experiment: JVMChaosStatusExperiment,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct JVMChaosStatusConditions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub status: String,
    #[serde(rename = "type")]
    pub r#type: String,
}

/// Experiment records the last experiment state.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct JVMChaosStatusExperiment {
    /// Records are used to track the running status
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "containerRecords")]
    pub container_records: Option<Vec<JVMChaosStatusExperimentContainerRecords>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "desiredPhase")]
    pub desired_phase: Option<JVMChaosStatusExperimentDesiredPhase>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct JVMChaosStatusExperimentContainerRecords {
    /// Events are the essential details about the injections and recoveries
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<JVMChaosStatusExperimentContainerRecordsEvents>>,
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
pub struct JVMChaosStatusExperimentContainerRecordsEvents {
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
pub enum JVMChaosStatusExperimentDesiredPhase {
    Run,
    Stop,
}

