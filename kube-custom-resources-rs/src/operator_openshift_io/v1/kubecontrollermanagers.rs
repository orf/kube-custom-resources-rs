// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/openshift/api/operator.openshift.io/v1/kubecontrollermanagers.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// spec is the specification of the desired behavior of the Kubernetes Controller Manager
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "operator.openshift.io", version = "v1", kind = "KubeControllerManager", plural = "kubecontrollermanagers")]
#[kube(status = "KubeControllerManagerStatus")]
#[kube(schema = "disabled")]
pub struct KubeControllerManagerSpec {
    /// failedRevisionLimit is the number of failed static pod installer revisions to keep on disk and in the api -1 = unlimited, 0 or unset = 5 (default)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "failedRevisionLimit")]
    pub failed_revision_limit: Option<i32>,
    /// forceRedeploymentReason can be used to force the redeployment of the operand by providing a unique string. This provides a mechanism to kick a previously failed deployment and provide a reason why you think it will work this time instead of failing again on the same config.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "forceRedeploymentReason")]
    pub force_redeployment_reason: Option<String>,
    /// logLevel is an intent based logging for an overall component.  It does not give fine grained control, but it is a simple way to manage coarse grained logging choices that operators have to interpret for their operands. 
    ///  Valid values are: "Normal", "Debug", "Trace", "TraceAll". Defaults to "Normal".
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "logLevel")]
    pub log_level: Option<KubeControllerManagerLogLevel>,
    /// managementState indicates whether and how the operator should manage the component
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "managementState")]
    pub management_state: Option<String>,
    /// observedConfig holds a sparse config that controller has observed from the cluster state.  It exists in spec because it is an input to the level for the operator
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedConfig")]
    pub observed_config: Option<BTreeMap<String, serde_json::Value>>,
    /// operatorLogLevel is an intent based logging for the operator itself.  It does not give fine grained control, but it is a simple way to manage coarse grained logging choices that operators have to interpret for themselves. 
    ///  Valid values are: "Normal", "Debug", "Trace", "TraceAll". Defaults to "Normal".
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "operatorLogLevel")]
    pub operator_log_level: Option<KubeControllerManagerOperatorLogLevel>,
    /// succeededRevisionLimit is the number of successful static pod installer revisions to keep on disk and in the api -1 = unlimited, 0 or unset = 5 (default)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "succeededRevisionLimit")]
    pub succeeded_revision_limit: Option<i32>,
    /// unsupportedConfigOverrides overrides the final configuration that was computed by the operator. Red Hat does not support the use of this field. Misuse of this field could lead to unexpected behavior or conflict with other configuration options. Seek guidance from the Red Hat support before using this field. Use of this property blocks cluster upgrades, it must be removed before upgrading your cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "unsupportedConfigOverrides")]
    pub unsupported_config_overrides: Option<BTreeMap<String, serde_json::Value>>,
    /// useMoreSecureServiceCA indicates that the service-ca.crt provided in SA token volumes should include only enough certificates to validate service serving certificates. Once set to true, it cannot be set to false. Even if someone finds a way to set it back to false, the service-ca.crt files that previously existed will only have the more secure content.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "useMoreSecureServiceCA")]
    pub use_more_secure_service_ca: Option<bool>,
}

/// spec is the specification of the desired behavior of the Kubernetes Controller Manager
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum KubeControllerManagerLogLevel {
    #[serde(rename = "")]
    KopiumEmpty,
    Normal,
    Debug,
    Trace,
    TraceAll,
}

/// spec is the specification of the desired behavior of the Kubernetes Controller Manager
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum KubeControllerManagerOperatorLogLevel {
    #[serde(rename = "")]
    KopiumEmpty,
    Normal,
    Debug,
    Trace,
    TraceAll,
}

/// status is the most recently observed status of the Kubernetes Controller Manager
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct KubeControllerManagerStatus {
    /// conditions is a list of conditions and their status
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// generations are used to determine when an item needs to be reconciled or has changed in a way that needs a reaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generations: Option<Vec<KubeControllerManagerStatusGenerations>>,
    /// latestAvailableRevision is the deploymentID of the most recent deployment
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "latestAvailableRevision")]
    pub latest_available_revision: Option<i32>,
    /// latestAvailableRevisionReason describe the detailed reason for the most recent deployment
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "latestAvailableRevisionReason")]
    pub latest_available_revision_reason: Option<String>,
    /// nodeStatuses track the deployment values and errors across individual nodes
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nodeStatuses")]
    pub node_statuses: Option<Vec<KubeControllerManagerStatusNodeStatuses>>,
    /// observedGeneration is the last generation change you've dealt with
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
    /// readyReplicas indicates how many replicas are ready and at the desired state
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "readyReplicas")]
    pub ready_replicas: Option<i32>,
    /// version is the level this availability applies to
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// GenerationStatus keeps track of the generation for a given resource so that decisions about forced updates can be made.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct KubeControllerManagerStatusGenerations {
    /// group is the group of the thing you're tracking
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// hash is an optional field set for resources without generation that are content sensitive like secrets and configmaps
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// lastGeneration is the last generation of the workload controller involved
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastGeneration")]
    pub last_generation: Option<i64>,
    /// name is the name of the thing you're tracking
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// namespace is where the thing you're tracking is
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// resource is the resource type of the thing you're tracking
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

/// NodeStatus provides information about the current state of a particular node managed by this operator.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct KubeControllerManagerStatusNodeStatuses {
    /// currentRevision is the generation of the most recently successful deployment
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "currentRevision")]
    pub current_revision: Option<i32>,
    /// lastFailedCount is how often the installer pod of the last failed revision failed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastFailedCount")]
    pub last_failed_count: Option<i64>,
    /// lastFailedReason is a machine readable failure reason string.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastFailedReason")]
    pub last_failed_reason: Option<String>,
    /// lastFailedRevision is the generation of the deployment we tried and failed to deploy.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastFailedRevision")]
    pub last_failed_revision: Option<i32>,
    /// lastFailedRevisionErrors is a list of human readable errors during the failed deployment referenced in lastFailedRevision.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastFailedRevisionErrors")]
    pub last_failed_revision_errors: Option<Vec<String>>,
    /// lastFailedTime is the time the last failed revision failed the last time.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastFailedTime")]
    pub last_failed_time: Option<String>,
    /// lastFallbackCount is how often a fallback to a previous revision happened.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastFallbackCount")]
    pub last_fallback_count: Option<i64>,
    /// nodeName is the name of the node
    #[serde(rename = "nodeName")]
    pub node_name: String,
    /// targetRevision is the generation of the deployment we're trying to apply
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "targetRevision")]
    pub target_revision: Option<i32>,
}

