// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws/zone-aware-controllers-for-k8s/zonecontrol.k8s.aws/v1/zonedisruptionbudgets.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

/// ZoneDisruptionBudgetSpec defines the desired state of ZoneDisruptionBudget
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "zonecontrol.k8s.aws", version = "v1", kind = "ZoneDisruptionBudget", plural = "zonedisruptionbudgets")]
#[kube(namespaced)]
#[kube(status = "ZoneDisruptionBudgetStatus")]
#[kube(schema = "disabled")]
pub struct ZoneDisruptionBudgetSpec {
    /// Dryn-run mode that can be used to test the new controller before enable it
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dryRun")]
    pub dry_run: Option<bool>,
    /// Evict pod specification is allowed if at most "maxUnavailable" pods selected by "selector" are unavailable in the same zone after the above operation for pod. Evictions are not allowed if there are unavailable pods in other zones.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxUnavailable")]
    pub max_unavailable: Option<IntOrString>,
    /// Selector label query over pods managed by the budget
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<ZoneDisruptionBudgetSelector>,
}

/// Selector label query over pods managed by the budget
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ZoneDisruptionBudgetSelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<ZoneDisruptionBudgetSelectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ZoneDisruptionBudgetSelectorMatchExpressions {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// ZoneDisruptionBudgetStatus defines the observed state of ZoneDisruptionBudget
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ZoneDisruptionBudgetStatus {
    /// Current number of healthy pods per zone
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "currentHealthy")]
    pub current_healthy: Option<BTreeMap<String, i32>>,
    /// Current number of unhealthy pods per zone
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "currentUnhealthy")]
    pub current_unhealthy: Option<BTreeMap<String, i32>>,
    /// Minimum desired number of healthy pods per zone
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "desiredHealthy")]
    pub desired_healthy: Option<BTreeMap<String, i32>>,
    /// DisruptedPods contains information about pods whose eviction was processed by the API server eviction subresource handler but has not yet been observed by the ZoneDisruptionBudget controller. A pod will be in this map from the time when the API server processed the eviction request to the time when the pod is seen by ZDB controller as having been marked for deletion (or after a timeout). The key in the map is the name of the pod and the value is the time when the API server processed the eviction request. If the deletion didn't occur and a pod is still there it will be removed from the list automatically by ZoneDisruptionBudget controller after some time.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "disruptedPods")]
    pub disrupted_pods: Option<BTreeMap<String, String>>,
    /// Number of pod disruptions that are currently allowed *per zone*
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "disruptionsAllowed")]
    pub disruptions_allowed: Option<BTreeMap<String, i32>>,
    /// Total number of expected replicas per zone
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "expectedPods")]
    pub expected_pods: Option<BTreeMap<String, i32>>,
    /// Most recent generation observed when updating this ZDB status. DisruptionsAllowed and other status information is valid only if observedGeneration equals to ZDB's object generation.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
}

