// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/emqx/emqx-operator/apps.emqx.io/v1beta4/rebalances.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "apps.emqx.io", version = "v1beta4", kind = "Rebalance", plural = "rebalances")]
#[kube(namespaced)]
#[kube(status = "RebalanceStatus")]
#[kube(schema = "disabled")]
pub struct RebalanceSpec {
    #[serde(rename = "instanceName")]
    pub instance_name: String,
    #[serde(rename = "rebalanceStrategy")]
    pub rebalance_strategy: RebalanceRebalanceStrategy,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RebalanceRebalanceStrategy {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "absConnThreshold")]
    pub abs_conn_threshold: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "absSessThreshold")]
    pub abs_sess_threshold: Option<i32>,
    #[serde(rename = "connEvictRate")]
    pub conn_evict_rate: i32,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "relConnThreshold")]
    pub rel_conn_threshold: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "relSessThreshold")]
    pub rel_sess_threshold: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sessEvictRate")]
    pub sess_evict_rate: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "waitHealthCheck")]
    pub wait_health_check: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "waitTakeover")]
    pub wait_takeover: Option<i32>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RebalanceStatus {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "completedTime")]
    pub completed_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "rebalanceStates")]
    pub rebalance_states: Option<Vec<RebalanceStatusRebalanceStates>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "startedTime")]
    pub started_time: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RebalanceStatusRebalanceStates {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_eviction_rate: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinator_node: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub donors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipients: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_eviction_rate: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

