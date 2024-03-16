// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/strimzi/strimzi-kafka-operator/kafka.strimzi.io/v1beta2/kafkaconnectors.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// The specification of the Kafka Connector.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "kafka.strimzi.io", version = "v1beta2", kind = "KafkaConnector", plural = "kafkaconnectors")]
#[kube(namespaced)]
#[kube(status = "KafkaConnectorStatus")]
#[kube(schema = "disabled")]
pub struct KafkaConnectorSpec {
    /// Automatic restart of connector and tasks configuration.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "autoRestart")]
    pub auto_restart: Option<KafkaConnectorAutoRestart>,
    /// The Class for the Kafka Connector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    /// The Kafka Connector configuration. The following properties cannot be set: connector.class, tasks.max.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<BTreeMap<String, serde_json::Value>>,
    /// Whether the connector should be paused. Defaults to false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pause: Option<bool>,
    /// The state the connector should be in. Defaults to running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<KafkaConnectorState>,
    /// The maximum number of tasks for the Kafka Connector.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "tasksMax")]
    pub tasks_max: Option<i64>,
}

/// Automatic restart of connector and tasks configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct KafkaConnectorAutoRestart {
    /// Whether automatic restart for failed connectors and tasks should be enabled or disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// The maximum number of connector restarts that the operator will try. If the connector remains in a failed state after reaching this limit, it must be restarted manually by the user. Defaults to an unlimited number of restarts.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxRestarts")]
    pub max_restarts: Option<i64>,
}

/// The specification of the Kafka Connector.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum KafkaConnectorState {
    #[serde(rename = "paused")]
    Paused,
    #[serde(rename = "stopped")]
    Stopped,
    #[serde(rename = "running")]
    Running,
}

/// The status of the Kafka Connector.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct KafkaConnectorStatus {
    /// The auto restart status.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "autoRestart")]
    pub auto_restart: Option<KafkaConnectorStatusAutoRestart>,
    /// List of status conditions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// The connector status, as reported by the Kafka Connect REST API.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "connectorStatus")]
    pub connector_status: Option<BTreeMap<String, serde_json::Value>>,
    /// The generation of the CRD that was last reconciled by the operator.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
    /// The maximum number of tasks for the Kafka Connector.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "tasksMax")]
    pub tasks_max: Option<i64>,
    /// The list of topics used by the Kafka Connector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topics: Option<Vec<String>>,
}

/// The auto restart status.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct KafkaConnectorStatusAutoRestart {
    /// The name of the connector being restarted.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "connectorName")]
    pub connector_name: Option<String>,
    /// The number of times the connector or task is restarted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
    /// The last time the automatic restart was attempted. The required format is 'yyyy-MM-ddTHH:mm:ssZ' in the UTC time zone.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastRestartTimestamp")]
    pub last_restart_timestamp: Option<String>,
}

