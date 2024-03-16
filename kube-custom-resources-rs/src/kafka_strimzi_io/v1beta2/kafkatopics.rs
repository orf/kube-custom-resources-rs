// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/strimzi/strimzi-kafka-operator/kafka.strimzi.io/v1beta2/kafkatopics.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// The specification of the topic.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "kafka.strimzi.io", version = "v1beta2", kind = "KafkaTopic", plural = "kafkatopics")]
#[kube(namespaced)]
#[kube(status = "KafkaTopicStatus")]
#[kube(schema = "disabled")]
pub struct KafkaTopicSpec {
    /// The topic configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<BTreeMap<String, serde_json::Value>>,
    /// The number of partitions the topic should have. This cannot be decreased after topic creation. It can be increased after topic creation, but it is important to understand the consequences that has, especially for topics with semantic partitioning. When absent this will default to the broker configuration for `num.partitions`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partitions: Option<i64>,
    /// The number of replicas the topic should have. When absent this will default to the broker configuration for `default.replication.factor`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<i64>,
    /// The name of the topic. When absent this will default to the metadata.name of the topic. It is recommended to not set this unless the topic name is not a valid Kubernetes resource name.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "topicName")]
    pub topic_name: Option<String>,
}

/// The status of the topic.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct KafkaTopicStatus {
    /// List of status conditions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// The generation of the CRD that was last reconciled by the operator.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
    /// The topic's id. For a KafkaTopic with the ready condition, this will change only if the topic gets deleted and recreated with the same name.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "topicId")]
    pub topic_id: Option<String>,
    /// Topic name.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "topicName")]
    pub topic_name: Option<String>,
}

