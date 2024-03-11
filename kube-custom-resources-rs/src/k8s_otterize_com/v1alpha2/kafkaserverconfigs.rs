// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/otterize/helm-charts/k8s.otterize.com/v1alpha2/kafkaserverconfigs.yaml --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// KafkaServerConfigSpec defines the desired state of KafkaServerConfig
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "k8s.otterize.com", version = "v1alpha2", kind = "KafkaServerConfig", plural = "kafkaserverconfigs")]
#[kube(namespaced)]
#[kube(status = "KafkaServerConfigStatus")]
#[kube(schema = "disabled")]
pub struct KafkaServerConfigSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
    /// If Intents for network policies are enabled, and there are other Intents to this Kafka server, will automatically create an Intent so that the Intents Operator can connect. Set to true to disable.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "noAutoCreateIntentsForOperator")]
    pub no_auto_create_intents_for_operator: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<KafkaServerConfigService>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<KafkaServerConfigTls>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topics: Option<Vec<KafkaServerConfigTopics>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KafkaServerConfigService {
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KafkaServerConfigTls {
    #[serde(rename = "certFile")]
    pub cert_file: String,
    #[serde(rename = "keyFile")]
    pub key_file: String,
    #[serde(rename = "rootCAFile")]
    pub root_ca_file: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KafkaServerConfigTopics {
    #[serde(rename = "clientIdentityRequired")]
    pub client_identity_required: bool,
    #[serde(rename = "intentsRequired")]
    pub intents_required: bool,
    pub pattern: KafkaServerConfigTopicsPattern,
    pub topic: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum KafkaServerConfigTopicsPattern {
    #[serde(rename = "literal")]
    Literal,
    #[serde(rename = "prefix")]
    Prefix,
}

/// KafkaServerConfigStatus defines the observed state of KafkaServerConfig
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KafkaServerConfigStatus {
}

