// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/otterize/helm-charts/k8s.otterize.com/v1alpha2/clientintents.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// IntentsSpec defines the desired state of ClientIntents
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "k8s.otterize.com", version = "v1alpha2", kind = "ClientIntents", plural = "clientintents")]
#[kube(namespaced)]
#[kube(status = "ClientIntentsStatus")]
#[kube(schema = "disabled")]
pub struct ClientIntentsSpec {
    pub calls: Vec<ClientIntentsCalls>,
    pub service: ClientIntentsService,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClientIntentsCalls {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "databaseResources")]
    pub database_resources: Option<Vec<ClientIntentsCallsDatabaseResources>>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<ClientIntentsCallsResources>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topics: Option<Vec<ClientIntentsCallsTopics>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<ClientIntentsCallsType>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClientIntentsCallsDatabaseResources {
    #[serde(rename = "databaseName")]
    pub database_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operations: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClientIntentsCallsResources {
    pub methods: Vec<String>,
    pub path: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClientIntentsCallsTopics {
    pub name: String,
    pub operations: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ClientIntentsCallsType {
    #[serde(rename = "http")]
    Http,
    #[serde(rename = "kafka")]
    Kafka,
    #[serde(rename = "database")]
    Database,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClientIntentsService {
    pub name: String,
}

/// IntentsStatus defines the observed state of ClientIntents
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClientIntentsStatus {
    /// upToDate field reflects whether the client intents have successfully been applied
    /// to the cluster to the state specified
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "upToDate")]
    pub up_to_date: Option<bool>,
}

