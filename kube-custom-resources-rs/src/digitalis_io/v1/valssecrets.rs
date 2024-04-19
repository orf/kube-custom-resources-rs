// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/digitalis-io/vals-operator/digitalis.io/v1/valssecrets.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// ValsSecretSpec defines the desired state of ValsSecret
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "digitalis.io", version = "v1", kind = "ValsSecret", plural = "valssecrets")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct ValsSecretSpec {
    pub data: BTreeMap<String, ValsSecretData>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub databases: Option<Vec<ValsSecretDatabases>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ValsSecretData {
    /// Encoding type for the secret. Only base64 supported. Optional
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    /// Ref value to the secret in the format ref+backend://path https://github.com/helmfile/vals
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ref")]
    pub r#ref: Option<String>,
}

/// Database defines a DB connection
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ValsSecretDatabases {
    /// Defines the database type
    pub driver: String,
    /// List of hosts to connect to, they'll be tried in sequence until one succeeds
    pub hosts: Vec<String>,
    /// Credentials to access the database
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "loginCredentials")]
    pub login_credentials: Option<ValsSecretDatabasesLoginCredentials>,
    /// Key in the secret containing the database username
    #[serde(rename = "passwordKey")]
    pub password_key: String,
    /// Database port number
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<i64>,
    /// Used for MySQL only, the host part for the username
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "userHost")]
    pub user_host: Option<String>,
    /// Key in the secret containing the database username
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "usernameKey")]
    pub username_key: Option<String>,
}

/// Credentials to access the database
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ValsSecretDatabasesLoginCredentials {
    /// Optional namespace of the secret, default current namespace
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Key in the secret containing the database username
    #[serde(rename = "passwordKey")]
    pub password_key: String,
    /// Name of the secret containing the credentials to be able to log in to the database
    #[serde(rename = "secretName")]
    pub secret_name: String,
    /// Key in the secret containing the database username
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "usernameKey")]
    pub username_key: Option<String>,
}

/// ValsSecretStatus defines the observed state of ValsSecret
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ValsSecretStatus {
}

