// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/digitalis-io/vals-operator/digitalis.io/v1beta1/dbsecrets.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// DbSecretSpec defines the desired state of DbSecret
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "digitalis.io", version = "v1beta1", kind = "DbSecret", plural = "dbsecrets")]
#[kube(namespaced)]
#[kube(status = "DbSecretStatus")]
#[kube(schema = "disabled")]
pub struct DbSecretSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renew: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollout: Option<Vec<DbSecretRollout>>,
    /// Name can override the secret name, defaults to manifests.name
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretName")]
    pub secret_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<BTreeMap<String, String>>,
    pub vault: DbSecretVault,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct DbSecretRollout {
    /// Kind is either Deployment, Pod or StatefulSet
    pub kind: String,
    /// Name is the object name
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct DbSecretVault {
    /// Mount is the vault database
    pub mount: String,
    /// Role is the vault role used to connect to the database
    pub role: String,
}

/// DbSecretStatus defines the observed state of DbSecret
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct DbSecretStatus {
}

