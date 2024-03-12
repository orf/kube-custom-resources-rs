// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/craftypath/sops-operator/craftypath.github.io/v1alpha1/sopssecrets.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// SopsSecretSpec defines the desired state of SopsSecret.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "craftypath.github.io", version = "v1alpha1", kind = "SopsSecret", plural = "sopssecrets")]
#[kube(namespaced)]
#[kube(status = "SopsSecretStatus")]
#[kube(schema = "disabled")]
pub struct SopsSecretSpec {
    /// Metadata allows adding labels and annotations to generated Secrets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<SopsSecretMetadata>,
    /// StringData allows specifying Sops-encrypted secret data in string form.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "stringData")]
    pub string_data: Option<BTreeMap<String, String>>,
    /// Type specifies the type of the secret.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
}

/// Metadata allows adding labels and annotations to generated Secrets.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SopsSecretMetadata {
    /// Annotations allows adding annotations to generated Secrets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
    /// Labels allows adding labels to generated Secrets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
}

/// SopsSecretStatus defines the observed state of SopsSecret.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SopsSecretStatus {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastUpdate")]
    pub last_update: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

