// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/bitnami-labs/sealed-secrets/bitnami.com/v1alpha1/sealedsecrets.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// SealedSecretSpec is the specification of a SealedSecret
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "bitnami.com", version = "v1alpha1", kind = "SealedSecret", plural = "sealedsecrets")]
#[kube(namespaced)]
#[kube(status = "SealedSecretStatus")]
#[kube(schema = "disabled")]
pub struct SealedSecretSpec {
    /// Data is deprecated and will be removed eventually. Use per-value EncryptedData instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(rename = "encryptedData")]
    pub encrypted_data: BTreeMap<String, String>,
    /// Template defines the structure of the Secret that will be created from this sealed secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<SealedSecretTemplate>,
}

/// Template defines the structure of the Secret that will be created from this sealed secret.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SealedSecretTemplate {
    /// Keys that should be templated using decrypted data
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<BTreeMap<String, String>>,
    /// Immutable, if set to true, ensures that data stored in the Secret cannot be updated (only object metadata can be modified). If not set to true, the field can be modified at any time. Defaulted to nil.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub immutable: Option<bool>,
    /// Standard object's metadata. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#metadata
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<SealedSecretTemplateMetadata>,
    /// Used to facilitate programmatic handling of secret data.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
}

/// Standard object's metadata. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#metadata
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SealedSecretTemplateMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalizers: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// SealedSecretStatus is the most recently observed status of the SealedSecret.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SealedSecretStatus {
    /// Represents the latest available observations of a sealed secret's current state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// ObservedGeneration reflects the generation most recently observed by the sealed-secrets controller.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
}

