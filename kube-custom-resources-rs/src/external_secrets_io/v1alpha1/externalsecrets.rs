// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/external-secrets/external-secrets/external-secrets.io/v1alpha1/externalsecrets.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// ExternalSecretSpec defines the desired state of ExternalSecret.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "external-secrets.io", version = "v1alpha1", kind = "ExternalSecret", plural = "externalsecrets")]
#[kube(namespaced)]
#[kube(status = "ExternalSecretStatus")]
#[kube(schema = "disabled")]
pub struct ExternalSecretSpec {
    /// Data defines the connection between the Kubernetes Secret keys and the Provider data
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<ExternalSecretData>>,
    /// DataFrom is used to fetch all properties from a specific Provider data
    /// If multiple entries are specified, the Secret keys are merged in the specified order
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dataFrom")]
    pub data_from: Option<Vec<ExternalSecretDataFrom>>,
    /// RefreshInterval is the amount of time before the values are read again from the SecretStore provider
    /// Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h"
    /// May be set to zero to fetch and create it once. Defaults to 1h.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "refreshInterval")]
    pub refresh_interval: Option<String>,
    /// SecretStoreRef defines which SecretStore to fetch the ExternalSecret data.
    #[serde(rename = "secretStoreRef")]
    pub secret_store_ref: ExternalSecretSecretStoreRef,
    /// ExternalSecretTarget defines the Kubernetes Secret to be created
    /// There can be only one target per ExternalSecret.
    pub target: ExternalSecretTarget,
}

/// ExternalSecretData defines the connection between the Kubernetes Secret key (spec.data.<key>) and the Provider data.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ExternalSecretData {
    /// ExternalSecretDataRemoteRef defines Provider data location.
    #[serde(rename = "remoteRef")]
    pub remote_ref: ExternalSecretDataRemoteRef,
    #[serde(rename = "secretKey")]
    pub secret_key: String,
}

/// ExternalSecretDataRemoteRef defines Provider data location.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ExternalSecretDataRemoteRef {
    /// Used to define a conversion Strategy
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "conversionStrategy")]
    pub conversion_strategy: Option<ExternalSecretDataRemoteRefConversionStrategy>,
    /// Key is the key used in the Provider, mandatory
    pub key: String,
    /// Used to select a specific property of the Provider value (if a map), if supported
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub property: Option<String>,
    /// Used to select a specific version of the Provider value, if supported
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// ExternalSecretDataRemoteRef defines Provider data location.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ExternalSecretDataRemoteRefConversionStrategy {
    Default,
    Unicode,
}

/// ExternalSecretDataRemoteRef defines Provider data location.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ExternalSecretDataFrom {
    /// Used to define a conversion Strategy
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "conversionStrategy")]
    pub conversion_strategy: Option<ExternalSecretDataFromConversionStrategy>,
    /// Key is the key used in the Provider, mandatory
    pub key: String,
    /// Used to select a specific property of the Provider value (if a map), if supported
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub property: Option<String>,
    /// Used to select a specific version of the Provider value, if supported
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// ExternalSecretDataRemoteRef defines Provider data location.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ExternalSecretDataFromConversionStrategy {
    Default,
    Unicode,
}

/// SecretStoreRef defines which SecretStore to fetch the ExternalSecret data.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ExternalSecretSecretStoreRef {
    /// Kind of the SecretStore resource (SecretStore or ClusterSecretStore)
    /// Defaults to `SecretStore`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Name of the SecretStore resource
    pub name: String,
}

/// ExternalSecretTarget defines the Kubernetes Secret to be created
/// There can be only one target per ExternalSecret.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ExternalSecretTarget {
    /// CreationPolicy defines rules on how to create the resulting Secret
    /// Defaults to 'Owner'
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "creationPolicy")]
    pub creation_policy: Option<ExternalSecretTargetCreationPolicy>,
    /// Immutable defines if the final secret will be immutable
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub immutable: Option<bool>,
    /// Name defines the name of the Secret resource to be managed
    /// This field is immutable
    /// Defaults to the .metadata.name of the ExternalSecret resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Template defines a blueprint for the created Secret resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<ExternalSecretTargetTemplate>,
}

/// ExternalSecretTarget defines the Kubernetes Secret to be created
/// There can be only one target per ExternalSecret.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ExternalSecretTargetCreationPolicy {
    Owner,
    Merge,
    None,
}

/// Template defines a blueprint for the created Secret resource.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ExternalSecretTargetTemplate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<BTreeMap<String, String>>,
    /// EngineVersion specifies the template engine version
    /// that should be used to compile/execute the
    /// template specified in .data and .templateFrom[].
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "engineVersion")]
    pub engine_version: Option<ExternalSecretTargetTemplateEngineVersion>,
    /// ExternalSecretTemplateMetadata defines metadata fields for the Secret blueprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ExternalSecretTargetTemplateMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "templateFrom")]
    pub template_from: Option<Vec<ExternalSecretTargetTemplateTemplateFrom>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
}

/// Template defines a blueprint for the created Secret resource.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ExternalSecretTargetTemplateEngineVersion {
    #[serde(rename = "v1")]
    V1,
    #[serde(rename = "v2")]
    V2,
}

/// ExternalSecretTemplateMetadata defines metadata fields for the Secret blueprint.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ExternalSecretTargetTemplateMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ExternalSecretTargetTemplateTemplateFrom {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "configMap")]
    pub config_map: Option<ExternalSecretTargetTemplateTemplateFromConfigMap>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<ExternalSecretTargetTemplateTemplateFromSecret>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ExternalSecretTargetTemplateTemplateFromConfigMap {
    pub items: Vec<ExternalSecretTargetTemplateTemplateFromConfigMapItems>,
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ExternalSecretTargetTemplateTemplateFromConfigMapItems {
    pub key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ExternalSecretTargetTemplateTemplateFromSecret {
    pub items: Vec<ExternalSecretTargetTemplateTemplateFromSecretItems>,
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ExternalSecretTargetTemplateTemplateFromSecretItems {
    pub key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ExternalSecretStatus {
    /// Binding represents a servicebinding.io Provisioned Service reference to the secret
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<ExternalSecretStatusBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// refreshTime is the time and date the external secret was fetched and
    /// the target secret updated
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "refreshTime")]
    pub refresh_time: Option<String>,
    /// SyncedResourceVersion keeps track of the last synced version
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "syncedResourceVersion")]
    pub synced_resource_version: Option<String>,
}

/// Binding represents a servicebinding.io Provisioned Service reference to the secret
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ExternalSecretStatusBinding {
    /// Name of the referent.
    /// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
    /// TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

