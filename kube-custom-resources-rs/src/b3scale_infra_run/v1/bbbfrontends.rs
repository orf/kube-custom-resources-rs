// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/b3scale/b3scale-operator/b3scale.infra.run/v1/bbbfrontends.yaml --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// Desired state of the BBBFrontend resource.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "b3scale.infra.run", version = "v1", kind = "BBBFrontend", plural = "bbbfrontends")]
#[kube(namespaced)]
#[kube(status = "BBBFrontendStatus")]
#[kube(schema = "disabled")]
pub struct BBBFrontendSpec {
    /// Predefined credentials for the B3scale instance
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<BBBFrontendCredentials>,
    /// Settings defines the B3Scale instance settings
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<BBBFrontendSettings>,
}

/// Predefined credentials for the B3scale instance
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BBBFrontendCredentials {
    /// Predefined key for B3scale instance, will be defined if not set
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// SecretRef is a reference to a key in a Secret resource containing the key to connect to the BBB instance.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretRef")]
    pub secret_ref: Option<BBBFrontendCredentialsSecretRef>,
}

/// SecretRef is a reference to a key in a Secret resource containing the key to connect to the BBB instance.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BBBFrontendCredentialsSecretRef {
    /// The key of the entry in the Secret resource's `data` field to be used.
    pub key: String,
    /// Name of the resource being referred to. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
    pub name: String,
}

/// Settings defines the B3Scale instance settings
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BBBFrontendSettings {
    /// See https://github.com/b3scale/b3scale#configure-create-parameter-defaults-and-overrides
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create_default_params: Option<BTreeMap<String, String>>,
    /// See https://github.com/b3scale/b3scale#configure-create-parameter-defaults-and-overrides
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create_override_params: Option<BTreeMap<String, String>>,
    /// See https://github.com/b3scale/b3scale#middleware-configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_presentation: Option<BBBFrontendSettingsDefaultPresentation>,
    /// See https://github.com/b3scale/b3scale#middleware-configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_tags: Option<Vec<String>>,
}

/// See https://github.com/b3scale/b3scale#middleware-configuration
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BBBFrontendSettingsDefaultPresentation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Status of the BBBFrontend. This is set and managed automatically.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BBBFrontendStatus {
    /// List of status conditions to indicate the status of the BBB frontend. Known condition types are `Ready`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
}

