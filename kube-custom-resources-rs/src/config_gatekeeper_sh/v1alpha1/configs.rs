// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/open-policy-agent/gatekeeper/config.gatekeeper.sh/v1alpha1/configs.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// ConfigSpec defines the desired state of Config.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "config.gatekeeper.sh", version = "v1alpha1", kind = "Config", plural = "configs")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct ConfigSpec {
    /// Configuration for namespace exclusion
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "match")]
    pub r#match: Option<Vec<ConfigMatch>>,
    /// Configuration for readiness tracker
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness: Option<ConfigReadiness>,
    /// Configuration for syncing k8s objects
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync: Option<ConfigSync>,
    /// Configuration for validation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation: Option<ConfigValidation>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ConfigMatch {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "excludedNamespaces")]
    pub excluded_namespaces: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processes: Option<Vec<String>>,
}

/// Configuration for readiness tracker
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ConfigReadiness {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "statsEnabled")]
    pub stats_enabled: Option<bool>,
}

/// Configuration for syncing k8s objects
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ConfigSync {
    /// If non-empty, only entries on this list will be replicated into OPA
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "syncOnly")]
    pub sync_only: Option<Vec<ConfigSyncSyncOnly>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ConfigSyncSyncOnly {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Configuration for validation
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ConfigValidation {
    /// List of requests to trace. Both "user" and "kinds" must be specified
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traces: Option<Vec<ConfigValidationTraces>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ConfigValidationTraces {
    /// Also dump the state of OPA with the trace. Set to `All` to dump everything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dump: Option<String>,
    /// Only trace requests of the following GroupVersionKind
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<ConfigValidationTracesKind>,
    /// Only trace requests from the specified user
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

/// Only trace requests of the following GroupVersionKind
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ConfigValidationTracesKind {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// ConfigStatus defines the observed state of Config.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ConfigStatus {
}

