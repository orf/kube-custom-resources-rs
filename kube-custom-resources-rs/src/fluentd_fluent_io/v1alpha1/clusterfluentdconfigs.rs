// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/fluent/fluent-operator/fluentd.fluent.io/v1alpha1/clusterfluentdconfigs.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// ClusterFluentdConfigSpec defines the desired state of ClusterFluentdConfig
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "fluentd.fluent.io", version = "v1alpha1", kind = "ClusterFluentdConfig", plural = "clusterfluentdconfigs")]
#[kube(status = "ClusterFluentdConfigStatus")]
#[kube(schema = "disabled")]
pub struct ClusterFluentdConfigSpec {
    /// Select cluster filter plugins
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clusterFilterSelector")]
    pub cluster_filter_selector: Option<ClusterFluentdConfigClusterFilterSelector>,
    /// Select cluster input plugins
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clusterInputSelector")]
    pub cluster_input_selector: Option<ClusterFluentdConfigClusterInputSelector>,
    /// Select cluster output plugins
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clusterOutputSelector")]
    pub cluster_output_selector: Option<ClusterFluentdConfigClusterOutputSelector>,
    /// Emit mode. If batch, the plugin will emit events per labels matched. Enum: record, batch. will make no effect if EnableFilterKubernetes is set false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emit_mode: Option<ClusterFluentdConfigEmitMode>,
    /// Sticky tags will match only one record from an event stream. The same tag will be treated the same way. will make no effect if EnableFilterKubernetes is set false.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "stickyTags")]
    pub sticky_tags: Option<String>,
    /// A set of container names. Ignored if left empty.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "watchedConstainers")]
    pub watched_constainers: Option<Vec<String>>,
    /// A set of hosts. Ignored if left empty.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "watchedHosts")]
    pub watched_hosts: Option<Vec<String>>,
    /// Use this field to filter the logs, will make no effect if EnableFilterKubernetes is set false.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "watchedLabels")]
    pub watched_labels: Option<BTreeMap<String, String>>,
    /// A set of namespaces. The whole namespaces would be watched if left empty.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "watchedNamespaces")]
    pub watched_namespaces: Option<Vec<String>>,
}

/// Select cluster filter plugins
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterFluentdConfigClusterFilterSelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<ClusterFluentdConfigClusterFilterSelectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterFluentdConfigClusterFilterSelectorMatchExpressions {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// Select cluster input plugins
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterFluentdConfigClusterInputSelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<ClusterFluentdConfigClusterInputSelectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterFluentdConfigClusterInputSelectorMatchExpressions {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// Select cluster output plugins
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterFluentdConfigClusterOutputSelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<ClusterFluentdConfigClusterOutputSelectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterFluentdConfigClusterOutputSelectorMatchExpressions {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// ClusterFluentdConfigSpec defines the desired state of ClusterFluentdConfig
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ClusterFluentdConfigEmitMode {
    #[serde(rename = "record")]
    Record,
    #[serde(rename = "batch")]
    Batch,
}

/// ClusterFluentdConfigStatus defines the observed state of ClusterFluentdConfig
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterFluentdConfigStatus {
    /// Messages defines the plugin errors which is selected by this fluentdconfig
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub messages: Option<String>,
    /// The state of this fluentd config
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

