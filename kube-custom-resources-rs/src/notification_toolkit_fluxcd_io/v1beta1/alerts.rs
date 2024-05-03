// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/fluxcd/notification-controller/notification.toolkit.fluxcd.io/v1beta1/alerts.yaml --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use std::collections::BTreeMap;
    pub use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
}
use self::prelude::*;

/// AlertSpec defines an alerting rule for events involving a list of objects
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "notification.toolkit.fluxcd.io", version = "v1beta1", kind = "Alert", plural = "alerts")]
#[kube(namespaced)]
#[kube(status = "AlertStatus")]
#[kube(schema = "disabled")]
#[kube(derive="PartialEq")]
pub struct AlertSpec {
    /// Filter events based on severity, defaults to ('info').
    /// If set to 'info' no events will be filtered.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "eventSeverity")]
    pub event_severity: Option<AlertEventSeverity>,
    /// Filter events based on the involved objects.
    #[serde(rename = "eventSources")]
    pub event_sources: Vec<AlertEventSources>,
    /// A list of Golang regular expressions to be used for excluding messages.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "exclusionList")]
    pub exclusion_list: Option<Vec<String>>,
    /// Send events using this provider.
    #[serde(rename = "providerRef")]
    pub provider_ref: AlertProviderRef,
    /// Short description of the impact and affected cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// This flag tells the controller to suspend subsequent events dispatching.
    /// Defaults to false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspend: Option<bool>,
}

/// AlertSpec defines an alerting rule for events involving a list of objects
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum AlertEventSeverity {
    #[serde(rename = "info")]
    Info,
    #[serde(rename = "error")]
    Error,
}

/// CrossNamespaceObjectReference contains enough information to let you locate the
/// typed referenced object at cluster level
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AlertEventSources {
    /// API version of the referent
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiVersion")]
    pub api_version: Option<String>,
    /// Kind of the referent
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<AlertEventSourcesKind>,
    /// MatchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels
    /// map is equivalent to an element of matchExpressions, whose key field is "key", the
    /// operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
    /// Name of the referent
    pub name: String,
    /// Namespace of the referent
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// CrossNamespaceObjectReference contains enough information to let you locate the
/// typed referenced object at cluster level
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum AlertEventSourcesKind {
    Bucket,
    GitRepository,
    Kustomization,
    HelmRelease,
    HelmChart,
    HelmRepository,
    ImageRepository,
    ImagePolicy,
    ImageUpdateAutomation,
    #[serde(rename = "OCIRepository")]
    OciRepository,
}

/// Send events using this provider.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AlertProviderRef {
    /// Name of the referent.
    pub name: String,
}

/// AlertStatus defines the observed state of Alert
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AlertStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// ObservedGeneration is the last observed generation.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
}

