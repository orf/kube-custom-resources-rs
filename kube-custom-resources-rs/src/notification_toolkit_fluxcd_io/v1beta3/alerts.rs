// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/fluxcd/notification-controller/notification.toolkit.fluxcd.io/v1beta3/alerts.yaml --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use std::collections::BTreeMap;
}
use self::prelude::*;

/// AlertSpec defines an alerting rule for events involving a list of objects.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "notification.toolkit.fluxcd.io", version = "v1beta3", kind = "Alert", plural = "alerts")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
#[kube(derive="PartialEq")]
pub struct AlertSpec {
    /// EventMetadata is an optional field for adding metadata to events dispatched by the
    /// controller. This can be used for enhancing the context of the event. If a field
    /// would override one already present on the original event as generated by the emitter,
    /// then the override doesn't happen, i.e. the original value is preserved, and an info
    /// log is printed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "eventMetadata")]
    pub event_metadata: Option<BTreeMap<String, String>>,
    /// EventSeverity specifies how to filter events based on severity.
    /// If set to 'info' no events will be filtered.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "eventSeverity")]
    pub event_severity: Option<AlertEventSeverity>,
    /// EventSources specifies how to filter events based
    /// on the involved object kind, name and namespace.
    #[serde(rename = "eventSources")]
    pub event_sources: Vec<AlertEventSources>,
    /// ExclusionList specifies a list of Golang regular expressions
    /// to be used for excluding messages.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "exclusionList")]
    pub exclusion_list: Option<Vec<String>>,
    /// InclusionList specifies a list of Golang regular expressions
    /// to be used for including messages.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "inclusionList")]
    pub inclusion_list: Option<Vec<String>>,
    /// ProviderRef specifies which Provider this Alert should use.
    #[serde(rename = "providerRef")]
    pub provider_ref: AlertProviderRef,
    /// Summary holds a short description of the impact and affected cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Suspend tells the controller to suspend subsequent
    /// events handling for this Alert.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspend: Option<bool>,
}

/// AlertSpec defines an alerting rule for events involving a list of objects.
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
    pub kind: AlertEventSourcesKind,
    /// MatchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels
    /// map is equivalent to an element of matchExpressions, whose key field is "key", the
    /// operator is "In", and the values array contains only "value". The requirements are ANDed.
    /// MatchLabels requires the name to be set to `*`.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
    /// Name of the referent
    /// If multiple resources are targeted `*` may be set.
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

/// ProviderRef specifies which Provider this Alert should use.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AlertProviderRef {
    /// Name of the referent.
    pub name: String,
}

