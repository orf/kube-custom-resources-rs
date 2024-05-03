// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kubernetes-sigs/hierarchical-namespaces/hnc.x-k8s.io/v1alpha2/hncconfigurations.yaml --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
}
use self::prelude::*;

/// HNCConfigurationSpec defines the desired state of HNC configuration.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "hnc.x-k8s.io", version = "v1alpha2", kind = "HNCConfiguration", plural = "hncconfigurations")]
#[kube(schema = "disabled")]
#[kube(derive="PartialEq")]
pub struct HNCConfigurationSpec {
    /// Resources defines the cluster-wide settings for resource synchronization. Note that 'roles' and 'rolebindings' are pre-configured by HNC with 'Propagate' mode and are omitted in the spec. Any configuration of 'roles' or 'rolebindings' are not allowed. To learn more, see https://github.com/kubernetes-sigs/hierarchical-namespaces/blob/master/docs/user-guide/how-to.md#admin-types
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<HNCConfigurationResources>>,
}

/// ResourceSpec defines the desired synchronization state of a specific resource.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct HNCConfigurationResources {
    /// Group of the resource defined below. This is used to unambiguously identify the resource. It may be omitted for core resources (e.g. "secrets").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Synchronization mode of the kind. If the field is empty, it will be treated as "Propagate".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<HNCConfigurationResourcesMode>,
    /// Resource to be configured.
    pub resource: String,
}

/// ResourceSpec defines the desired synchronization state of a specific resource.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum HNCConfigurationResourcesMode {
    Propagate,
    Ignore,
    Remove,
    AllowPropagate,
}

/// HNCConfigurationStatus defines the observed state of HNC configuration.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct HNCConfigurationStatus {
    /// Conditions describes the errors, if any. If there are any conditions with "ActivitiesHalted" reason, this means that HNC cannot function in the affected namespaces. The HierarchyConfiguration object in each of the affected namespaces will have more information. To learn more about conditions, see https://github.com/kubernetes-sigs/hierarchical-namespaces/blob/master/docs/user-guide/concepts.md#admin-conditions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// Resources indicates the observed synchronization states of the resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<HNCConfigurationStatusResources>>,
}

/// ResourceStatus defines the actual synchronization state of a specific resource.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct HNCConfigurationStatusResources {
    /// The API group of the resource being synchronized.
    pub group: String,
    /// Mode describes the synchronization mode of the kind. Typically, it will be the same as the mode in the spec, except when the reconciler has fallen behind or for resources with an enforced default synchronization mode, such as RBAC objects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Tracks the number of objects that are being propagated to descendant namespaces. The propagated objects are created by HNC.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "numPropagatedObjects")]
    pub num_propagated_objects: Option<i64>,
    /// Tracks the number of objects that are created by users.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "numSourceObjects")]
    pub num_source_objects: Option<i64>,
    /// The resource being synchronized.
    pub resource: String,
    /// The API version used by HNC when propagating this resource.
    pub version: String,
}

