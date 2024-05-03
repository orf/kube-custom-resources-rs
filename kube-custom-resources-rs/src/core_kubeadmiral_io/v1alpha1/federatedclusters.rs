// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kubewharf/kubeadmiral/core.kubeadmiral.io/v1alpha1/federatedclusters.yaml --derive=Default --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use std::collections::BTreeMap;
    pub use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
    pub use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
}
use self::prelude::*;

/// FederatedClusterSpec defines the desired state of FederatedCluster
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "core.kubeadmiral.io", version = "v1alpha1", kind = "FederatedCluster", plural = "federatedclusters")]
#[kube(status = "FederatedClusterStatus")]
#[kube(schema = "disabled")]
#[kube(derive="Default")]
#[kube(derive="PartialEq")]
pub struct FederatedClusterSpec {
    /// The API endpoint of the member cluster. This can be a hostname, hostname:port, IP or IP:port.
    #[serde(rename = "apiEndpoint")]
    pub api_endpoint: String,
    /// Access API endpoint with security.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,
    /// Name of the secret containing the token required to access the member cluster. The secret needs to exist in the fed system namespace.
    #[serde(rename = "secretRef")]
    pub secret_ref: FederatedClusterSecretRef,
    /// If specified, the cluster's taints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taints: Option<Vec<FederatedClusterTaints>>,
    /// Whether to use service account token to authenticate to the member cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "useServiceAccount")]
    pub use_service_account: Option<bool>,
}

/// Name of the secret containing the token required to access the member cluster. The secret needs to exist in the fed system namespace.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FederatedClusterSecretRef {
    /// Name of a secret within the enclosing namespace
    pub name: String,
}

/// The node this Taint is attached to has the "effect" on any pod that does not tolerate the Taint.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FederatedClusterTaints {
    /// Required. The effect of the taint on pods that do not tolerate the taint. Valid effects are NoSchedule, PreferNoSchedule and NoExecute.
    pub effect: String,
    /// Required. The taint key to be applied to a node.
    pub key: String,
    /// TimeAdded represents the time at which the taint was added. It is only written for NoExecute taints.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "timeAdded")]
    pub time_added: Option<String>,
    /// The taint value corresponding to the taint key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// FederatedClusterStatus defines the observed state of FederatedCluster
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FederatedClusterStatus {
    /// The list of api resource types defined in the federated cluster
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiResourceTypes")]
    pub api_resource_types: Option<Vec<FederatedClusterStatusApiResourceTypes>>,
    /// Conditions is an array of current cluster conditions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// Whether any effectual action was performed in the cluster while joining. If true, clean-up is required on cluster removal to undo the side-effects.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "joinPerformed")]
    pub join_performed: Option<bool>,
    /// Resources describes the cluster's resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<FederatedClusterStatusResources>,
}

/// APIResource represents a Kubernetes API resource.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FederatedClusterStatusApiResourceTypes {
    /// Group of the resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Kind of the resource.
    pub kind: String,
    /// Lower-cased plural name of the resource (e.g. configmaps).  If not provided, it will be computed by lower-casing the kind and suffixing an 's'.
    #[serde(rename = "pluralName")]
    pub plural_name: String,
    /// Scope of the resource.
    pub scope: String,
    /// Version of the resource.
    pub version: String,
}

/// Resources describes the cluster's resources.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FederatedClusterStatusResources {
    /// Allocatable represents the total resources that are allocatable for scheduling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocatable: Option<BTreeMap<String, IntOrString>>,
    /// Available represents the resources currently available for scheduling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub available: Option<BTreeMap<String, IntOrString>>,
    /// SchedulableNodes represents number of nodes which is ready and schedulable.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "schedulableNodes")]
    pub schedulable_nodes: Option<i64>,
}

