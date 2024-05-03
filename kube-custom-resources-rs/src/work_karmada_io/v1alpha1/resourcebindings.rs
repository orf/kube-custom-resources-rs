// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/karmada-io/karmada/work.karmada.io/v1alpha1/resourcebindings.yaml --derive=PartialEq
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

/// Spec represents the desired behavior.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "work.karmada.io", version = "v1alpha1", kind = "ResourceBinding", plural = "resourcebindings")]
#[kube(namespaced)]
#[kube(status = "ResourceBindingStatus")]
#[kube(schema = "disabled")]
#[kube(derive="PartialEq")]
pub struct ResourceBindingSpec {
    /// Clusters represents target member clusters where the resource to be deployed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clusters: Option<Vec<ResourceBindingClusters>>,
    /// Resource represents the Kubernetes resource to be propagated.
    pub resource: ResourceBindingResource,
}

/// TargetCluster represents the identifier of a member cluster.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ResourceBindingClusters {
    /// Name of target cluster.
    pub name: String,
    /// Replicas in target cluster
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<i32>,
}

/// Resource represents the Kubernetes resource to be propagated.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ResourceBindingResource {
    /// APIVersion represents the API version of the referent.
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    /// Kind represents the Kind of the referent.
    pub kind: String,
    /// Name represents the name of the referent.
    pub name: String,
    /// Namespace represents the namespace for the referent.
    /// For non-namespace scoped resources(e.g. 'ClusterRole')，do not need specify Namespace,
    /// and for namespace scoped resources, Namespace is required.
    /// If Namespace is not specified, means the resource is non-namespace scoped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Replicas represents the replica number of the referencing resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<i32>,
    /// ReplicaResourceRequirements represents the resources required by each replica.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "resourcePerReplicas")]
    pub resource_per_replicas: Option<BTreeMap<String, IntOrString>>,
    /// ResourceVersion represents the internal version of the referenced object, that can be used by clients to
    /// determine when object has changed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "resourceVersion")]
    pub resource_version: Option<String>,
}

/// Status represents the most recently observed status of the ResourceBinding.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ResourceBindingStatus {
    /// AggregatedStatus represents status list of the resource running in each member cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "aggregatedStatus")]
    pub aggregated_status: Option<Vec<ResourceBindingStatusAggregatedStatus>>,
    /// Conditions contain the different condition statuses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
}

/// AggregatedStatusItem represents status of the resource running in a member cluster.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ResourceBindingStatusAggregatedStatus {
    /// Applied represents if the resource referencing by ResourceBinding or ClusterResourceBinding
    /// is successfully applied on the cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied: Option<bool>,
    /// AppliedMessage is a human readable message indicating details about the applied status.
    /// This is usually holds the error message in case of apply failed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "appliedMessage")]
    pub applied_message: Option<String>,
    /// ClusterName represents the member cluster name which the resource deployed on.
    #[serde(rename = "clusterName")]
    pub cluster_name: String,
    /// Status reflects running status of current manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<BTreeMap<String, serde_json::Value>>,
}

