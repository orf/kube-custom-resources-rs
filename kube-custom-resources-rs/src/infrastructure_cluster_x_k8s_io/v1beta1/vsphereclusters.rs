// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kubernetes-sigs/cluster-api-provider-vsphere/infrastructure.cluster.x-k8s.io/v1beta1/vsphereclusters.yaml --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// VSphereClusterSpec defines the desired state of VSphereCluster.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "infrastructure.cluster.x-k8s.io", version = "v1beta1", kind = "VSphereCluster", plural = "vsphereclusters")]
#[kube(namespaced)]
#[kube(status = "VSphereClusterStatus")]
#[kube(schema = "disabled")]
pub struct VSphereClusterSpec {
    /// ClusterModules hosts information regarding the anti-affinity vSphere constructs for each of the objects responsible for creation of VM objects belonging to the cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clusterModules")]
    pub cluster_modules: Option<Vec<VSphereClusterClusterModules>>,
    /// ControlPlaneEndpoint represents the endpoint used to communicate with the control plane.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "controlPlaneEndpoint")]
    pub control_plane_endpoint: Option<VSphereClusterControlPlaneEndpoint>,
    /// FailureDomainSelector is the label selector to use for failure domain selection for the control plane nodes of the cluster. If not set (`nil`), selecting failure domains will be disabled. An empty value (`{}`) selects all existing failure domains. A valid selector will select all failure domains which match the selector.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "failureDomainSelector")]
    pub failure_domain_selector: Option<VSphereClusterFailureDomainSelector>,
    /// IdentityRef is a reference to either a Secret or VSphereClusterIdentity that contains the identity to use when reconciling the cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "identityRef")]
    pub identity_ref: Option<VSphereClusterIdentityRef>,
    /// Server is the address of the vSphere endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Thumbprint is the colon-separated SHA-1 checksum of the given vCenter server's host certificate
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
}

/// ClusterModule holds the anti affinity construct `ClusterModule` identifier in use by the VMs owned by the object referred by the TargetObjectName field.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct VSphereClusterClusterModules {
    /// ControlPlane indicates whether the referred object is responsible for control plane nodes. Currently, only the KubeadmControlPlane objects have this flag set to true. Only a single object in the slice can have this value set to true.
    #[serde(rename = "controlPlane")]
    pub control_plane: bool,
    /// ModuleUUID is the unique identifier of the `ClusterModule` used by the object.
    #[serde(rename = "moduleUUID")]
    pub module_uuid: String,
    /// TargetObjectName points to the object that uses the Cluster Module information to enforce anti-affinity amongst its descendant VM objects.
    #[serde(rename = "targetObjectName")]
    pub target_object_name: String,
}

/// ControlPlaneEndpoint represents the endpoint used to communicate with the control plane.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct VSphereClusterControlPlaneEndpoint {
    /// The hostname on which the API server is serving.
    pub host: String,
    /// The port on which the API server is serving.
    pub port: i32,
}

/// FailureDomainSelector is the label selector to use for failure domain selection for the control plane nodes of the cluster. If not set (`nil`), selecting failure domains will be disabled. An empty value (`{}`) selects all existing failure domains. A valid selector will select all failure domains which match the selector.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct VSphereClusterFailureDomainSelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<VSphereClusterFailureDomainSelectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct VSphereClusterFailureDomainSelectorMatchExpressions {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// IdentityRef is a reference to either a Secret or VSphereClusterIdentity that contains the identity to use when reconciling the cluster.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct VSphereClusterIdentityRef {
    /// Kind of the identity. Can either be VSphereClusterIdentity or Secret
    pub kind: VSphereClusterIdentityRefKind,
    /// Name of the identity.
    pub name: String,
}

/// IdentityRef is a reference to either a Secret or VSphereClusterIdentity that contains the identity to use when reconciling the cluster.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum VSphereClusterIdentityRefKind {
    VSphereClusterIdentity,
    Secret,
}

/// VSphereClusterStatus defines the observed state of VSphereClusterSpec.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct VSphereClusterStatus {
    /// Conditions defines current service state of the VSphereCluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// FailureDomains is a list of failure domain objects synced from the infrastructure provider.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "failureDomains")]
    pub failure_domains: Option<BTreeMap<String, VSphereClusterStatusFailureDomains>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<bool>,
    /// VCenterVersion defines the version of the vCenter server defined in the spec.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vCenterVersion")]
    pub v_center_version: Option<String>,
}

/// FailureDomains is a list of failure domain objects synced from the infrastructure provider.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct VSphereClusterStatusFailureDomains {
    /// Attributes is a free form map of attributes an infrastructure provider might use or require.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<BTreeMap<String, String>>,
    /// ControlPlane determines if this failure domain is suitable for use by control plane machines.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "controlPlane")]
    pub control_plane: Option<bool>,
}

