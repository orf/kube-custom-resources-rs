// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws/aws-app-mesh-controller-for-k8/appmesh.k8s.aws/v1beta2/backendgroups.yaml --derive=Default --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
}
use self::prelude::*;

/// BackendGroupSpec defines the desired state of BackendGroup
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "appmesh.k8s.aws", version = "v1beta2", kind = "BackendGroup", plural = "backendgroups")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
#[kube(derive="Default")]
#[kube(derive="PartialEq")]
pub struct BackendGroupSpec {
    /// A reference to k8s Mesh CR that this BackendGroup belongs to. The admission controller populates it using Meshes's selector, and prevents users from setting this field. 
    ///  Populated by the system. Read-only.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "meshRef")]
    pub mesh_ref: Option<BackendGroupMeshRef>,
    /// VirtualServices defines the set of virtual services in this BackendGroup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtualservices: Option<Vec<BackendGroupVirtualservices>>,
}

/// A reference to k8s Mesh CR that this BackendGroup belongs to. The admission controller populates it using Meshes's selector, and prevents users from setting this field. 
///  Populated by the system. Read-only.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackendGroupMeshRef {
    /// Name is the name of Mesh CR
    pub name: String,
    /// UID is the UID of Mesh CR
    pub uid: String,
}

/// VirtualServiceReference holds a reference to VirtualService.appmesh.k8s.aws
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackendGroupVirtualservices {
    /// Name is the name of VirtualService CR
    pub name: String,
    /// Namespace is the namespace of VirtualService CR. If unspecified, defaults to the referencing object's namespace
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// BackendGroupStatus defines the observed state of BackendGroup
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackendGroupStatus {
}

