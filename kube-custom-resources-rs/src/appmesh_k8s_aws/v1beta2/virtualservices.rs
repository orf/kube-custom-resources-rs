// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws/aws-app-mesh-controller-for-k8/appmesh.k8s.aws/v1beta2/virtualservices.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// VirtualServiceSpec defines the desired state of VirtualService refers to https://docs.aws.amazon.com/app-mesh/latest/APIReference/API_VirtualServiceSpec.html
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "appmesh.k8s.aws", version = "v1beta2", kind = "VirtualService", plural = "virtualservices")]
#[kube(namespaced)]
#[kube(status = "VirtualServiceStatus")]
#[kube(schema = "disabled")]
pub struct VirtualServiceSpec {
    /// AWSName is the AppMesh VirtualService object's name. If unspecified or empty, it defaults to be "${name}.${namespace}" of k8s VirtualService
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "awsName")]
    pub aws_name: Option<String>,
    /// A reference to k8s Mesh CR that this VirtualService belongs to. The admission controller populates it using Meshes's selector, and prevents users from setting this field. 
    ///  Populated by the system. Read-only.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "meshRef")]
    pub mesh_ref: Option<VirtualServiceMeshRef>,
    /// The provider for virtual services. You can specify a single virtual node or virtual router.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<VirtualServiceProvider>,
}

/// A reference to k8s Mesh CR that this VirtualService belongs to. The admission controller populates it using Meshes's selector, and prevents users from setting this field. 
///  Populated by the system. Read-only.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct VirtualServiceMeshRef {
    /// Name is the name of Mesh CR
    pub name: String,
    /// UID is the UID of Mesh CR
    pub uid: String,
}

/// The provider for virtual services. You can specify a single virtual node or virtual router.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct VirtualServiceProvider {
    /// The virtual node associated with a virtual service.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "virtualNode")]
    pub virtual_node: Option<VirtualServiceProviderVirtualNode>,
    /// The virtual router associated with a virtual service.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "virtualRouter")]
    pub virtual_router: Option<VirtualServiceProviderVirtualRouter>,
}

/// The virtual node associated with a virtual service.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct VirtualServiceProviderVirtualNode {
    /// Amazon Resource Name to AppMesh VirtualNode object that is acting as a service provider. Exactly one of 'virtualNodeRef' or 'virtualNodeARN' must be specified.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "virtualNodeARN")]
    pub virtual_node_arn: Option<String>,
    /// Reference to Kubernetes VirtualNode CR in cluster that is acting as a service provider. Exactly one of 'virtualNodeRef' or 'virtualNodeARN' must be specified.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "virtualNodeRef")]
    pub virtual_node_ref: Option<VirtualServiceProviderVirtualNodeVirtualNodeRef>,
}

/// Reference to Kubernetes VirtualNode CR in cluster that is acting as a service provider. Exactly one of 'virtualNodeRef' or 'virtualNodeARN' must be specified.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct VirtualServiceProviderVirtualNodeVirtualNodeRef {
    /// Name is the name of VirtualNode CR
    pub name: String,
    /// Namespace is the namespace of VirtualNode CR. If unspecified, defaults to the referencing object's namespace
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// The virtual router associated with a virtual service.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct VirtualServiceProviderVirtualRouter {
    /// Amazon Resource Name to AppMesh VirtualRouter object that is acting as a service provider. Exactly one of 'virtualRouterRef' or 'virtualRouterARN' must be specified.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "virtualRouterARN")]
    pub virtual_router_arn: Option<String>,
    /// Reference to Kubernetes VirtualRouter CR in cluster that is acting as a service provider. Exactly one of 'virtualRouterRef' or 'virtualRouterARN' must be specified.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "virtualRouterRef")]
    pub virtual_router_ref: Option<VirtualServiceProviderVirtualRouterVirtualRouterRef>,
}

/// Reference to Kubernetes VirtualRouter CR in cluster that is acting as a service provider. Exactly one of 'virtualRouterRef' or 'virtualRouterARN' must be specified.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct VirtualServiceProviderVirtualRouterVirtualRouterRef {
    /// Name is the name of VirtualRouter CR
    pub name: String,
    /// Namespace is the namespace of VirtualRouter CR. If unspecified, defaults to the referencing object's namespace
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// VirtualServiceStatus defines the observed state of VirtualService
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct VirtualServiceStatus {
    /// The current VirtualService status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// The generation observed by the VirtualService controller.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
    /// VirtualServiceARN is the AppMesh VirtualService object's Amazon Resource Name.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "virtualServiceARN")]
    pub virtual_service_arn: Option<String>,
}

