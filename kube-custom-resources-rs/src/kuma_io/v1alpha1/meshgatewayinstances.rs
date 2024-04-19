// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kumahq/kuma/kuma.io/v1alpha1/meshgatewayinstances.yaml --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// MeshGatewayInstanceSpec specifies the options available for a GatewayDataplane.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "kuma.io", version = "v1alpha1", kind = "MeshGatewayInstance", plural = "meshgatewayinstances")]
#[kube(namespaced)]
#[kube(status = "MeshGatewayInstanceStatus")]
#[kube(schema = "disabled")]
pub struct MeshGatewayInstanceSpec {
    /// PodTemplate configures the Pod owned by this config.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "podTemplate")]
    pub pod_template: Option<MeshGatewayInstancePodTemplate>,
    /// Replicas is the number of dataplane proxy replicas to create. For
    /// now this is a fixed number, but in the future it could be
    /// automatically scaled based on metrics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<i32>,
    /// Resources specifies the compute resources for the proxy container.
    /// The default can be set in the control plane config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<MeshGatewayInstanceResources>,
    /// ServiceTemplate configures the Service owned by this config.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "serviceTemplate")]
    pub service_template: Option<MeshGatewayInstanceServiceTemplate>,
    /// ServiceType specifies the type of managed Service that will be
    /// created to expose the dataplane proxies to traffic from outside
    /// the cluster. The ports to expose will be taken from the matching Gateway
    /// resource. If there is no matching Gateway, the managed Service will
    /// be deleted.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "serviceType")]
    pub service_type: Option<MeshGatewayInstanceServiceType>,
    /// Tags specifies the Kuma tags that are propagated to the managed
    /// dataplane proxies. These tags should include exactly one
    /// `kuma.io/service` tag, and should match exactly one Gateway
    /// resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,
}

/// PodTemplate configures the Pod owned by this config.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshGatewayInstancePodTemplate {
    /// Metadata holds metadata configuration for a Service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<MeshGatewayInstancePodTemplateMetadata>,
    /// Spec holds some customizable fields of a Pod.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<MeshGatewayInstancePodTemplateSpec>,
}

/// Metadata holds metadata configuration for a Service.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshGatewayInstancePodTemplateMetadata {
    /// Annotations holds annotations to be set on an object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
    /// Labels holds labels to be set on an objects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
}

/// Spec holds some customizable fields of a Pod.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshGatewayInstancePodTemplateSpec {
    /// Container corresponds to PodSpec.Container
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<MeshGatewayInstancePodTemplateSpecContainer>,
    /// PodSecurityContext corresponds to PodSpec.SecurityContext
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "securityContext")]
    pub security_context: Option<MeshGatewayInstancePodTemplateSpecSecurityContext>,
    /// ServiceAccountName corresponds to PodSpec.ServiceAccountName.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "serviceAccountName")]
    pub service_account_name: Option<String>,
}

/// Container corresponds to PodSpec.Container
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshGatewayInstancePodTemplateSpecContainer {
    /// ContainerSecurityContext corresponds to PodSpec.Container.SecurityContext
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "securityContext")]
    pub security_context: Option<MeshGatewayInstancePodTemplateSpecContainerSecurityContext>,
}

/// ContainerSecurityContext corresponds to PodSpec.Container.SecurityContext
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshGatewayInstancePodTemplateSpecContainerSecurityContext {
    /// ReadOnlyRootFilesystem corresponds to PodSpec.Container.SecurityContext.ReadOnlyRootFilesystem
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "readOnlyRootFilesystem")]
    pub read_only_root_filesystem: Option<bool>,
}

/// PodSecurityContext corresponds to PodSpec.SecurityContext
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshGatewayInstancePodTemplateSpecSecurityContext {
    /// FSGroup corresponds to PodSpec.SecurityContext.FSGroup
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "fsGroup")]
    pub fs_group: Option<i64>,
}

/// Resources specifies the compute resources for the proxy container.
/// The default can be set in the control plane config.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshGatewayInstanceResources {
    /// Claims lists the names of resources, defined in spec.resourceClaims,
    /// that are used by this container.
    /// 
    /// 
    /// This is an alpha field and requires enabling the
    /// DynamicResourceAllocation feature gate.
    /// 
    /// 
    /// This field is immutable. It can only be set for containers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<MeshGatewayInstanceResourcesClaims>>,
    /// Limits describes the maximum amount of compute resources allowed.
    /// More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<BTreeMap<String, IntOrString>>,
    /// Requests describes the minimum amount of compute resources required.
    /// If Requests is omitted for a container, it defaults to Limits if that is explicitly specified,
    /// otherwise to an implementation-defined value. Requests cannot exceed Limits.
    /// More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<BTreeMap<String, IntOrString>>,
}

/// ResourceClaim references one entry in PodSpec.ResourceClaims.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshGatewayInstanceResourcesClaims {
    /// Name must match the name of one entry in pod.spec.resourceClaims of
    /// the Pod where this field is used. It makes that resource available
    /// inside a container.
    pub name: String,
}

/// ServiceTemplate configures the Service owned by this config.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshGatewayInstanceServiceTemplate {
    /// Metadata holds metadata configuration for a Service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<MeshGatewayInstanceServiceTemplateMetadata>,
    /// Spec holds some customizable fields of a Service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<MeshGatewayInstanceServiceTemplateSpec>,
}

/// Metadata holds metadata configuration for a Service.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshGatewayInstanceServiceTemplateMetadata {
    /// Annotations holds annotations to be set on an object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
    /// Labels holds labels to be set on an objects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
}

/// Spec holds some customizable fields of a Service.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshGatewayInstanceServiceTemplateSpec {
    /// LoadBalancerIP corresponds to ServiceSpec.LoadBalancerIP.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "loadBalancerIP")]
    pub load_balancer_ip: Option<String>,
}

/// MeshGatewayInstanceSpec specifies the options available for a GatewayDataplane.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum MeshGatewayInstanceServiceType {
    LoadBalancer,
    #[serde(rename = "ClusterIP")]
    ClusterIp,
    NodePort,
}

/// MeshGatewayInstanceStatus holds information about the status of the gateway
/// instance.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshGatewayInstanceStatus {
    /// Conditions is an array of gateway instance conditions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// LoadBalancer contains the current status of the load-balancer,
    /// if one is present.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "loadBalancer")]
    pub load_balancer: Option<MeshGatewayInstanceStatusLoadBalancer>,
}

/// LoadBalancer contains the current status of the load-balancer,
/// if one is present.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshGatewayInstanceStatusLoadBalancer {
    /// Ingress is a list containing ingress points for the load-balancer.
    /// Traffic intended for the service should be sent to these ingress points.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress: Option<Vec<MeshGatewayInstanceStatusLoadBalancerIngress>>,
}

/// LoadBalancerIngress represents the status of a load-balancer ingress point:
/// traffic intended for the service should be sent to an ingress point.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshGatewayInstanceStatusLoadBalancerIngress {
    /// Hostname is set for load-balancer ingress points that are DNS based
    /// (typically AWS load-balancers)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// IP is set for load-balancer ingress points that are IP based
    /// (typically GCE or OpenStack load-balancers)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// IPMode specifies how the load-balancer IP behaves, and may only be specified when the ip field is specified.
    /// Setting this to "VIP" indicates that traffic is delivered to the node with
    /// the destination set to the load-balancer's IP and port.
    /// Setting this to "Proxy" indicates that traffic is delivered to the node or pod with
    /// the destination set to the node's IP and node port or the pod's IP and port.
    /// Service implementations may use this information to adjust traffic routing.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ipMode")]
    pub ip_mode: Option<String>,
    /// Ports is a list of records of service ports
    /// If used, every port defined in the service should have an entry in it
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<MeshGatewayInstanceStatusLoadBalancerIngressPorts>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshGatewayInstanceStatusLoadBalancerIngressPorts {
    /// Error is to record the problem with the service port
    /// The format of the error shall comply with the following rules:
    /// - built-in error values shall be specified in this file and those shall use
    ///   CamelCase names
    /// - cloud provider specific error values must have names that comply with the
    ///   format foo.example.com/CamelCase.
    /// ---
    /// The regex it matches is (dns1123SubdomainFmt/)?(qualifiedNameFmt)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Port is the port number of the service port of which status is recorded here
    pub port: i32,
    /// Protocol is the protocol of the service port of which status is recorded here
    /// The supported values are: "TCP", "UDP", "SCTP"
    pub protocol: String,
}

