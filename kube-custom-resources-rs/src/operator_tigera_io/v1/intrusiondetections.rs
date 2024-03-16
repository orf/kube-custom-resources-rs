// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/tigera/operator/operator.tigera.io/v1/intrusiondetections.yaml --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// Specification of the desired state for Tigera intrusion detection.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "operator.tigera.io", version = "v1", kind = "IntrusionDetection", plural = "intrusiondetections")]
#[kube(status = "IntrusionDetectionStatus")]
#[kube(schema = "disabled")]
pub struct IntrusionDetectionSpec {
    /// AnomalyDetection is now deprecated, and configuring it has no effect.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "anomalyDetection")]
    pub anomaly_detection: Option<IntrusionDetectionAnomalyDetection>,
    /// ComponentResources can be used to customize the resource requirements for each component. Only DeepPacketInspection is supported for this spec.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "componentResources")]
    pub component_resources: Option<Vec<IntrusionDetectionComponentResources>>,
    /// IntrusionDetectionControllerDeployment configures the IntrusionDetection Controller Deployment.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "intrusionDetectionControllerDeployment")]
    pub intrusion_detection_controller_deployment: Option<IntrusionDetectionIntrusionDetectionControllerDeployment>,
}

/// AnomalyDetection is now deprecated, and configuring it has no effect.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IntrusionDetectionAnomalyDetection {
    /// StorageClassName is now deprecated, and configuring it has no effect.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "storageClassName")]
    pub storage_class_name: Option<String>,
}

/// The ComponentResource struct associates a ResourceRequirements with a component by name
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IntrusionDetectionComponentResources {
    /// ComponentName is an enum which identifies the component
    #[serde(rename = "componentName")]
    pub component_name: IntrusionDetectionComponentResourcesComponentName,
    /// ResourceRequirements allows customization of limits and requests for compute resources such as cpu and memory.
    #[serde(rename = "resourceRequirements")]
    pub resource_requirements: IntrusionDetectionComponentResourcesResourceRequirements,
}

/// The ComponentResource struct associates a ResourceRequirements with a component by name
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum IntrusionDetectionComponentResourcesComponentName {
    DeepPacketInspection,
}

/// ResourceRequirements allows customization of limits and requests for compute resources such as cpu and memory.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IntrusionDetectionComponentResourcesResourceRequirements {
    /// Claims lists the names of resources, defined in spec.resourceClaims, that are used by this container. 
    ///  This is an alpha field and requires enabling the DynamicResourceAllocation feature gate. 
    ///  This field is immutable. It can only be set for containers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<IntrusionDetectionComponentResourcesResourceRequirementsClaims>>,
    /// Limits describes the maximum amount of compute resources allowed. More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<BTreeMap<String, IntOrString>>,
    /// Requests describes the minimum amount of compute resources required. If Requests is omitted for a container, it defaults to Limits if that is explicitly specified, otherwise to an implementation-defined value. Requests cannot exceed Limits. More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<BTreeMap<String, IntOrString>>,
}

/// ResourceClaim references one entry in PodSpec.ResourceClaims.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IntrusionDetectionComponentResourcesResourceRequirementsClaims {
    /// Name must match the name of one entry in pod.spec.resourceClaims of the Pod where this field is used. It makes that resource available inside a container.
    pub name: String,
}

/// IntrusionDetectionControllerDeployment configures the IntrusionDetection Controller Deployment.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IntrusionDetectionIntrusionDetectionControllerDeployment {
    /// Spec is the specification of the IntrusionDetectionController Deployment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<IntrusionDetectionIntrusionDetectionControllerDeploymentSpec>,
}

/// Spec is the specification of the IntrusionDetectionController Deployment.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IntrusionDetectionIntrusionDetectionControllerDeploymentSpec {
    /// Template describes the IntrusionDetectionController Deployment pod that will be created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<IntrusionDetectionIntrusionDetectionControllerDeploymentSpecTemplate>,
}

/// Template describes the IntrusionDetectionController Deployment pod that will be created.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IntrusionDetectionIntrusionDetectionControllerDeploymentSpecTemplate {
    /// Spec is the IntrusionDetectionController Deployment's PodSpec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<IntrusionDetectionIntrusionDetectionControllerDeploymentSpecTemplateSpec>,
}

/// Spec is the IntrusionDetectionController Deployment's PodSpec.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IntrusionDetectionIntrusionDetectionControllerDeploymentSpecTemplateSpec {
    /// Containers is a list of IntrusionDetectionController containers. If specified, this overrides the specified IntrusionDetectionController Deployment containers. If omitted, the IntrusionDetectionController Deployment will use its default values for its containers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub containers: Option<Vec<IntrusionDetectionIntrusionDetectionControllerDeploymentSpecTemplateSpecContainers>>,
    /// InitContainers is a list of IntrusionDetectionController init containers. If specified, this overrides the specified IntrusionDetectionController Deployment init containers. If omitted, the IntrusionDetectionController Deployment will use its default values for its init containers.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "initContainers")]
    pub init_containers: Option<Vec<IntrusionDetectionIntrusionDetectionControllerDeploymentSpecTemplateSpecInitContainers>>,
}

/// IntrusionDetectionControllerDeploymentContainer is a IntrusionDetectionController Deployment container.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IntrusionDetectionIntrusionDetectionControllerDeploymentSpecTemplateSpecContainers {
    /// Name is an enum which identifies the IntrusionDetectionController Deployment container by name.
    pub name: IntrusionDetectionIntrusionDetectionControllerDeploymentSpecTemplateSpecContainersName,
    /// Resources allows customization of limits and requests for compute resources such as cpu and memory. If specified, this overrides the named IntrusionDetectionController Deployment container's resources. If omitted, the IntrusionDetection Deployment will use its default value for this container's resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<IntrusionDetectionIntrusionDetectionControllerDeploymentSpecTemplateSpecContainersResources>,
}

/// IntrusionDetectionControllerDeploymentContainer is a IntrusionDetectionController Deployment container.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum IntrusionDetectionIntrusionDetectionControllerDeploymentSpecTemplateSpecContainersName {
    #[serde(rename = "controller")]
    Controller,
    #[serde(rename = "webhooks-processor")]
    WebhooksProcessor,
}

/// Resources allows customization of limits and requests for compute resources such as cpu and memory. If specified, this overrides the named IntrusionDetectionController Deployment container's resources. If omitted, the IntrusionDetection Deployment will use its default value for this container's resources.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IntrusionDetectionIntrusionDetectionControllerDeploymentSpecTemplateSpecContainersResources {
    /// Claims lists the names of resources, defined in spec.resourceClaims, that are used by this container. 
    ///  This is an alpha field and requires enabling the DynamicResourceAllocation feature gate. 
    ///  This field is immutable. It can only be set for containers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<IntrusionDetectionIntrusionDetectionControllerDeploymentSpecTemplateSpecContainersResourcesClaims>>,
    /// Limits describes the maximum amount of compute resources allowed. More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<BTreeMap<String, IntOrString>>,
    /// Requests describes the minimum amount of compute resources required. If Requests is omitted for a container, it defaults to Limits if that is explicitly specified, otherwise to an implementation-defined value. Requests cannot exceed Limits. More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<BTreeMap<String, IntOrString>>,
}

/// ResourceClaim references one entry in PodSpec.ResourceClaims.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IntrusionDetectionIntrusionDetectionControllerDeploymentSpecTemplateSpecContainersResourcesClaims {
    /// Name must match the name of one entry in pod.spec.resourceClaims of the Pod where this field is used. It makes that resource available inside a container.
    pub name: String,
}

/// IntrusionDetectionControllerDeploymentInitContainer is a IntrusionDetectionController Deployment init container.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IntrusionDetectionIntrusionDetectionControllerDeploymentSpecTemplateSpecInitContainers {
    /// Name is an enum which identifies the IntrusionDetectionController Deployment init container by name.
    pub name: IntrusionDetectionIntrusionDetectionControllerDeploymentSpecTemplateSpecInitContainersName,
    /// Resources allows customization of limits and requests for compute resources such as cpu and memory. If specified, this overrides the named IntrusionDetectionController Deployment init container's resources. If omitted, the IntrusionDetectionController Deployment will use its default value for this init container's resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<IntrusionDetectionIntrusionDetectionControllerDeploymentSpecTemplateSpecInitContainersResources>,
}

/// IntrusionDetectionControllerDeploymentInitContainer is a IntrusionDetectionController Deployment init container.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum IntrusionDetectionIntrusionDetectionControllerDeploymentSpecTemplateSpecInitContainersName {
    #[serde(rename = "intrusion-detection-tls-key-cert-provisioner")]
    IntrusionDetectionTlsKeyCertProvisioner,
}

/// Resources allows customization of limits and requests for compute resources such as cpu and memory. If specified, this overrides the named IntrusionDetectionController Deployment init container's resources. If omitted, the IntrusionDetectionController Deployment will use its default value for this init container's resources.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IntrusionDetectionIntrusionDetectionControllerDeploymentSpecTemplateSpecInitContainersResources {
    /// Claims lists the names of resources, defined in spec.resourceClaims, that are used by this container. 
    ///  This is an alpha field and requires enabling the DynamicResourceAllocation feature gate. 
    ///  This field is immutable. It can only be set for containers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<IntrusionDetectionIntrusionDetectionControllerDeploymentSpecTemplateSpecInitContainersResourcesClaims>>,
    /// Limits describes the maximum amount of compute resources allowed. More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<BTreeMap<String, IntOrString>>,
    /// Requests describes the minimum amount of compute resources required. If Requests is omitted for a container, it defaults to Limits if that is explicitly specified, otherwise to an implementation-defined value. Requests cannot exceed Limits. More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<BTreeMap<String, IntOrString>>,
}

/// ResourceClaim references one entry in PodSpec.ResourceClaims.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IntrusionDetectionIntrusionDetectionControllerDeploymentSpecTemplateSpecInitContainersResourcesClaims {
    /// Name must match the name of one entry in pod.spec.resourceClaims of the Pod where this field is used. It makes that resource available inside a container.
    pub name: String,
}

/// Most recently observed state for Tigera intrusion detection.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IntrusionDetectionStatus {
    /// Conditions represents the latest observed set of conditions for the component. A component may be one or more of Ready, Progressing, Degraded or other customer types.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// State provides user-readable status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

