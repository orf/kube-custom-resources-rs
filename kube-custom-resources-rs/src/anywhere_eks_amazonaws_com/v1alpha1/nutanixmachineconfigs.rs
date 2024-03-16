// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws/eks-anywhere/anywhere.eks.amazonaws.com/v1alpha1/nutanixmachineconfigs.yaml --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// NutanixMachineConfigSpec defines the desired state of NutanixMachineConfig.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "anywhere.eks.amazonaws.com", version = "v1alpha1", kind = "NutanixMachineConfig", plural = "nutanixmachineconfigs")]
#[kube(namespaced)]
#[kube(status = "NutanixMachineConfigStatus")]
#[kube(schema = "disabled")]
pub struct NutanixMachineConfigSpec {
    /// additionalCategories is a list of optional categories to be added to the VM. Categories must be created in Prism Central before they can be used.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "additionalCategories")]
    pub additional_categories: Option<Vec<NutanixMachineConfigAdditionalCategories>>,
    /// cluster is to identify the cluster (the Prism Element under management of the Prism Central), in which the Machine's VM will be created. The cluster identifier (uuid or name) can be obtained from the Prism Central console or using the prism_central API.
    pub cluster: NutanixMachineConfigCluster,
    /// image is to identify the OS image uploaded to the Prism Central (PC) The image identifier (uuid or name) can be obtained from the Prism Central console or using the Prism Central API. It must include the Kubernetes version(s). For example, a template used for Kubernetes 1.27 could be ubuntu-2204-1.27.
    pub image: NutanixMachineConfigImage,
    /// memorySize is the memory size (in Quantity format) of the VM The minimum memorySize is 2Gi bytes
    #[serde(rename = "memorySize")]
    pub memory_size: IntOrString,
    #[serde(rename = "osFamily")]
    pub os_family: String,
    /// Project is an optional property that specifies the Prism Central project so that machine resources can be linked to it. The project identifier (uuid or name) can be obtained from the Prism Central console or using the Prism Central API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<NutanixMachineConfigProject>,
    /// subnet is to identify the cluster's network subnet to use for the Machine's VM The cluster identifier (uuid or name) can be obtained from the Prism Central console or using the Prism Central API.
    pub subnet: NutanixMachineConfigSubnet,
    /// systemDiskSize is size (in Quantity format) of the system disk of the VM The minimum systemDiskSize is 20Gi bytes
    #[serde(rename = "systemDiskSize")]
    pub system_disk_size: IntOrString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<NutanixMachineConfigUsers>>,
    /// vcpuSockets is the number of vCPU sockets of the VM
    #[serde(rename = "vcpuSockets")]
    pub vcpu_sockets: i32,
    /// vcpusPerSocket is the number of vCPUs per socket of the VM
    #[serde(rename = "vcpusPerSocket")]
    pub vcpus_per_socket: i32,
}

/// NutanixCategoryIdentifier holds the identity of a Nutanix Prism Central category.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NutanixMachineConfigAdditionalCategories {
    /// key is the Key of the category in the Prism Central.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// value is the category value linked to the key in the Prism Central.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// cluster is to identify the cluster (the Prism Element under management of the Prism Central), in which the Machine's VM will be created. The cluster identifier (uuid or name) can be obtained from the Prism Central console or using the prism_central API.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NutanixMachineConfigCluster {
    /// name is the resource name in the PC
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Type is the identifier type to use for this resource.
    #[serde(rename = "type")]
    pub r#type: NutanixMachineConfigClusterType,
    /// uuid is the UUID of the resource in the PC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
}

/// cluster is to identify the cluster (the Prism Element under management of the Prism Central), in which the Machine's VM will be created. The cluster identifier (uuid or name) can be obtained from the Prism Central console or using the prism_central API.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum NutanixMachineConfigClusterType {
    #[serde(rename = "uuid")]
    Uuid,
    #[serde(rename = "name")]
    Name,
}

/// image is to identify the OS image uploaded to the Prism Central (PC) The image identifier (uuid or name) can be obtained from the Prism Central console or using the Prism Central API. It must include the Kubernetes version(s). For example, a template used for Kubernetes 1.27 could be ubuntu-2204-1.27.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NutanixMachineConfigImage {
    /// name is the resource name in the PC
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Type is the identifier type to use for this resource.
    #[serde(rename = "type")]
    pub r#type: NutanixMachineConfigImageType,
    /// uuid is the UUID of the resource in the PC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
}

/// image is to identify the OS image uploaded to the Prism Central (PC) The image identifier (uuid or name) can be obtained from the Prism Central console or using the Prism Central API. It must include the Kubernetes version(s). For example, a template used for Kubernetes 1.27 could be ubuntu-2204-1.27.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum NutanixMachineConfigImageType {
    #[serde(rename = "uuid")]
    Uuid,
    #[serde(rename = "name")]
    Name,
}

/// Project is an optional property that specifies the Prism Central project so that machine resources can be linked to it. The project identifier (uuid or name) can be obtained from the Prism Central console or using the Prism Central API.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NutanixMachineConfigProject {
    /// name is the resource name in the PC
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Type is the identifier type to use for this resource.
    #[serde(rename = "type")]
    pub r#type: NutanixMachineConfigProjectType,
    /// uuid is the UUID of the resource in the PC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
}

/// Project is an optional property that specifies the Prism Central project so that machine resources can be linked to it. The project identifier (uuid or name) can be obtained from the Prism Central console or using the Prism Central API.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum NutanixMachineConfigProjectType {
    #[serde(rename = "uuid")]
    Uuid,
    #[serde(rename = "name")]
    Name,
}

/// subnet is to identify the cluster's network subnet to use for the Machine's VM The cluster identifier (uuid or name) can be obtained from the Prism Central console or using the Prism Central API.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NutanixMachineConfigSubnet {
    /// name is the resource name in the PC
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Type is the identifier type to use for this resource.
    #[serde(rename = "type")]
    pub r#type: NutanixMachineConfigSubnetType,
    /// uuid is the UUID of the resource in the PC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
}

/// subnet is to identify the cluster's network subnet to use for the Machine's VM The cluster identifier (uuid or name) can be obtained from the Prism Central console or using the Prism Central API.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum NutanixMachineConfigSubnetType {
    #[serde(rename = "uuid")]
    Uuid,
    #[serde(rename = "name")]
    Name,
}

/// UserConfiguration defines the configuration of the user to be added to the VM.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NutanixMachineConfigUsers {
    pub name: String,
    #[serde(rename = "sshAuthorizedKeys")]
    pub ssh_authorized_keys: Vec<String>,
}

/// NutanixMachineConfigStatus defines the observed state of NutanixMachineConfig.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NutanixMachineConfigStatus {
    /// Addresses contains the Nutanix VM associated addresses. Address type is one of Hostname, ExternalIP, InternalIP, ExternalDNS, InternalDNS
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addresses: Option<Vec<NutanixMachineConfigStatusAddresses>>,
    /// Conditions defines current service state of the NutanixMachine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// NodeRef is a reference to the corresponding workload cluster Node if it exists.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nodeRef")]
    pub node_ref: Option<NutanixMachineConfigStatusNodeRef>,
    /// Ready is true when the provider resource is ready.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<bool>,
    /// The Nutanix VM's UUID
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vmUUID")]
    pub vm_uuid: Option<String>,
}

/// MachineAddress contains information for the node's address.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NutanixMachineConfigStatusAddresses {
    /// The machine address.
    pub address: String,
    /// Machine address type, one of Hostname, ExternalIP, InternalIP, ExternalDNS or InternalDNS.
    #[serde(rename = "type")]
    pub r#type: String,
}

/// NodeRef is a reference to the corresponding workload cluster Node if it exists.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NutanixMachineConfigStatusNodeRef {
    /// API version of the referent.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiVersion")]
    pub api_version: Option<String>,
    /// If referring to a piece of an object instead of an entire object, this string should contain a valid JSON/Go field access statement, such as desiredState.manifest.containers[2]. For example, if the object reference is to a container within a pod, this would take on a value like: "spec.containers{name}" (where "name" refers to the name of the container that triggered the event) or if no container name is specified "spec.containers[2]" (container with index 2 in this pod). This syntax is chosen only to have some well-defined way of referencing a part of an object. TODO: this design is not final and this field is subject to change in the future.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "fieldPath")]
    pub field_path: Option<String>,
    /// Kind of the referent. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Namespace of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Specific resourceVersion to which this reference is made, if any. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#concurrency-control-and-consistency
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "resourceVersion")]
    pub resource_version: Option<String>,
    /// UID of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#uids
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
}

