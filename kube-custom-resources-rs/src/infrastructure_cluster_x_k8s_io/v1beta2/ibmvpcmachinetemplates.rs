// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kubernetes-sigs/cluster-api-provider-ibmcloud/infrastructure.cluster.x-k8s.io/v1beta2/ibmvpcmachinetemplates.yaml --derive=Default --derive=PartialEq
// kopium version: 0.16.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// IBMVPCMachineTemplateSpec defines the desired state of IBMVPCMachineTemplate.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "infrastructure.cluster.x-k8s.io", version = "v1beta2", kind = "IBMVPCMachineTemplate", plural = "ibmvpcmachinetemplates")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct IBMVPCMachineTemplateSpec {
    /// IBMVPCMachineTemplateResource describes the data needed to create am IBMVPCMachine from a template.
    pub template: IBMVPCMachineTemplateTemplate,
}

/// IBMVPCMachineTemplateResource describes the data needed to create am IBMVPCMachine from a template.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct IBMVPCMachineTemplateTemplate {
    /// Spec is the specification of the desired behavior of the machine.
    pub spec: IBMVPCMachineTemplateTemplateSpec,
}

/// Spec is the specification of the desired behavior of the machine.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct IBMVPCMachineTemplateTemplateSpec {
    /// BootVolume contains machines's boot volume configurations like size, iops etc..
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "bootVolume")]
    pub boot_volume: Option<IBMVPCMachineTemplateTemplateSpecBootVolume>,
    /// Image is the OS image which would be install on the instance. ID will take higher precedence over Name if both specified.
    pub image: IBMVPCMachineTemplateTemplateSpecImage,
    /// Name of the instance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// PrimaryNetworkInterface is required to specify subnet.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "primaryNetworkInterface")]
    pub primary_network_interface: Option<IBMVPCMachineTemplateTemplateSpecPrimaryNetworkInterface>,
    /// Profile indicates the flavor of instance. Example: bx2-8x32	means 8 vCPUs	32 GB RAM	16 Gbps TODO: add a reference link of profile
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// ProviderID is the unique identifier as specified by the cloud provider.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "providerID")]
    pub provider_id: Option<String>,
    /// SSHKeys is the SSH pub keys that will be used to access VM. ID will take higher precedence over Name if both specified.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sshKeys")]
    pub ssh_keys: Option<Vec<IBMVPCMachineTemplateTemplateSpecSshKeys>>,
    /// Zone is the place where the instance should be created. Example: us-south-3 TODO: Actually zone is transparent to user. The field user can access is location. Example: Dallas 2
    pub zone: String,
}

/// BootVolume contains machines's boot volume configurations like size, iops etc..
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct IBMVPCMachineTemplateTemplateSpecBootVolume {
    /// DeleteVolumeOnInstanceDelete If set to true, when deleting the instance the volume will also be deleted. Default is set as true
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "deleteVolumeOnInstanceDelete")]
    pub delete_volume_on_instance_delete: Option<bool>,
    /// EncryptionKey is the root key to use to wrap the data encryption key for the volume and this points to the CRN and possible values are as follows. The CRN of the [Key Protect Root Key](https://cloud.ibm.com/docs/key-protect?topic=key-protect-getting-started-tutorial) or [Hyper Protect Crypto Service Root Key](https://cloud.ibm.com/docs/hs-crypto?topic=hs-crypto-get-started) for this resource. If unspecified, the `encryption` type for the volume will be `provider_managed`.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "encryptionKeyCRN")]
    pub encryption_key_crn: Option<String>,
    /// Iops is the maximum I/O operations per second (IOPS) to use for the volume. Applicable only to volumes using a profile family of `custom`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iops: Option<i64>,
    /// Name is the unique user-defined name for this volume. Default will be autogenerated
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Profile is the volume profile for the bootdisk, refer https://cloud.ibm.com/docs/vpc?topic=vpc-block-storage-profiles for more information. Default to general-purpose
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<IBMVPCMachineTemplateTemplateSpecBootVolumeProfile>,
    /// SizeGiB is the size of the virtual server's boot disk in GiB. Default to the size of the image's `minimum_provisioned_size`.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sizeGiB")]
    pub size_gi_b: Option<i64>,
}

/// BootVolume contains machines's boot volume configurations like size, iops etc..
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum IBMVPCMachineTemplateTemplateSpecBootVolumeProfile {
    #[serde(rename = "general-purpose")]
    GeneralPurpose,
    #[serde(rename = "5iops-tier")]
    r#_5iopsTier,
    #[serde(rename = "10iops-tier")]
    r#_10iopsTier,
    #[serde(rename = "custom")]
    Custom,
}

/// Image is the OS image which would be install on the instance. ID will take higher precedence over Name if both specified.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct IBMVPCMachineTemplateTemplateSpecImage {
    /// ID of resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Name of resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// PrimaryNetworkInterface is required to specify subnet.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct IBMVPCMachineTemplateTemplateSpecPrimaryNetworkInterface {
    /// Subnet ID of the network interface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subnet: Option<String>,
}

/// IBMVPCResourceReference is a reference to a specific VPC resource by ID or Name Only one of ID or Name may be specified. Specifying more than one will result in a validation error.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct IBMVPCMachineTemplateTemplateSpecSshKeys {
    /// ID of resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Name of resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}
