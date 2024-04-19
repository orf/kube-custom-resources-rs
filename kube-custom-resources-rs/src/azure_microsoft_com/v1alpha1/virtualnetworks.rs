// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/Azure/azure-service-operator/azure.microsoft.com/v1alpha1/virtualnetworks.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// VirtualNetworkSpec defines the desired state of VirtualNetwork
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "azure.microsoft.com", version = "v1alpha1", kind = "VirtualNetwork", plural = "virtualnetworks")]
#[kube(namespaced)]
#[kube(status = "VirtualNetworkStatus")]
#[kube(schema = "disabled")]
pub struct VirtualNetworkSpec {
    #[serde(rename = "addressSpace")]
    pub address_space: String,
    /// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster Important: Run "make" to regenerate code after modifying this file
    pub location: String,
    #[serde(rename = "resourceGroup")]
    pub resource_group: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subnets: Option<Vec<VirtualNetworkSubnets>>,
}

/// VNetSubnets defines subnets for this vnet
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct VirtualNetworkSubnets {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "serviceEndpoints")]
    pub service_endpoints: Option<Vec<String>>,
    #[serde(rename = "subnetAddressPrefix")]
    pub subnet_address_prefix: String,
    /// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster Important: Run "make" to regenerate code after modifying this file
    #[serde(rename = "subnetName")]
    pub subnet_name: String,
}

/// ASOStatus (AzureServiceOperatorsStatus) defines the observed state of resource actions
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct VirtualNetworkStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "containsUpdate")]
    pub contains_update: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "failedProvisioning")]
    pub failed_provisioning: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "flattenedSecrets")]
    pub flattened_secrets: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "pollingUrl")]
    pub polling_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "pollingUrlKind")]
    pub polling_url_kind: Option<VirtualNetworkStatusPollingUrlKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provisioned: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provisioning: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "resourceId")]
    pub resource_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "specHash")]
    pub spec_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// ASOStatus (AzureServiceOperatorsStatus) defines the observed state of resource actions
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum VirtualNetworkStatusPollingUrlKind {
    CreateOrUpdate,
    Delete,
}

