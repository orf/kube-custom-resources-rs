// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/Azure/azure-service-operator/azure.microsoft.com/v1alpha1/keyvaults.yaml --derive=Default --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
}
use self::prelude::*;

/// KeyVaultSpec defines the desired state of KeyVault
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "azure.microsoft.com", version = "v1alpha1", kind = "KeyVault", plural = "keyvaults")]
#[kube(namespaced)]
#[kube(status = "KeyVaultStatus")]
#[kube(schema = "disabled")]
#[kube(derive="Default")]
#[kube(derive="PartialEq")]
pub struct KeyVaultSpec {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "accessPolicies")]
    pub access_policies: Option<Vec<KeyVaultAccessPolicies>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "enableSoftDelete")]
    pub enable_soft_delete: Option<bool>,
    pub location: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "networkPolicies")]
    pub network_policies: Option<KeyVaultNetworkPolicies>,
    #[serde(rename = "resourceGroup")]
    pub resource_group: String,
    /// KeyVaultSku the SKU of the Key Vault
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sku: Option<KeyVaultSku>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct KeyVaultAccessPolicies {
    /// ApplicationID -  Application ID of the client making request on behalf of a principal
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "applicationID")]
    pub application_id: Option<String>,
    /// ClientID - The client ID of a user, service principal or security group in the Azure Active Directory tenant for the vault. The client ID must be unique for the list of access policies. TODO: Remove this in a future API version, see: https://github.com/Azure/azure-service-operator/issues/1351
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clientID")]
    pub client_id: Option<String>,
    /// ObjectID is the AAD object id of the entity to provide access to.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "objectID")]
    pub object_id: Option<String>,
    /// Permissions - Permissions the identity has for keys, secrets, and certificates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<KeyVaultAccessPoliciesPermissions>,
    /// TenantID - The Azure Active Directory tenant ID that should be used for authenticating requests to the key vault.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "tenantID")]
    pub tenant_id: Option<String>,
}

/// Permissions - Permissions the identity has for keys, secrets, and certificates.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct KeyVaultAccessPoliciesPermissions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct KeyVaultNetworkPolicies {
    /// Bypass - Tells what traffic can bypass network rules. This can be 'AzureServices' or 'None'.  If not specified the default is 'AzureServices'. Possible values include: 'AzureServices', 'None'
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bypass: Option<String>,
    /// DefaultAction - The default action when no rule from ipRules and from virtualNetworkRules match. This is only used after the bypass property has been evaluated. Possible values include: 'Allow', 'Deny'
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "defaultAction")]
    pub default_action: Option<String>,
    /// IPRules - The list of IP address rules.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ipRules")]
    pub ip_rules: Option<Vec<String>>,
    /// VirtualNetworkRules - The list of virtual network rules.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "virtualNetworkRules")]
    pub virtual_network_rules: Option<Vec<String>>,
}

/// KeyVaultSku the SKU of the Key Vault
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct KeyVaultSku {
    /// Name - The SKU name. Required for account creation; optional for update. Possible values include: 'Premium', `Standard`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// ASOStatus (AzureServiceOperatorsStatus) defines the observed state of resource actions
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct KeyVaultStatus {
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
    pub polling_url_kind: Option<KeyVaultStatusPollingUrlKind>,
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
pub enum KeyVaultStatusPollingUrlKind {
    CreateOrUpdate,
    Delete,
}

