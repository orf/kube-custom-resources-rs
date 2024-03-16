// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/Azure/azure-service-operator/azure.microsoft.com/v1alpha1/rediscachefirewallrules.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// RedisCacheFirewallRuleSpec defines the desired state of RedisCacheFirewallRule
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "azure.microsoft.com", version = "v1alpha1", kind = "RedisCacheFirewallRule", plural = "rediscachefirewallrules")]
#[kube(namespaced)]
#[kube(status = "RedisCacheFirewallRuleStatus")]
#[kube(schema = "disabled")]
pub struct RedisCacheFirewallRuleSpec {
    /// RedisCacheFirewallRuleProperties the parameters of the RedisCacheFirewallRule
    pub properties: RedisCacheFirewallRuleProperties,
    #[serde(rename = "redisCache")]
    pub redis_cache: String,
    #[serde(rename = "resourceGroup")]
    pub resource_group: String,
}

/// RedisCacheFirewallRuleProperties the parameters of the RedisCacheFirewallRule
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RedisCacheFirewallRuleProperties {
    #[serde(rename = "endIP")]
    pub end_ip: String,
    #[serde(rename = "startIP")]
    pub start_ip: String,
}

/// ASOStatus (AzureServiceOperatorsStatus) defines the observed state of resource actions
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RedisCacheFirewallRuleStatus {
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
    pub polling_url_kind: Option<RedisCacheFirewallRuleStatusPollingUrlKind>,
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
pub enum RedisCacheFirewallRuleStatusPollingUrlKind {
    CreateOrUpdate,
    Delete,
}

