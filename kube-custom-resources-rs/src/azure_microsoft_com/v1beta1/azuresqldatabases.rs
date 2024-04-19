// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/Azure/azure-service-operator/azure.microsoft.com/v1beta1/azuresqldatabases.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

/// AzureSqlDatabaseSpec defines the desired state of AzureSqlDatabase
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "azure.microsoft.com", version = "v1beta1", kind = "AzureSqlDatabase", plural = "azuresqldatabases")]
#[kube(namespaced)]
#[kube(status = "AzureSqlDatabaseStatus")]
#[kube(schema = "disabled")]
pub struct AzureSqlDatabaseSpec {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dbName")]
    pub db_name: Option<String>,
    pub edition: i64,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "elasticPoolId")]
    pub elastic_pool_id: Option<String>,
    pub location: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxSize")]
    pub max_size: Option<IntOrString>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "monthlyRetention")]
    pub monthly_retention: Option<String>,
    #[serde(rename = "resourceGroup")]
    pub resource_group: String,
    pub server: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "shortTermRetentionPolicy")]
    pub short_term_retention_policy: Option<AzureSqlDatabaseShortTermRetentionPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sku: Option<AzureSqlDatabaseSku>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "subscriptionId")]
    pub subscription_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "weekOfYear")]
    pub week_of_year: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "weeklyRetention")]
    pub weekly_retention: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "yearlyRetention")]
    pub yearly_retention: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AzureSqlDatabaseShortTermRetentionPolicy {
    /// RetentionDays is the backup retention period in days. This is how many days Point-in-Time Restore will be supported.
    #[serde(rename = "retentionDays")]
    pub retention_days: i32,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AzureSqlDatabaseSku {
    /// Capacity - Capacity of the particular SKU.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity: Option<i32>,
    /// Family - If the service has different generations of hardware, for the same SKU, then that can be captured here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// Name - The name of the SKU, typically, a letter + Number code, e.g. P3.
    pub name: String,
    /// Size - Size of the particular SKU
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    /// optional Tier - The tier or edition of the particular SKU, e.g. Basic, Premium.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
}

/// ASOStatus (AzureServiceOperatorsStatus) defines the observed state of resource actions
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AzureSqlDatabaseStatus {
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
    pub polling_url_kind: Option<AzureSqlDatabaseStatusPollingUrlKind>,
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
pub enum AzureSqlDatabaseStatusPollingUrlKind {
    CreateOrUpdate,
    Delete,
}

