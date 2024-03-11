// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/Azure/azure-service-operator/azure.microsoft.com/v1alpha1/eventhubs.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// EventhubSpec defines the desired state of Eventhub
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "azure.microsoft.com", version = "v1alpha1", kind = "Eventhub", plural = "eventhubs")]
#[kube(namespaced)]
#[kube(status = "EventhubStatus")]
#[kube(schema = "disabled")]
pub struct EventhubSpec {
    /// EventhubAuthorizationRule defines the name and rights of the access policy
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "authorizationRule")]
    pub authorization_rule: Option<EventhubAuthorizationRule>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "keyVaultToStoreSecrets")]
    pub key_vault_to_store_secrets: Option<String>,
    /// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster Important: Run "make" to regenerate code after modifying this file
    pub location: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// EventhubProperties defines the namespace properties
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<EventhubProperties>,
    #[serde(rename = "resourceGroup")]
    pub resource_group: String,
    /// SecretName - Used to specify the name of the secret. Defaults to Event Hub name if omitted.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretName")]
    pub secret_name: Option<String>,
}

/// EventhubAuthorizationRule defines the name and rights of the access policy
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct EventhubAuthorizationRule {
    /// Name - Name of AuthorizationRule for eventhub
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Rights - Rights set on the AuthorizationRule
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rights: Option<Vec<String>>,
}

/// EventhubProperties defines the namespace properties
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct EventhubProperties {
    /// CaptureDescription - Details specifying EventHub capture to persistent storage
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "captureDescription")]
    pub capture_description: Option<EventhubPropertiesCaptureDescription>,
    /// MessageRetentionInDays - Number of days to retain the events for this Event Hub, value should be 1 to 7 days
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "messageRetentionInDays")]
    pub message_retention_in_days: Option<i32>,
    /// PartitionCount - Number of partitions created for the Event Hub, allowed values are from 2 to 32 partitions.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "partitionCount")]
    pub partition_count: Option<i32>,
}

/// CaptureDescription - Details specifying EventHub capture to persistent storage
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct EventhubPropertiesCaptureDescription {
    /// Destination - Resource id of the storage account to be used to create the blobs
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<EventhubPropertiesCaptureDescriptionDestination>,
    /// Enabled - indicates whether capture is enabled
    pub enabled: bool,
    /// IntervalInSeconds - The time window allows you to set the frequency with which the capture to Azure Blobs will happen
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "intervalInSeconds")]
    pub interval_in_seconds: Option<i32>,
    /// SizeLimitInBytes - The size window defines the amount of data built up in your Event Hub before an capture operation
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sizeLimitInBytes")]
    pub size_limit_in_bytes: Option<i32>,
}

/// Destination - Resource id of the storage account to be used to create the blobs
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct EventhubPropertiesCaptureDescriptionDestination {
    /// ArchiveNameFormat - Blob naming convention for archive, e.g. {Namespace}/{EventHub}/{PartitionId}/{Year}/{Month}/{Day}/{Hour}/{Minute}/{Second}. Here all the parameters (Namespace,EventHub .. etc) are mandatory irrespective of order
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "archiveNameFormat")]
    pub archive_name_format: Option<String>,
    /// BlobContainer - Blob container Name
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "blobContainer")]
    pub blob_container: Option<String>,
    /// Name - Name for capture destination
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<EventhubPropertiesCaptureDescriptionDestinationName>,
    /// StorageAccount - Details of the storage account
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "storageAccount")]
    pub storage_account: Option<EventhubPropertiesCaptureDescriptionDestinationStorageAccount>,
}

/// Destination - Resource id of the storage account to be used to create the blobs
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum EventhubPropertiesCaptureDescriptionDestinationName {
    #[serde(rename = "EventHubArchive.AzureBlockBlob")]
    EventHubArchiveAzureBlockBlob,
    #[serde(rename = "EventHubArchive.AzureDataLake")]
    EventHubArchiveAzureDataLake,
}

/// StorageAccount - Details of the storage account
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct EventhubPropertiesCaptureDescriptionDestinationStorageAccount {
    /// AccountName - Name of the storage account
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "accountName")]
    pub account_name: Option<String>,
    /// ResourceGroup - Name of the storage account resource group
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "resourceGroup")]
    pub resource_group: Option<String>,
}

/// ASOStatus (AzureServiceOperatorsStatus) defines the observed state of resource actions
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct EventhubStatus {
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
    pub polling_url_kind: Option<EventhubStatusPollingUrlKind>,
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
pub enum EventhubStatusPollingUrlKind {
    CreateOrUpdate,
    Delete,
}

