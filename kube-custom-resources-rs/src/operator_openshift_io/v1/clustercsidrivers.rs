// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/openshift/api/operator.openshift.io/v1/clustercsidrivers.yaml --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// spec holds user settable values for configuration
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "operator.openshift.io", version = "v1", kind = "ClusterCSIDriver", plural = "clustercsidrivers")]
#[kube(status = "ClusterCSIDriverStatus")]
#[kube(schema = "disabled")]
pub struct ClusterCSIDriverSpec {
    /// driverConfig can be used to specify platform specific driver configuration. When omitted, this means no opinion and the platform is left to choose reasonable defaults. These defaults are subject to change over time.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "driverConfig")]
    pub driver_config: Option<ClusterCSIDriverDriverConfig>,
    /// logLevel is an intent based logging for an overall component.  It does not give fine grained control, but it is a simple way to manage coarse grained logging choices that operators have to interpret for their operands. 
    ///  Valid values are: "Normal", "Debug", "Trace", "TraceAll". Defaults to "Normal".
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "logLevel")]
    pub log_level: Option<ClusterCSIDriverLogLevel>,
    /// managementState indicates whether and how the operator should manage the component
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "managementState")]
    pub management_state: Option<String>,
    /// observedConfig holds a sparse config that controller has observed from the cluster state.  It exists in spec because it is an input to the level for the operator
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedConfig")]
    pub observed_config: Option<BTreeMap<String, serde_json::Value>>,
    /// operatorLogLevel is an intent based logging for the operator itself.  It does not give fine grained control, but it is a simple way to manage coarse grained logging choices that operators have to interpret for themselves. 
    ///  Valid values are: "Normal", "Debug", "Trace", "TraceAll". Defaults to "Normal".
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "operatorLogLevel")]
    pub operator_log_level: Option<ClusterCSIDriverOperatorLogLevel>,
    /// StorageClassState determines if CSI operator should create and manage storage classes. If this field value is empty or Managed - CSI operator will continuously reconcile storage class and create if necessary. If this field value is Unmanaged - CSI operator will not reconcile any previously created storage class. If this field value is Removed - CSI operator will delete the storage class it created previously. When omitted, this means the user has no opinion and the platform chooses a reasonable default, which is subject to change over time. The current default behaviour is Managed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "storageClassState")]
    pub storage_class_state: Option<ClusterCSIDriverStorageClassState>,
    /// unsupportedConfigOverrides overrides the final configuration that was computed by the operator. Red Hat does not support the use of this field. Misuse of this field could lead to unexpected behavior or conflict with other configuration options. Seek guidance from the Red Hat support before using this field. Use of this property blocks cluster upgrades, it must be removed before upgrading your cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "unsupportedConfigOverrides")]
    pub unsupported_config_overrides: Option<BTreeMap<String, serde_json::Value>>,
}

/// driverConfig can be used to specify platform specific driver configuration. When omitted, this means no opinion and the platform is left to choose reasonable defaults. These defaults are subject to change over time.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterCSIDriverDriverConfig {
    /// aws is used to configure the AWS CSI driver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws: Option<ClusterCSIDriverDriverConfigAws>,
    /// azure is used to configure the Azure CSI driver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure: Option<ClusterCSIDriverDriverConfigAzure>,
    /// driverType indicates type of CSI driver for which the driverConfig is being applied to. Valid values are: AWS, Azure, GCP, IBMCloud, vSphere and omitted. Consumers should treat unknown values as a NO-OP.
    #[serde(rename = "driverType")]
    pub driver_type: ClusterCSIDriverDriverConfigDriverType,
    /// gcp is used to configure the GCP CSI driver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gcp: Option<ClusterCSIDriverDriverConfigGcp>,
    /// ibmcloud is used to configure the IBM Cloud CSI driver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ibmcloud: Option<ClusterCSIDriverDriverConfigIbmcloud>,
    /// vsphere is used to configure the vsphere CSI driver.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vSphere")]
    pub v_sphere: Option<ClusterCSIDriverDriverConfigVSphere>,
}

/// aws is used to configure the AWS CSI driver.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterCSIDriverDriverConfigAws {
    /// kmsKeyARN sets the cluster default storage class to encrypt volumes with a user-defined KMS key, rather than the default KMS key used by AWS. The value may be either the ARN or Alias ARN of a KMS key.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "kmsKeyARN")]
    pub kms_key_arn: Option<String>,
}

/// azure is used to configure the Azure CSI driver.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterCSIDriverDriverConfigAzure {
    /// diskEncryptionSet sets the cluster default storage class to encrypt volumes with a customer-managed encryption set, rather than the default platform-managed keys.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "diskEncryptionSet")]
    pub disk_encryption_set: Option<ClusterCSIDriverDriverConfigAzureDiskEncryptionSet>,
}

/// diskEncryptionSet sets the cluster default storage class to encrypt volumes with a customer-managed encryption set, rather than the default platform-managed keys.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterCSIDriverDriverConfigAzureDiskEncryptionSet {
    /// name is the name of the disk encryption set that will be set on the default storage class. The value should consist of only alphanumberic characters, underscores (_), hyphens, and be at most 80 characters in length.
    pub name: String,
    /// resourceGroup defines the Azure resource group that contains the disk encryption set. The value should consist of only alphanumberic characters, underscores (_), parentheses, hyphens and periods. The value should not end in a period and be at most 90 characters in length.
    #[serde(rename = "resourceGroup")]
    pub resource_group: String,
    /// subscriptionID defines the Azure subscription that contains the disk encryption set. The value should meet the following conditions: 1. It should be a 128-bit number. 2. It should be 36 characters (32 hexadecimal characters and 4 hyphens) long. 3. It should be displayed in five groups separated by hyphens (-). 4. The first group should be 8 characters long. 5. The second, third, and fourth groups should be 4 characters long. 6. The fifth group should be 12 characters long. An Example SubscrionID: f2007bbf-f802-4a47-9336-cf7c6b89b378
    #[serde(rename = "subscriptionID")]
    pub subscription_id: String,
}

/// driverConfig can be used to specify platform specific driver configuration. When omitted, this means no opinion and the platform is left to choose reasonable defaults. These defaults are subject to change over time.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ClusterCSIDriverDriverConfigDriverType {
    #[serde(rename = "")]
    KopiumEmpty,
    #[serde(rename = "AWS")]
    Aws,
    Azure,
    #[serde(rename = "GCP")]
    Gcp,
    #[serde(rename = "IBMCloud")]
    IbmCloud,
    #[serde(rename = "vSphere")]
    VSphere,
}

/// gcp is used to configure the GCP CSI driver.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterCSIDriverDriverConfigGcp {
    /// kmsKey sets the cluster default storage class to encrypt volumes with customer-supplied encryption keys, rather than the default keys managed by GCP.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "kmsKey")]
    pub kms_key: Option<ClusterCSIDriverDriverConfigGcpKmsKey>,
}

/// kmsKey sets the cluster default storage class to encrypt volumes with customer-supplied encryption keys, rather than the default keys managed by GCP.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterCSIDriverDriverConfigGcpKmsKey {
    /// keyRing is the name of the KMS Key Ring which the KMS Key belongs to. The value should correspond to an existing KMS key ring and should consist of only alphanumeric characters, hyphens (-) and underscores (_), and be at most 63 characters in length.
    #[serde(rename = "keyRing")]
    pub key_ring: String,
    /// location is the GCP location in which the Key Ring exists. The value must match an existing GCP location, or "global". Defaults to global, if not set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// name is the name of the customer-managed encryption key to be used for disk encryption. The value should correspond to an existing KMS key and should consist of only alphanumeric characters, hyphens (-) and underscores (_), and be at most 63 characters in length.
    pub name: String,
    /// projectID is the ID of the Project in which the KMS Key Ring exists. It must be 6 to 30 lowercase letters, digits, or hyphens. It must start with a letter. Trailing hyphens are prohibited.
    #[serde(rename = "projectID")]
    pub project_id: String,
}

/// ibmcloud is used to configure the IBM Cloud CSI driver.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterCSIDriverDriverConfigIbmcloud {
    /// encryptionKeyCRN is the IBM Cloud CRN of the customer-managed root key to use for disk encryption of volumes for the default storage classes.
    #[serde(rename = "encryptionKeyCRN")]
    pub encryption_key_crn: String,
}

/// vsphere is used to configure the vsphere CSI driver.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterCSIDriverDriverConfigVSphere {
    /// topologyCategories indicates tag categories with which vcenter resources such as hostcluster or datacenter were tagged with. If cluster Infrastructure object has a topology, values specified in Infrastructure object will be used and modifications to topologyCategories will be rejected.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "topologyCategories")]
    pub topology_categories: Option<Vec<String>>,
}

/// spec holds user settable values for configuration
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ClusterCSIDriverLogLevel {
    #[serde(rename = "")]
    KopiumEmpty,
    Normal,
    Debug,
    Trace,
    TraceAll,
}

/// spec holds user settable values for configuration
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ClusterCSIDriverOperatorLogLevel {
    #[serde(rename = "")]
    KopiumEmpty,
    Normal,
    Debug,
    Trace,
    TraceAll,
}

/// spec holds user settable values for configuration
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ClusterCSIDriverStorageClassState {
    #[serde(rename = "")]
    KopiumEmpty,
    Managed,
    Unmanaged,
    Removed,
}

/// status holds observed values from the cluster. They may not be overridden.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterCSIDriverStatus {
    /// conditions is a list of conditions and their status
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// generations are used to determine when an item needs to be reconciled or has changed in a way that needs a reaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generations: Option<Vec<ClusterCSIDriverStatusGenerations>>,
    /// observedGeneration is the last generation change you've dealt with
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
    /// readyReplicas indicates how many replicas are ready and at the desired state
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "readyReplicas")]
    pub ready_replicas: Option<i32>,
    /// version is the level this availability applies to
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// GenerationStatus keeps track of the generation for a given resource so that decisions about forced updates can be made.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterCSIDriverStatusGenerations {
    /// group is the group of the thing you're tracking
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// hash is an optional field set for resources without generation that are content sensitive like secrets and configmaps
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// lastGeneration is the last generation of the workload controller involved
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastGeneration")]
    pub last_generation: Option<i64>,
    /// name is the name of the thing you're tracking
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// namespace is where the thing you're tracking is
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// resource is the resource type of the thing you're tracking
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

