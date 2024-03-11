// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/apecloud/kubeblocks/storage.kubeblocks.io/v1alpha1/storageproviders.yaml --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// StorageProviderSpec defines the desired state of `StorageProvider`.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "storage.kubeblocks.io", version = "v1alpha1", kind = "StorageProvider", plural = "storageproviders")]
#[kube(status = "StorageProviderStatus")]
#[kube(schema = "disabled")]
pub struct StorageProviderSpec {
    /// Specifies the name of the CSI driver used to access remote storage. This field can be empty, it indicates that the storage is not accessible via CSI.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "csiDriverName")]
    pub csi_driver_name: Option<String>,
    /// A Go template that used to render and generate `k8s.io/api/core/v1.Secret` resources for a specific CSI driver. For example, `accessKey` and `secretKey` needed by CSI-S3 are stored in this `Secret` resource.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "csiDriverSecretTemplate")]
    pub csi_driver_secret_template: Option<String>,
    /// A Go template used to render and generate `k8s.io/api/core/v1.Secret`. This `Secret` involves the configuration details required by the `datasafed` tool to access remote storage. For example, the `Secret` should contain `endpoint`, `bucket`, 'region', 'accessKey', 'secretKey', or something else for S3 storage. This field can be empty, it means this kind of storage is not accessible via the `datasafed` tool.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "datasafedConfigTemplate")]
    pub datasafed_config_template: Option<String>,
    /// Describes the parameters required for storage. The parameters defined here can be referenced in the above templates, and `kbcli` uses this definition for dynamic command-line parameter parsing.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "parametersSchema")]
    pub parameters_schema: Option<StorageProviderParametersSchema>,
    /// A Go template that renders and generates `k8s.io/api/core/v1.PersistentVolumeClaim` resources. This PVC can reference the `StorageClass` created from `storageClassTemplate`, allowing Pods to access remote storage by mounting the PVC.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "persistentVolumeClaimTemplate")]
    pub persistent_volume_claim_template: Option<String>,
    /// A Go template utilized to render and generate `kubernetes.storage.k8s.io.v1.StorageClass` resources. The `StorageClass' created by this template is aimed at using the CSI driver.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "storageClassTemplate")]
    pub storage_class_template: Option<String>,
}

/// Describes the parameters required for storage. The parameters defined here can be referenced in the above templates, and `kbcli` uses this definition for dynamic command-line parameter parsing.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct StorageProviderParametersSchema {
    /// Defines which parameters are credential fields, which need to be handled specifically. For instance, these should be stored in a `Secret` instead of a `ConfigMap`.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "credentialFields")]
    pub credential_fields: Option<Vec<String>>,
    /// Defines the parameters in OpenAPI V3.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "openAPIV3Schema")]
    pub open_apiv3_schema: Option<BTreeMap<String, serde_json::Value>>,
}

/// StorageProviderStatus defines the observed state of `StorageProvider`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct StorageProviderStatus {
    /// Describes the current state of the `StorageProvider`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// The phase of the `StorageProvider`. Valid phases are `NotReady` and `Ready`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<StorageProviderStatusPhase>,
}

/// StorageProviderStatus defines the observed state of `StorageProvider`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum StorageProviderStatusPhase {
    NotReady,
    Ready,
}

