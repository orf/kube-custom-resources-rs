// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/isindir/sops-secrets-operator/isindir.github.com/v1alpha1/sopssecrets.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// SopsSecret metadata
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SopsSecretSops {
    /// Azure KMS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure_kv: Option<Vec<SopsSecretSopsAzureKv>>,
    /// Suffix used to encrypt SopsSecret resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_suffix: Option<String>,
    /// Gcp KMS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gcp_kms: Option<Vec<SopsSecretSopsGcpKms>>,
    /// Aws KMS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kms: Option<Vec<SopsSecretSopsKms>>,
    /// LastModified date when SopsSecret was last modified
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lastmodified: Option<String>,
    /// Mac - sops setting
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// PGP configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pgp: Option<Vec<SopsSecretSopsPgp>>,
    /// Version of the sops tool used to encrypt SopsSecret
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// AzureKmsItem defines Azure Keyvault Key specific encryption details
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SopsSecretSopsAzureKv {
    /// Object creation date
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Azure KMS vault URL
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// GcpKmsDataItem defines GCP KMS Key specific encryption details
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SopsSecretSopsGcpKms {
    /// Object creation date
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
}

/// KmsDataItem defines AWS KMS specific encryption details
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SopsSecretSopsKms {
    /// Arn - KMS key ARN to use
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws_profile: Option<String>,
    /// Object creation date
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc: Option<String>,
}

/// PgpDataItem defines PGP specific encryption details
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SopsSecretSopsPgp {
    /// Object creation date
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc: Option<String>,
    /// PGP FingerPrint of the key which can be used for decryption
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fp: Option<String>,
}

/// SopsSecret Spec definition
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "isindir.github.com", version = "v1alpha1", kind = "SopsSecret", plural = "sopssecrets")]
#[kube(namespaced)]
#[kube(status = "SopsSecretStatus")]
#[kube(schema = "disabled")]
pub struct SopsSecretSpec {
    /// Secrets template is a list of definitions to create Kubernetes Secrets
    pub secret_templates: Vec<SopsSecretSecretTemplates>,
}

/// SopsSecretTemplate defines the map of secrets to create
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SopsSecretSecretTemplates {
    /// Annotations to apply to Kubernetes secret
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
    /// Data map to use in Kubernetes secret (equivalent to Kubernetes Secret object stringData, please see for more
    /// information: https://kubernetes.io/docs/concepts/configuration/secret/#overview-of-secrets)
    pub data: BTreeMap<String, String>,
    /// Labels to apply to Kubernetes secret
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    /// Name of the Kubernetes secret to create
    pub name: String,
    /// Kubernetes secret type. Default: Opauqe. Possible values: Opauqe,
    /// kubernetes.io/service-account-token, kubernetes.io/dockercfg,
    /// kubernetes.io/dockerconfigjson, kubernetes.io/basic-auth,
    /// kubernetes.io/ssh-auth, kubernetes.io/tls, bootstrap.kubernetes.io/token
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
}

/// SopsSecret Status information
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SopsSecretStatus {
}

