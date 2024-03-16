// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws/eks-anywhere/anywhere.eks.amazonaws.com/v1alpha1/fluxconfigs.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// FluxConfigSpec defines the desired state of FluxConfig.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "anywhere.eks.amazonaws.com", version = "v1alpha1", kind = "FluxConfig", plural = "fluxconfigs")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct FluxConfigSpec {
    /// Git branch. Defaults to main.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// ClusterConfigPath relative to the repository root, when specified the cluster sync will be scoped to this path.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clusterConfigPath")]
    pub cluster_config_path: Option<String>,
    /// Used to specify Git provider that will be used to host the git files
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<FluxConfigGit>,
    /// Used to specify Github provider to host the Git repo and host the git files
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github: Option<FluxConfigGithub>,
    /// SystemNamespace scope for this operation. Defaults to flux-system
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "systemNamespace")]
    pub system_namespace: Option<String>,
}

/// Used to specify Git provider that will be used to host the git files
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FluxConfigGit {
    /// Repository URL for the repository to be used with flux. Can be either an SSH or HTTPS url.
    #[serde(rename = "repositoryUrl")]
    pub repository_url: String,
    /// SSH public key algorithm for the private key specified (rsa, ecdsa, ed25519) (default ecdsa)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sshKeyAlgorithm")]
    pub ssh_key_algorithm: Option<String>,
}

/// Used to specify Github provider to host the Git repo and host the git files
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FluxConfigGithub {
    /// Owner is the user or organization name of the Git provider.
    pub owner: String,
    /// if true, the owner is assumed to be a Git user; otherwise an org.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub personal: Option<bool>,
    /// Repository name.
    pub repository: String,
}

/// FluxConfigStatus defines the observed state of FluxConfig.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FluxConfigStatus {
}

