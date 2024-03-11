// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/openshift/hive/hiveinternal.openshift.io/v1alpha1/fakeclusterinstalls.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// FakeClusterInstallSpec defines the desired state of the FakeClusterInstall.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "hiveinternal.openshift.io", version = "v1alpha1", kind = "FakeClusterInstall", plural = "fakeclusterinstalls")]
#[kube(namespaced)]
#[kube(status = "FakeClusterInstallStatus")]
#[kube(schema = "disabled")]
pub struct FakeClusterInstallSpec {
    /// ClusterDeploymentRef is a reference to the ClusterDeployment associated with this AgentClusterInstall.
    #[serde(rename = "clusterDeploymentRef")]
    pub cluster_deployment_ref: FakeClusterInstallClusterDeploymentRef,
    /// ClusterMetadata contains metadata information about the installed cluster. It should be populated once the cluster install is completed. (it can be populated sooner if desired, but Hive will not copy back to ClusterDeployment until the Installed condition goes True.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clusterMetadata")]
    pub cluster_metadata: Option<FakeClusterInstallClusterMetadata>,
    /// ImageSetRef is a reference to a ClusterImageSet. The release image specified in the ClusterImageSet will be used to install the cluster.
    #[serde(rename = "imageSetRef")]
    pub image_set_ref: FakeClusterInstallImageSetRef,
}

/// ClusterDeploymentRef is a reference to the ClusterDeployment associated with this AgentClusterInstall.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FakeClusterInstallClusterDeploymentRef {
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// ClusterMetadata contains metadata information about the installed cluster. It should be populated once the cluster install is completed. (it can be populated sooner if desired, but Hive will not copy back to ClusterDeployment until the Installed condition goes True.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FakeClusterInstallClusterMetadata {
    /// AdminKubeconfigSecretRef references the secret containing the admin kubeconfig for this cluster.
    #[serde(rename = "adminKubeconfigSecretRef")]
    pub admin_kubeconfig_secret_ref: FakeClusterInstallClusterMetadataAdminKubeconfigSecretRef,
    /// AdminPasswordSecretRef references the secret containing the admin username/password which can be used to login to this cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "adminPasswordSecretRef")]
    pub admin_password_secret_ref: Option<FakeClusterInstallClusterMetadataAdminPasswordSecretRef>,
    /// ClusterID is a globally unique identifier for this cluster generated during installation. Used for reporting metrics among other places.
    #[serde(rename = "clusterID")]
    pub cluster_id: String,
    /// InfraID is an identifier for this cluster generated during installation and used for tagging/naming resources in cloud providers.
    #[serde(rename = "infraID")]
    pub infra_id: String,
    /// Platform holds platform-specific cluster metadata
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<FakeClusterInstallClusterMetadataPlatform>,
}

/// AdminKubeconfigSecretRef references the secret containing the admin kubeconfig for this cluster.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FakeClusterInstallClusterMetadataAdminKubeconfigSecretRef {
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// AdminPasswordSecretRef references the secret containing the admin username/password which can be used to login to this cluster.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FakeClusterInstallClusterMetadataAdminPasswordSecretRef {
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Platform holds platform-specific cluster metadata
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FakeClusterInstallClusterMetadataPlatform {
    /// AWS holds AWS-specific cluster metadata
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws: Option<FakeClusterInstallClusterMetadataPlatformAws>,
    /// Azure holds azure-specific cluster metadata
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure: Option<FakeClusterInstallClusterMetadataPlatformAzure>,
    /// GCP holds GCP-specific cluster metadata
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gcp: Option<FakeClusterInstallClusterMetadataPlatformGcp>,
}

/// AWS holds AWS-specific cluster metadata
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FakeClusterInstallClusterMetadataPlatformAws {
    /// HostedZoneRole is the role to assume when performing operations on a hosted zone owned by another account.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "hostedZoneRole")]
    pub hosted_zone_role: Option<String>,
}

/// Azure holds azure-specific cluster metadata
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FakeClusterInstallClusterMetadataPlatformAzure {
    /// ResourceGroupName is the name of the resource group in which the cluster resources were created.
    #[serde(rename = "resourceGroupName")]
    pub resource_group_name: String,
}

/// GCP holds GCP-specific cluster metadata
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FakeClusterInstallClusterMetadataPlatformGcp {
    /// NetworkProjectID is used for shared VPC setups
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "networkProjectID")]
    pub network_project_id: Option<String>,
}

/// ImageSetRef is a reference to a ClusterImageSet. The release image specified in the ClusterImageSet will be used to install the cluster.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FakeClusterInstallImageSetRef {
    /// Name is the name of the ClusterImageSet that this refers to
    pub name: String,
}

/// FakeClusterInstallStatus defines the observed state of the FakeClusterInstall.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FakeClusterInstallStatus {
    /// Conditions includes more detailed status for the cluster install.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
}

