// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/openshift/api/helm.openshift.io/v1beta1/projecthelmchartrepositories.yaml --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// spec holds user settable values for configuration
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "helm.openshift.io", version = "v1beta1", kind = "ProjectHelmChartRepository", plural = "projecthelmchartrepositories")]
#[kube(namespaced)]
#[kube(status = "ProjectHelmChartRepositoryStatus")]
#[kube(schema = "disabled")]
pub struct ProjectHelmChartRepositorySpec {
    /// Required configuration for connecting to the chart repo
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "connectionConfig")]
    pub connection_config: Option<ProjectHelmChartRepositoryConnectionConfig>,
    /// Optional human readable repository description, it can be used by UI for displaying purposes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// If set to true, disable the repo usage in the namespace
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    /// Optional associated human readable repository name, it can be used by UI for displaying purposes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Required configuration for connecting to the chart repo
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ProjectHelmChartRepositoryConnectionConfig {
    /// basicAuthConfig is an optional reference to a secret by name that contains the basic authentication credentials to present when connecting to the server. The key "username" is used locate the username. The key "password" is used to locate the password. The namespace for this secret must be same as the namespace where the project helm chart repository is getting instantiated.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "basicAuthConfig")]
    pub basic_auth_config: Option<ProjectHelmChartRepositoryConnectionConfigBasicAuthConfig>,
    /// ca is an optional reference to a config map by name containing the PEM-encoded CA bundle. It is used as a trust anchor to validate the TLS certificate presented by the remote server. The key "ca-bundle.crt" is used to locate the data. If empty, the default system roots are used. The namespace for this configmap must be same as the namespace where the project helm chart repository is getting instantiated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<ProjectHelmChartRepositoryConnectionConfigCa>,
    /// tlsClientConfig is an optional reference to a secret by name that contains the PEM-encoded TLS client certificate and private key to present when connecting to the server. The key "tls.crt" is used to locate the client certificate. The key "tls.key" is used to locate the private key. The namespace for this secret must be same as the namespace where the project helm chart repository is getting instantiated.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "tlsClientConfig")]
    pub tls_client_config: Option<ProjectHelmChartRepositoryConnectionConfigTlsClientConfig>,
    /// Chart repository URL
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// basicAuthConfig is an optional reference to a secret by name that contains the basic authentication credentials to present when connecting to the server. The key "username" is used locate the username. The key "password" is used to locate the password. The namespace for this secret must be same as the namespace where the project helm chart repository is getting instantiated.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ProjectHelmChartRepositoryConnectionConfigBasicAuthConfig {
    /// name is the metadata.name of the referenced secret
    pub name: String,
}

/// ca is an optional reference to a config map by name containing the PEM-encoded CA bundle. It is used as a trust anchor to validate the TLS certificate presented by the remote server. The key "ca-bundle.crt" is used to locate the data. If empty, the default system roots are used. The namespace for this configmap must be same as the namespace where the project helm chart repository is getting instantiated.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ProjectHelmChartRepositoryConnectionConfigCa {
    /// name is the metadata.name of the referenced config map
    pub name: String,
}

/// tlsClientConfig is an optional reference to a secret by name that contains the PEM-encoded TLS client certificate and private key to present when connecting to the server. The key "tls.crt" is used to locate the client certificate. The key "tls.key" is used to locate the private key. The namespace for this secret must be same as the namespace where the project helm chart repository is getting instantiated.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ProjectHelmChartRepositoryConnectionConfigTlsClientConfig {
    /// name is the metadata.name of the referenced secret
    pub name: String,
}

/// Observed status of the repository within the namespace..
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ProjectHelmChartRepositoryStatus {
    /// conditions is a list of conditions and their statuses
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
}

