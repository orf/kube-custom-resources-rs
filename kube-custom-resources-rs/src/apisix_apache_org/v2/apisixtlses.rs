// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/apache/apisix-ingress-controller/apisix.apache.org/v2/apisixtlses.yaml --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// ApisixTlsSpec is the specification of ApisixSSL.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "apisix.apache.org", version = "v2", kind = "ApisixTls", plural = "apisixtlses")]
#[kube(namespaced)]
#[kube(status = "ApisixTlsStatus")]
#[kube(schema = "disabled")]
pub struct ApisixTlsSpec {
    /// ApisixMutualTlsClientConfig describes the mutual TLS CA and verify depth
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<ApisixTlsClient>,
    pub hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ingressClassName")]
    pub ingress_class_name: Option<String>,
    /// ApisixSecret describes the Kubernetes Secret name and namespace.
    pub secret: ApisixTlsSecret,
}

/// ApisixMutualTlsClientConfig describes the mutual TLS CA and verify depth
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ApisixTlsClient {
    /// ApisixSecret describes the Kubernetes Secret name and namespace.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "caSecret")]
    pub ca_secret: Option<ApisixTlsClientCaSecret>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_mtls_uri_regex: Option<Vec<String>>,
}

/// ApisixSecret describes the Kubernetes Secret name and namespace.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ApisixTlsClientCaSecret {
    pub name: String,
    pub namespace: String,
}

/// ApisixSecret describes the Kubernetes Secret name and namespace.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ApisixTlsSecret {
    pub name: String,
    pub namespace: String,
}

/// ApisixStatus is the status report for Apisix ingress Resources
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ApisixTlsStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
}

