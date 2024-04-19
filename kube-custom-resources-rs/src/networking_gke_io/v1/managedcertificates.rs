// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/GoogleCloudPlatform/gke-managed-certs/networking.gke.io/v1/managedcertificates.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};

#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "networking.gke.io", version = "v1", kind = "ManagedCertificate", plural = "managedcertificates")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct ManagedCertificateSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domains: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ManagedCertificateStatus {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "certificateName")]
    pub certificate_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "certificateStatus")]
    pub certificate_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "domainStatus")]
    pub domain_status: Option<Vec<ManagedCertificateStatusDomainStatus>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "expireTime")]
    pub expire_time: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ManagedCertificateStatusDomainStatus {
    pub domain: String,
    pub status: String,
}

