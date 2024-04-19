// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/hashicorp/vault-secrets-operator/secrets.hashicorp.com/v1beta1/hcpauths.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// HCPAuthSpec defines the desired state of HCPAuth
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "secrets.hashicorp.com", version = "v1beta1", kind = "HCPAuth", plural = "hcpauths")]
#[kube(namespaced)]
#[kube(status = "HCPAuthStatus")]
#[kube(schema = "disabled")]
pub struct HCPAuthSpec {
    /// AllowedNamespaces Kubernetes Namespaces which are allow-listed for use with this AuthMethod. This field allows administrators to customize which Kubernetes namespaces are authorized to use with this AuthMethod. While Vault will still enforce its own rules, this has the added configurability of restricting which HCPAuthMethods can be used by which namespaces. Accepted values: []{"*"} - wildcard, all namespaces. []{"a", "b"} - list of namespaces. unset - disallow all namespaces except the Operator's the HCPAuthMethod's namespace, this is the default behavior.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "allowedNamespaces")]
    pub allowed_namespaces: Option<Vec<String>>,
    /// Method to use when authenticating to Vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<HCPAuthMethod>,
    /// OrganizationID of the HCP organization.
    #[serde(rename = "organizationID")]
    pub organization_id: String,
    /// ProjectID of the HCP project.
    #[serde(rename = "projectID")]
    pub project_id: String,
    /// ServicePrincipal provides the necessary configuration for authenticating to HCP using a service principal. For security reasons, only project-level service principals should ever be used.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "servicePrincipal")]
    pub service_principal: Option<HCPAuthServicePrincipal>,
}

/// HCPAuthSpec defines the desired state of HCPAuth
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum HCPAuthMethod {
    #[serde(rename = "servicePrincipal")]
    ServicePrincipal,
}

/// ServicePrincipal provides the necessary configuration for authenticating to HCP using a service principal. For security reasons, only project-level service principals should ever be used.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct HCPAuthServicePrincipal {
    /// SecretRef is the name of a Kubernetes secret in the consumer's (VDS/VSS/PKI/HCP) namespace which provides the HCP ServicePrincipal clientID, and clientSecret. The secret data must have the following structure { "clientID": "clientID", "clientSecret": "clientSecret", }
    #[serde(rename = "secretRef")]
    pub secret_ref: String,
}

/// HCPAuthStatus defines the observed state of HCPAuth
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct HCPAuthStatus {
    pub error: String,
    /// Valid auth mechanism.
    pub valid: bool,
}

