// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/nginxinc/kubernetes-ingress/appprotectdos.f5.com/v1beta1/apdospolicies.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// APDosPolicySpec defines the desired state of APDosPolicy
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "appprotectdos.f5.com", version = "v1beta1", kind = "APDosPolicy", plural = "apdospolicies")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct APDosPolicySpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub automation_tools_detection: Option<APDosPolicyAutomationToolsDetection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bad_actors: Option<APDosPolicyBadActors>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mitigation_mode: Option<APDosPolicyMitigationMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signatures: Option<APDosPolicySignatures>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_fingerprint: Option<APDosPolicyTlsFingerprint>,
}

/// APDosPolicySpec defines the desired state of APDosPolicy
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum APDosPolicyAutomationToolsDetection {
    #[serde(rename = "on")]
    On,
    #[serde(rename = "off")]
    Off,
}

/// APDosPolicySpec defines the desired state of APDosPolicy
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum APDosPolicyBadActors {
    #[serde(rename = "on")]
    On,
    #[serde(rename = "off")]
    Off,
}

/// APDosPolicySpec defines the desired state of APDosPolicy
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum APDosPolicyMitigationMode {
    #[serde(rename = "standard")]
    Standard,
    #[serde(rename = "conservative")]
    Conservative,
    #[serde(rename = "none")]
    None,
}

/// APDosPolicySpec defines the desired state of APDosPolicy
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum APDosPolicySignatures {
    #[serde(rename = "on")]
    On,
    #[serde(rename = "off")]
    Off,
}

/// APDosPolicySpec defines the desired state of APDosPolicy
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum APDosPolicyTlsFingerprint {
    #[serde(rename = "on")]
    On,
    #[serde(rename = "off")]
    Off,
}

