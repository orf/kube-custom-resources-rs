// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/nginxinc/kubernetes-ingress/appprotect.f5.com/v1beta1/apusersigs.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// APUserSigSpec defines the desired state of APUserSig
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "appprotect.f5.com", version = "v1beta1", kind = "APUserSig", plural = "apusersigs")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct APUserSigSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signatures: Option<Vec<APUserSigSignatures>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct APUserSigSignatures {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accuracy: Option<APUserSigSignaturesAccuracy>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "attackType")]
    pub attack_type: Option<APUserSigSignaturesAttackType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub references: Option<APUserSigSignaturesReferences>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<APUserSigSignaturesRisk>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "signatureType")]
    pub signature_type: Option<APUserSigSignaturesSignatureType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub systems: Option<Vec<APUserSigSignaturesSystems>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum APUserSigSignaturesAccuracy {
    #[serde(rename = "high")]
    High,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "low")]
    Low,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct APUserSigSignaturesAttackType {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct APUserSigSignaturesReferences {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<APUserSigSignaturesReferencesType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum APUserSigSignaturesReferencesType {
    #[serde(rename = "bugtraq")]
    Bugtraq,
    #[serde(rename = "cve")]
    Cve,
    #[serde(rename = "nessus")]
    Nessus,
    #[serde(rename = "url")]
    Url,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum APUserSigSignaturesRisk {
    #[serde(rename = "high")]
    High,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "low")]
    Low,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum APUserSigSignaturesSignatureType {
    #[serde(rename = "request")]
    Request,
    #[serde(rename = "response")]
    Response,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct APUserSigSignaturesSystems {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

