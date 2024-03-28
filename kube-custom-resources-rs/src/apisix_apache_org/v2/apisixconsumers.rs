// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/apache/apisix-ingress-controller/apisix.apache.org/v2/apisixconsumers.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "apisix.apache.org", version = "v2", kind = "ApisixConsumer", plural = "apisixconsumers")]
#[kube(namespaced)]
#[kube(status = "ApisixConsumerStatus")]
#[kube(schema = "disabled")]
pub struct ApisixConsumerSpec {
    #[serde(rename = "authParameter")]
    pub auth_parameter: ApisixConsumerAuthParameter,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ingressClassName")]
    pub ingress_class_name: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ApisixConsumerAuthParameter {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "basicAuth")]
    pub basic_auth: Option<ApisixConsumerAuthParameterBasicAuth>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "hmacAuth")]
    pub hmac_auth: Option<ApisixConsumerAuthParameterHmacAuth>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "jwtAuth")]
    pub jwt_auth: Option<ApisixConsumerAuthParameterJwtAuth>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "keyAuth")]
    pub key_auth: Option<ApisixConsumerAuthParameterKeyAuth>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ldapAuth")]
    pub ldap_auth: Option<ApisixConsumerAuthParameterLdapAuth>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "wolfRBAC")]
    pub wolf_rbac: Option<ApisixConsumerAuthParameterWolfRbac>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ApisixConsumerAuthParameterBasicAuth {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretRef")]
    pub secret_ref: Option<ApisixConsumerAuthParameterBasicAuthSecretRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<ApisixConsumerAuthParameterBasicAuthValue>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ApisixConsumerAuthParameterBasicAuthSecretRef {
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ApisixConsumerAuthParameterBasicAuthValue {
    pub password: String,
    pub username: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ApisixConsumerAuthParameterHmacAuth {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretRef")]
    pub secret_ref: Option<ApisixConsumerAuthParameterHmacAuthSecretRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<ApisixConsumerAuthParameterHmacAuthValue>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ApisixConsumerAuthParameterHmacAuthSecretRef {
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ApisixConsumerAuthParameterHmacAuthValue {
    pub access_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock_skew: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encode_uri_params: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_headers: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_req_body: Option<i64>,
    pub secret_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_headers: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validate_request_body: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ApisixConsumerAuthParameterJwtAuth {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretRef")]
    pub secret_ref: Option<ApisixConsumerAuthParameterJwtAuthSecretRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<ApisixConsumerAuthParameterJwtAuthValue>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ApisixConsumerAuthParameterJwtAuthSecretRef {
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ApisixConsumerAuthParameterJwtAuthValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base64_secret: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetime_grace_period: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ApisixConsumerAuthParameterKeyAuth {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretRef")]
    pub secret_ref: Option<ApisixConsumerAuthParameterKeyAuthSecretRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<ApisixConsumerAuthParameterKeyAuthValue>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ApisixConsumerAuthParameterKeyAuthSecretRef {
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ApisixConsumerAuthParameterKeyAuthValue {
    pub key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ApisixConsumerAuthParameterLdapAuth {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretRef")]
    pub secret_ref: Option<ApisixConsumerAuthParameterLdapAuthSecretRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<ApisixConsumerAuthParameterLdapAuthValue>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ApisixConsumerAuthParameterLdapAuthSecretRef {
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ApisixConsumerAuthParameterLdapAuthValue {
    pub user_dn: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ApisixConsumerAuthParameterWolfRbac {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretRef")]
    pub secret_ref: Option<ApisixConsumerAuthParameterWolfRbacSecretRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<ApisixConsumerAuthParameterWolfRbacValue>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ApisixConsumerAuthParameterWolfRbacSecretRef {
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ApisixConsumerAuthParameterWolfRbacValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ApisixConsumerStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
}
