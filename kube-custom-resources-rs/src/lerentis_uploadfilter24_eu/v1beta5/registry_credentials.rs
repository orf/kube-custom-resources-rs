// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/Lerentis/bitwarden-crd-operator/lerentis.uploadfilter24.eu/v1beta5/registry-credentials.yaml --derive=Default --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use std::collections::BTreeMap;
}
use self::prelude::*;

#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "lerentis.uploadfilter24.eu", version = "v1beta5", kind = "RegistryCredential", plural = "registry-credentials")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
#[kube(derive="Default")]
#[kube(derive="PartialEq")]
pub struct RegistryCredentialSpec {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, serde_json::Value>>,
    pub name: String,
    pub namespace: String,
    #[serde(rename = "passwordRef")]
    pub password_ref: String,
    pub registry: String,
    #[serde(rename = "usernameRef")]
    pub username_ref: String,
}

