// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/CleverCloud/clever-operator/api.clever-cloud.com/v1/elasticsearches.yaml --derive=Default --derive=PartialEq
// kopium version: 0.16.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};

#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "api.clever-cloud.com", version = "v1", kind = "ElasticSearch", plural = "elasticsearches")]
#[kube(namespaced)]
#[kube(status = "ElasticSearchStatus")]
#[kube(schema = "disabled")]
pub struct ElasticSearchSpec {
    pub instance: ElasticSearchInstance,
    pub options: ElasticSearchOptions,
    pub organisation: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ElasticSearchInstance {
    pub plan: String,
    pub region: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ElasticSearchOptions {
    pub apm: bool,
    pub encryption: bool,
    pub kibana: bool,
    pub version: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ElasticSearchOptionsVersion {
    #[serde(rename = "6")]
    r#_6,
    #[serde(rename = "7")]
    r#_7,
    #[serde(rename = "8")]
    r#_8,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ElasticSearchStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addon: Option<String>,
}
