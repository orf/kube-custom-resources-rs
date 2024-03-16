// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/CleverCloud/clever-operator/api.clever-cloud.com/v1/redis.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};

#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "api.clever-cloud.com", version = "v1", kind = "Redis", plural = "redis")]
#[kube(namespaced)]
#[kube(status = "RedisStatus")]
#[kube(schema = "disabled")]
pub struct RedisSpec {
    pub instance: RedisInstance,
    pub options: RedisOptions,
    pub organisation: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RedisInstance {
    pub plan: String,
    pub region: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RedisOptions {
    pub encryption: bool,
    pub version: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum RedisOptionsVersion {
    #[serde(rename = "626")]
    r#_626,
    #[serde(rename = "704")]
    r#_704,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RedisStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addon: Option<String>,
}

