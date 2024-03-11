// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/emissary-ingress/emissary/getambassador.io/v3alpha1/logservices.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// LogServiceSpec defines the desired state of LogService
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "getambassador.io", version = "v3alpha1", kind = "LogService", plural = "logservices")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct LogServiceSpec {
    /// AmbassadorID declares which Ambassador instances should pay attention to this resource. If no value is provided, the default is: 
    ///  ambassador_id: - "default"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ambassador_id: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver: Option<LogServiceDriver>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver_config: Option<LogServiceDriverConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flush_interval_byte_size: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flush_interval_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc: Option<bool>,
    /// ProtocolVersion is the envoy api transport protocol version
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<LogServiceProtocolVersion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats_name: Option<String>,
}

/// LogServiceSpec defines the desired state of LogService
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum LogServiceDriver {
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "http")]
    Http,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct LogServiceDriverConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_log_headers: Option<Vec<LogServiceDriverConfigAdditionalLogHeaders>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct LogServiceDriverConfigAdditionalLogHeaders {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub during_request: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub during_response: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub during_trailer: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_name: Option<String>,
}

/// LogServiceSpec defines the desired state of LogService
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum LogServiceProtocolVersion {
    #[serde(rename = "v2")]
    V2,
    #[serde(rename = "v3")]
    V3,
}

