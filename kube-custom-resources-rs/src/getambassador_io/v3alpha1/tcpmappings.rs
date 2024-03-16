// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/emissary-ingress/emissary/getambassador.io/v3alpha1/tcpmappings.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// TCPMappingSpec defines the desired state of TCPMapping
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "getambassador.io", version = "v3alpha1", kind = "TCPMapping", plural = "tcpmappings")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct TCPMappingSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// AmbassadorID declares which Ambassador instances should pay attention to this resource. If no value is provided, the default is: 
    ///  ambassador_id: - "default"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ambassador_id: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuit_breakers: Option<Vec<TCPMappingCircuitBreakers>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_ipv4: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_ipv6: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout_ms: Option<String>,
    /// Port isn't a pointer because it's required.
    pub port: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver: Option<String>,
    pub service: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<String>,
    /// V2ExplicitTLS controls some vanity/stylistic elements when converting from v3alpha1 to v2.  The values in an V2ExplicitTLS should not in any way affect the runtime operation of Emissary; except that it may affect internal names in the Envoy config, which may in turn affect stats names.  But it should not affect any end-user observable behavior.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "v2ExplicitTLS")]
    pub v2_explicit_tls: Option<TCPMappingV2ExplicitTls>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<i64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TCPMappingCircuitBreakers {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_pending_requests: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_requests: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_retries: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<TCPMappingCircuitBreakersPriority>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum TCPMappingCircuitBreakersPriority {
    #[serde(rename = "default")]
    Default,
    #[serde(rename = "high")]
    High,
}

/// V2ExplicitTLS controls some vanity/stylistic elements when converting from v3alpha1 to v2.  The values in an V2ExplicitTLS should not in any way affect the runtime operation of Emissary; except that it may affect internal names in the Envoy config, which may in turn affect stats names.  But it should not affect any end-user observable behavior.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TCPMappingV2ExplicitTls {
    /// ServiceScheme specifies how to spell and capitalize the scheme-part of the service URL. 
    ///  Acceptable values are "http://" (case-insensitive), "https://" (case-insensitive), or "".  The value is used if it agrees with whether or not this resource enables TLS origination, or if something else in the resource overrides the scheme.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "serviceScheme")]
    pub service_scheme: Option<String>,
    /// TLS controls whether and how to represent the "tls" field when its value could be implied by the "service" field.  In v2, there were a lot of different ways to spell an "empty" value, and this field specifies which way to spell it (and will therefore only be used if the value will indeed be empty). 
    ///  | Value        | Representation                        | Meaning of representation          | |--------------+---------------------------------------+------------------------------------| | ""           | omit the field                        | defer to service (no TLSContext)   | | "null"       | store an explicit "null" in the field | defer to service (no TLSContext)   | | "string"     | store an empty string in the field    | defer to service (no TLSContext)   | | "bool:false" | store a Boolean "false" in the field  | defer to service (no TLSContext)   | | "bool:true"  | store a Boolean "true" in the field   | originate TLS (no TLSContext)      | 
    ///  If the meaning of the representation contradicts anything else (if a TLSContext is to be used, or in the case of "bool:true" if TLS is not to be originated), then this field is ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TCPMappingV2ExplicitTlsTls>,
}

/// V2ExplicitTLS controls some vanity/stylistic elements when converting from v3alpha1 to v2.  The values in an V2ExplicitTLS should not in any way affect the runtime operation of Emissary; except that it may affect internal names in the Envoy config, which may in turn affect stats names.  But it should not affect any end-user observable behavior.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum TCPMappingV2ExplicitTlsTls {
    #[serde(rename = "")]
    KopiumEmpty,
    #[serde(rename = "null")]
    Null,
    #[serde(rename = "bool:true")]
    BoolTrue,
    #[serde(rename = "bool:false")]
    BoolFalse,
    #[serde(rename = "string")]
    String,
}

