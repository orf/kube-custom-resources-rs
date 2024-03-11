// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/projectcontour/contour/projectcontour.io/v1alpha1/extensionservices.yaml --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// ExtensionServiceSpec defines the desired state of an ExtensionService resource.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "projectcontour.io", version = "v1alpha1", kind = "ExtensionService", plural = "extensionservices")]
#[kube(namespaced)]
#[kube(status = "ExtensionServiceStatus")]
#[kube(schema = "disabled")]
pub struct ExtensionServiceSpec {
    /// The policy for load balancing GRPC service requests. Note that the
    /// `Cookie` and `RequestHash` load balancing strategies cannot be used
    /// here.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "loadBalancerPolicy")]
    pub load_balancer_policy: Option<ExtensionServiceLoadBalancerPolicy>,
    /// Protocol may be used to specify (or override) the protocol used to reach this Service.
    /// Values may be h2 or h2c. If omitted, protocol-selection falls back on Service annotations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<ExtensionServiceProtocol>,
    /// This field sets the version of the GRPC protocol that Envoy uses to
    /// send requests to the extension service. Since Contour always uses the
    /// v3 Envoy API, this is currently fixed at "v3". However, other
    /// protocol options will be available in future.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "protocolVersion")]
    pub protocol_version: Option<ExtensionServiceProtocolVersion>,
    /// Services specifies the set of Kubernetes Service resources that
    /// receive GRPC extension API requests.
    /// If no weights are specified for any of the entries in
    /// this array, traffic will be spread evenly across all the
    /// services.
    /// Otherwise, traffic is balanced proportionally to the
    /// Weight field in each entry.
    pub services: Vec<ExtensionServiceServices>,
    /// The timeout policy for requests to the services.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "timeoutPolicy")]
    pub timeout_policy: Option<ExtensionServiceTimeoutPolicy>,
    /// UpstreamValidation defines how to verify the backend service's certificate
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation: Option<ExtensionServiceValidation>,
}

/// The policy for load balancing GRPC service requests. Note that the
/// `Cookie` and `RequestHash` load balancing strategies cannot be used
/// here.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ExtensionServiceLoadBalancerPolicy {
    /// RequestHashPolicies contains a list of hash policies to apply when the
    /// `RequestHash` load balancing strategy is chosen. If an element of the
    /// supplied list of hash policies is invalid, it will be ignored. If the
    /// list of hash policies is empty after validation, the load balancing
    /// strategy will fall back to the default `RoundRobin`.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "requestHashPolicies")]
    pub request_hash_policies: Option<Vec<ExtensionServiceLoadBalancerPolicyRequestHashPolicies>>,
    /// Strategy specifies the policy used to balance requests
    /// across the pool of backend pods. Valid policy names are
    /// `Random`, `RoundRobin`, `WeightedLeastRequest`, `Cookie`,
    /// and `RequestHash`. If an unknown strategy name is specified
    /// or no policy is supplied, the default `RoundRobin` policy
    /// is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,
}

/// RequestHashPolicy contains configuration for an individual hash policy
/// on a request attribute.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ExtensionServiceLoadBalancerPolicyRequestHashPolicies {
    /// HashSourceIP should be set to true when request source IP hash based
    /// load balancing is desired. It must be the only hash option field set,
    /// otherwise this request hash policy object will be ignored.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "hashSourceIP")]
    pub hash_source_ip: Option<bool>,
    /// HeaderHashOptions should be set when request header hash based load
    /// balancing is desired. It must be the only hash option field set,
    /// otherwise this request hash policy object will be ignored.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "headerHashOptions")]
    pub header_hash_options: Option<ExtensionServiceLoadBalancerPolicyRequestHashPoliciesHeaderHashOptions>,
    /// QueryParameterHashOptions should be set when request query parameter hash based load
    /// balancing is desired. It must be the only hash option field set,
    /// otherwise this request hash policy object will be ignored.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "queryParameterHashOptions")]
    pub query_parameter_hash_options: Option<ExtensionServiceLoadBalancerPolicyRequestHashPoliciesQueryParameterHashOptions>,
    /// Terminal is a flag that allows for short-circuiting computing of a hash
    /// for a given request. If set to true, and the request attribute specified
    /// in the attribute hash options is present, no further hash policies will
    /// be used to calculate a hash for the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<bool>,
}

/// HeaderHashOptions should be set when request header hash based load
/// balancing is desired. It must be the only hash option field set,
/// otherwise this request hash policy object will be ignored.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ExtensionServiceLoadBalancerPolicyRequestHashPoliciesHeaderHashOptions {
    /// HeaderName is the name of the HTTP request header that will be used to
    /// calculate the hash key. If the header specified is not present on a
    /// request, no hash will be produced.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "headerName")]
    pub header_name: Option<String>,
}

/// QueryParameterHashOptions should be set when request query parameter hash based load
/// balancing is desired. It must be the only hash option field set,
/// otherwise this request hash policy object will be ignored.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ExtensionServiceLoadBalancerPolicyRequestHashPoliciesQueryParameterHashOptions {
    /// ParameterName is the name of the HTTP request query parameter that will be used to
    /// calculate the hash key. If the query parameter specified is not present on a
    /// request, no hash will be produced.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "parameterName")]
    pub parameter_name: Option<String>,
}

/// ExtensionServiceSpec defines the desired state of an ExtensionService resource.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ExtensionServiceProtocol {
    #[serde(rename = "h2")]
    H2,
    #[serde(rename = "h2c")]
    H2c,
}

/// ExtensionServiceSpec defines the desired state of an ExtensionService resource.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ExtensionServiceProtocolVersion {
    #[serde(rename = "v3")]
    V3,
}

/// ExtensionServiceTarget defines an Kubernetes Service to target with
/// extension service traffic.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ExtensionServiceServices {
    /// Name is the name of Kubernetes service that will accept service
    /// traffic.
    pub name: String,
    /// Port (defined as Integer) to proxy traffic to since a service can have multiple defined.
    pub port: i64,
    /// Weight defines proportion of traffic to balance to the Kubernetes Service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<i32>,
}

/// The timeout policy for requests to the services.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ExtensionServiceTimeoutPolicy {
    /// Timeout for how long the proxy should wait while there is no activity during single request/response (for HTTP/1.1) or stream (for HTTP/2).
    /// Timeout will not trigger while HTTP/1.1 connection is idle between two consecutive requests.
    /// If not specified, there is no per-route idle timeout, though a connection manager-wide
    /// stream_idle_timeout default of 5m still applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle: Option<String>,
    /// Timeout for how long connection from the proxy to the upstream service is kept when there are no active requests.
    /// If not supplied, Envoy's default value of 1h applies.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "idleConnection")]
    pub idle_connection: Option<String>,
    /// Timeout for receiving a response from the server after processing a request from client.
    /// If not supplied, Envoy's default value of 15s applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
}

/// UpstreamValidation defines how to verify the backend service's certificate
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ExtensionServiceValidation {
    /// Name or namespaced name of the Kubernetes secret used to validate the certificate presented by the backend.
    /// The secret must contain key named ca.crt.
    /// The name can be optionally prefixed with namespace "namespace/name".
    /// When cross-namespace reference is used, TLSCertificateDelegation resource must exist in the namespace to grant access to the secret.
    /// Max length should be the actual max possible length of a namespaced name (63 + 253 + 1 = 317)
    #[serde(rename = "caSecret")]
    pub ca_secret: String,
    /// Key which is expected to be present in the 'subjectAltName' of the presented certificate.
    /// Deprecated: migrate to using the plural field subjectNames.
    #[serde(rename = "subjectName")]
    pub subject_name: String,
    /// List of keys, of which at least one is expected to be present in the 'subjectAltName of the
    /// presented certificate.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "subjectNames")]
    pub subject_names: Option<Vec<String>>,
}

/// ExtensionServiceStatus defines the observed state of an
/// ExtensionService resource.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ExtensionServiceStatus {
    /// Conditions contains the current status of the ExtensionService resource.
    /// Contour will update a single condition, `Valid`, that is in normal-true polarity.
    /// Contour will not modify any other Conditions set in this block,
    /// in case some other controller wants to add a Condition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
}

