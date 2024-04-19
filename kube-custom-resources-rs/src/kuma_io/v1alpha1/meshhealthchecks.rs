// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kumahq/kuma/kuma.io/v1alpha1/meshhealthchecks.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

/// Spec is the specification of the Kuma MeshHealthCheck resource.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "kuma.io", version = "v1alpha1", kind = "MeshHealthCheck", plural = "meshhealthchecks")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct MeshHealthCheckSpec {
    /// TargetRef is a reference to the resource the policy takes an effect on.
    /// The resource could be either a real store object or virtual resource
    /// defined inplace.
    #[serde(rename = "targetRef")]
    pub target_ref: MeshHealthCheckTargetRef,
    /// To list makes a match between the consumed services and corresponding configurations
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<Vec<MeshHealthCheckTo>>,
}

/// TargetRef is a reference to the resource the policy takes an effect on.
/// The resource could be either a real store object or virtual resource
/// defined inplace.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MeshHealthCheckTargetRef {
    /// Kind of the referenced resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<MeshHealthCheckTargetRefKind>,
    /// Mesh is reserved for future use to identify cross mesh resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh: Option<String>,
    /// Name of the referenced resource. Can only be used with kinds: `MeshService`,
    /// `MeshServiceSubset` and `MeshGatewayRoute`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// ProxyTypes specifies the data plane types that are subject to the policy. When not specified,
    /// all data plane types are targeted by the policy.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "proxyTypes")]
    pub proxy_types: Option<Vec<String>>,
    /// Tags used to select a subset of proxies by tags. Can only be used with kinds
    /// `MeshSubset` and `MeshServiceSubset`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,
}

/// TargetRef is a reference to the resource the policy takes an effect on.
/// The resource could be either a real store object or virtual resource
/// defined inplace.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum MeshHealthCheckTargetRefKind {
    Mesh,
    MeshSubset,
    MeshGateway,
    MeshService,
    MeshServiceSubset,
    #[serde(rename = "MeshHTTPRoute")]
    MeshHttpRoute,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MeshHealthCheckTo {
    /// Default is a configuration specific to the group of destinations referenced in
    /// 'targetRef'
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<MeshHealthCheckToDefault>,
    /// TargetRef is a reference to the resource that represents a group of
    /// destinations.
    #[serde(rename = "targetRef")]
    pub target_ref: MeshHealthCheckToTargetRef,
}

/// Default is a configuration specific to the group of destinations referenced in
/// 'targetRef'
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MeshHealthCheckToDefault {
    /// If set to true, health check failure events will always be logged. If set
    /// to false, only the initial health check failure event will be logged. The
    /// default value is false.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "alwaysLogHealthCheckFailures")]
    pub always_log_health_check_failures: Option<bool>,
    /// Specifies the path to the file where Envoy can log health check events.
    /// If empty, no event log will be written.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "eventLogPath")]
    pub event_log_path: Option<String>,
    /// If set to true, Envoy will not consider any hosts when the cluster is in
    /// 'panic mode'. Instead, the cluster will fail all requests as if all hosts
    /// are unhealthy. This can help avoid potentially overwhelming a failing
    /// service.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "failTrafficOnPanic")]
    pub fail_traffic_on_panic: Option<bool>,
    /// GrpcHealthCheck defines gRPC configuration which will instruct the service
    /// the health check will be made for is a gRPC service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc: Option<MeshHealthCheckToDefaultGrpc>,
    /// Allows to configure panic threshold for Envoy cluster. If not specified,
    /// the default is 50%. To disable panic mode, set to 0%.
    /// Either int or decimal represented as string.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "healthyPanicThreshold")]
    pub healthy_panic_threshold: Option<IntOrString>,
    /// Number of consecutive healthy checks before considering a host healthy.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "healthyThreshold")]
    pub healthy_threshold: Option<i32>,
    /// HttpHealthCheck defines HTTP configuration which will instruct the service
    /// the health check will be made for is an HTTP service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<MeshHealthCheckToDefaultHttp>,
    /// If specified, Envoy will start health checking after a random time in
    /// ms between 0 and initialJitter. This only applies to the first health
    /// check.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "initialJitter")]
    pub initial_jitter: Option<String>,
    /// Interval between consecutive health checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,
    /// If specified, during every interval Envoy will add IntervalJitter to the
    /// wait time.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "intervalJitter")]
    pub interval_jitter: Option<String>,
    /// If specified, during every interval Envoy will add IntervalJitter *
    /// IntervalJitterPercent / 100 to the wait time. If IntervalJitter and
    /// IntervalJitterPercent are both set, both of them will be used to
    /// increase the wait time.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "intervalJitterPercent")]
    pub interval_jitter_percent: Option<i32>,
    /// The "no traffic interval" is a special health check interval that is used
    /// when a cluster has never had traffic routed to it. This lower interval
    /// allows cluster information to be kept up to date, without sending a
    /// potentially large amount of active health checking traffic for no reason.
    /// Once a cluster has been used for traffic routing, Envoy will shift back
    /// to using the standard health check interval that is defined. Note that
    /// this interval takes precedence over any other. The default value for "no
    /// traffic interval" is 60 seconds.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "noTrafficInterval")]
    pub no_traffic_interval: Option<String>,
    /// Reuse health check connection between health checks. Default is true.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "reuseConnection")]
    pub reuse_connection: Option<bool>,
    /// TcpHealthCheck defines configuration for specifying bytes to send and
    /// expected response during the health check
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp: Option<MeshHealthCheckToDefaultTcp>,
    /// Maximum time to wait for a health check response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
    /// Number of consecutive unhealthy checks before considering a host
    /// unhealthy.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "unhealthyThreshold")]
    pub unhealthy_threshold: Option<i32>,
}

/// GrpcHealthCheck defines gRPC configuration which will instruct the service
/// the health check will be made for is a gRPC service.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MeshHealthCheckToDefaultGrpc {
    /// The value of the :authority header in the gRPC health check request,
    /// by default name of the cluster this health check is associated with
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    /// If true the GrpcHealthCheck is disabled
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    /// Service name parameter which will be sent to gRPC service
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "serviceName")]
    pub service_name: Option<String>,
}

/// HttpHealthCheck defines HTTP configuration which will instruct the service
/// the health check will be made for is an HTTP service.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MeshHealthCheckToDefaultHttp {
    /// If true the HttpHealthCheck is disabled
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    /// List of HTTP response statuses which are considered healthy
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "expectedStatuses")]
    pub expected_statuses: Option<Vec<i64>>,
    /// The HTTP path which will be requested during the health check
    /// (ie. /health)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The list of HTTP headers which should be added to each health check
    /// request
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "requestHeadersToAdd")]
    pub request_headers_to_add: Option<MeshHealthCheckToDefaultHttpRequestHeadersToAdd>,
}

/// The list of HTTP headers which should be added to each health check
/// request
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MeshHealthCheckToDefaultHttpRequestHeadersToAdd {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add: Option<Vec<MeshHealthCheckToDefaultHttpRequestHeadersToAddAdd>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set: Option<Vec<MeshHealthCheckToDefaultHttpRequestHeadersToAddSet>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MeshHealthCheckToDefaultHttpRequestHeadersToAddAdd {
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MeshHealthCheckToDefaultHttpRequestHeadersToAddSet {
    pub name: String,
    pub value: String,
}

/// TcpHealthCheck defines configuration for specifying bytes to send and
/// expected response during the health check
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MeshHealthCheckToDefaultTcp {
    /// If true the TcpHealthCheck is disabled
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    /// List of Base64 encoded blocks of strings expected as a response. When checking the response,
    /// "fuzzy" matching is performed such that each block must be found, and
    /// in the order specified, but not necessarily contiguous.
    /// If not provided or empty, checks will be performed as "connect only" and be marked as successful when TCP connection is successfully established.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receive: Option<Vec<String>>,
    /// Base64 encoded content of the message which will be sent during the health check to the target
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send: Option<String>,
}

/// TargetRef is a reference to the resource that represents a group of
/// destinations.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MeshHealthCheckToTargetRef {
    /// Kind of the referenced resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<MeshHealthCheckToTargetRefKind>,
    /// Mesh is reserved for future use to identify cross mesh resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh: Option<String>,
    /// Name of the referenced resource. Can only be used with kinds: `MeshService`,
    /// `MeshServiceSubset` and `MeshGatewayRoute`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// ProxyTypes specifies the data plane types that are subject to the policy. When not specified,
    /// all data plane types are targeted by the policy.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "proxyTypes")]
    pub proxy_types: Option<Vec<String>>,
    /// Tags used to select a subset of proxies by tags. Can only be used with kinds
    /// `MeshSubset` and `MeshServiceSubset`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,
}

/// TargetRef is a reference to the resource that represents a group of
/// destinations.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum MeshHealthCheckToTargetRefKind {
    Mesh,
    MeshSubset,
    MeshGateway,
    MeshService,
    MeshServiceSubset,
    #[serde(rename = "MeshHTTPRoute")]
    MeshHttpRoute,
}

