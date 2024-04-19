// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/traefik/traefik/traefik.io/v1alpha1/traefikservices.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

/// TraefikServiceSpec defines the desired state of a TraefikService.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "traefik.io", version = "v1alpha1", kind = "TraefikService", plural = "traefikservices")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct TraefikServiceSpec {
    /// Mirroring defines the Mirroring service configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirroring: Option<TraefikServiceMirroring>,
    /// Weighted defines the Weighted Round Robin configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weighted: Option<TraefikServiceWeighted>,
}

/// Mirroring defines the Mirroring service configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TraefikServiceMirroring {
    /// Kind defines the kind of the Service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<TraefikServiceMirroringKind>,
    /// MaxBodySize defines the maximum size allowed for the body of the request.
    /// If the body is larger, the request is not mirrored.
    /// Default value is -1, which means unlimited size.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxBodySize")]
    pub max_body_size: Option<i64>,
    /// Mirrors defines the list of mirrors where Traefik will duplicate the traffic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirrors: Option<Vec<TraefikServiceMirroringMirrors>>,
    /// Name defines the name of the referenced Kubernetes Service or TraefikService.
    /// The differentiation between the two is specified in the Kind field.
    pub name: String,
    /// Namespace defines the namespace of the referenced Kubernetes Service or TraefikService.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// NativeLB controls, when creating the load-balancer,
    /// whether the LB's children are directly the pods IPs or if the only child is the Kubernetes Service clusterIP.
    /// The Kubernetes Service itself does load-balance to the pods.
    /// By default, NativeLB is false.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nativeLB")]
    pub native_lb: Option<bool>,
    /// NodePortLB controls, when creating the load-balancer,
    /// whether the LB's children are directly the nodes internal IPs using the nodePort when the service type is NodePort.
    /// It allows services to be reachable when Traefik runs externally from the Kubernetes cluster but within the same network of the nodes.
    /// By default, NodePortLB is false.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nodePortLB")]
    pub node_port_lb: Option<bool>,
    /// PassHostHeader defines whether the client Host header is forwarded to the upstream Kubernetes Service.
    /// By default, passHostHeader is true.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "passHostHeader")]
    pub pass_host_header: Option<bool>,
    /// Port defines the port of a Kubernetes Service.
    /// This can be a reference to a named port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<IntOrString>,
    /// ResponseForwarding defines how Traefik forwards the response from the upstream Kubernetes Service to the client.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "responseForwarding")]
    pub response_forwarding: Option<TraefikServiceMirroringResponseForwarding>,
    /// Scheme defines the scheme to use for the request to the upstream Kubernetes Service.
    /// It defaults to https when Kubernetes Service port is 443, http otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// ServersTransport defines the name of ServersTransport resource to use.
    /// It allows to configure the transport between Traefik and your servers.
    /// Can only be used on a Kubernetes Service.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "serversTransport")]
    pub servers_transport: Option<String>,
    /// Sticky defines the sticky sessions configuration.
    /// More info: https://doc.traefik.io/traefik/v3.0/routing/services/#sticky-sessions
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sticky: Option<TraefikServiceMirroringSticky>,
    /// Strategy defines the load balancing strategy between the servers.
    /// RoundRobin is the only supported value at the moment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,
    /// Weight defines the weight and should only be specified when Name references a TraefikService object
    /// (and to be precise, one that embeds a Weighted Round Robin).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<i64>,
}

/// Mirroring defines the Mirroring service configuration.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum TraefikServiceMirroringKind {
    Service,
    TraefikService,
}

/// MirrorService holds the mirror configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TraefikServiceMirroringMirrors {
    /// Kind defines the kind of the Service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<TraefikServiceMirroringMirrorsKind>,
    /// Name defines the name of the referenced Kubernetes Service or TraefikService.
    /// The differentiation between the two is specified in the Kind field.
    pub name: String,
    /// Namespace defines the namespace of the referenced Kubernetes Service or TraefikService.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// NativeLB controls, when creating the load-balancer,
    /// whether the LB's children are directly the pods IPs or if the only child is the Kubernetes Service clusterIP.
    /// The Kubernetes Service itself does load-balance to the pods.
    /// By default, NativeLB is false.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nativeLB")]
    pub native_lb: Option<bool>,
    /// NodePortLB controls, when creating the load-balancer,
    /// whether the LB's children are directly the nodes internal IPs using the nodePort when the service type is NodePort.
    /// It allows services to be reachable when Traefik runs externally from the Kubernetes cluster but within the same network of the nodes.
    /// By default, NodePortLB is false.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nodePortLB")]
    pub node_port_lb: Option<bool>,
    /// PassHostHeader defines whether the client Host header is forwarded to the upstream Kubernetes Service.
    /// By default, passHostHeader is true.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "passHostHeader")]
    pub pass_host_header: Option<bool>,
    /// Percent defines the part of the traffic to mirror.
    /// Supported values: 0 to 100.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub percent: Option<i64>,
    /// Port defines the port of a Kubernetes Service.
    /// This can be a reference to a named port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<IntOrString>,
    /// ResponseForwarding defines how Traefik forwards the response from the upstream Kubernetes Service to the client.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "responseForwarding")]
    pub response_forwarding: Option<TraefikServiceMirroringMirrorsResponseForwarding>,
    /// Scheme defines the scheme to use for the request to the upstream Kubernetes Service.
    /// It defaults to https when Kubernetes Service port is 443, http otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// ServersTransport defines the name of ServersTransport resource to use.
    /// It allows to configure the transport between Traefik and your servers.
    /// Can only be used on a Kubernetes Service.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "serversTransport")]
    pub servers_transport: Option<String>,
    /// Sticky defines the sticky sessions configuration.
    /// More info: https://doc.traefik.io/traefik/v3.0/routing/services/#sticky-sessions
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sticky: Option<TraefikServiceMirroringMirrorsSticky>,
    /// Strategy defines the load balancing strategy between the servers.
    /// RoundRobin is the only supported value at the moment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,
    /// Weight defines the weight and should only be specified when Name references a TraefikService object
    /// (and to be precise, one that embeds a Weighted Round Robin).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<i64>,
}

/// MirrorService holds the mirror configuration.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum TraefikServiceMirroringMirrorsKind {
    Service,
    TraefikService,
}

/// ResponseForwarding defines how Traefik forwards the response from the upstream Kubernetes Service to the client.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TraefikServiceMirroringMirrorsResponseForwarding {
    /// FlushInterval defines the interval, in milliseconds, in between flushes to the client while copying the response body.
    /// A negative value means to flush immediately after each write to the client.
    /// This configuration is ignored when ReverseProxy recognizes a response as a streaming response;
    /// for such responses, writes are flushed to the client immediately.
    /// Default: 100ms
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "flushInterval")]
    pub flush_interval: Option<String>,
}

/// Sticky defines the sticky sessions configuration.
/// More info: https://doc.traefik.io/traefik/v3.0/routing/services/#sticky-sessions
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TraefikServiceMirroringMirrorsSticky {
    /// Cookie defines the sticky cookie configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie: Option<TraefikServiceMirroringMirrorsStickyCookie>,
}

/// Cookie defines the sticky cookie configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TraefikServiceMirroringMirrorsStickyCookie {
    /// HTTPOnly defines whether the cookie can be accessed by client-side APIs, such as JavaScript.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "httpOnly")]
    pub http_only: Option<bool>,
    /// MaxAge indicates the number of seconds until the cookie expires.
    /// When set to a negative number, the cookie expires immediately.
    /// When set to zero, the cookie never expires.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxAge")]
    pub max_age: Option<i64>,
    /// Name defines the Cookie name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// SameSite defines the same site policy.
    /// More info: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sameSite")]
    pub same_site: Option<String>,
    /// Secure defines whether the cookie can only be transmitted over an encrypted connection (i.e. HTTPS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secure: Option<bool>,
}

/// ResponseForwarding defines how Traefik forwards the response from the upstream Kubernetes Service to the client.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TraefikServiceMirroringResponseForwarding {
    /// FlushInterval defines the interval, in milliseconds, in between flushes to the client while copying the response body.
    /// A negative value means to flush immediately after each write to the client.
    /// This configuration is ignored when ReverseProxy recognizes a response as a streaming response;
    /// for such responses, writes are flushed to the client immediately.
    /// Default: 100ms
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "flushInterval")]
    pub flush_interval: Option<String>,
}

/// Sticky defines the sticky sessions configuration.
/// More info: https://doc.traefik.io/traefik/v3.0/routing/services/#sticky-sessions
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TraefikServiceMirroringSticky {
    /// Cookie defines the sticky cookie configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie: Option<TraefikServiceMirroringStickyCookie>,
}

/// Cookie defines the sticky cookie configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TraefikServiceMirroringStickyCookie {
    /// HTTPOnly defines whether the cookie can be accessed by client-side APIs, such as JavaScript.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "httpOnly")]
    pub http_only: Option<bool>,
    /// MaxAge indicates the number of seconds until the cookie expires.
    /// When set to a negative number, the cookie expires immediately.
    /// When set to zero, the cookie never expires.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxAge")]
    pub max_age: Option<i64>,
    /// Name defines the Cookie name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// SameSite defines the same site policy.
    /// More info: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sameSite")]
    pub same_site: Option<String>,
    /// Secure defines whether the cookie can only be transmitted over an encrypted connection (i.e. HTTPS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secure: Option<bool>,
}

/// Weighted defines the Weighted Round Robin configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TraefikServiceWeighted {
    /// Services defines the list of Kubernetes Service and/or TraefikService to load-balance, with weight.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<TraefikServiceWeightedServices>>,
    /// Sticky defines whether sticky sessions are enabled.
    /// More info: https://doc.traefik.io/traefik/v3.0/routing/providers/kubernetes-crd/#stickiness-and-load-balancing
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sticky: Option<TraefikServiceWeightedSticky>,
}

/// Service defines an upstream HTTP service to proxy traffic to.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TraefikServiceWeightedServices {
    /// Kind defines the kind of the Service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<TraefikServiceWeightedServicesKind>,
    /// Name defines the name of the referenced Kubernetes Service or TraefikService.
    /// The differentiation between the two is specified in the Kind field.
    pub name: String,
    /// Namespace defines the namespace of the referenced Kubernetes Service or TraefikService.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// NativeLB controls, when creating the load-balancer,
    /// whether the LB's children are directly the pods IPs or if the only child is the Kubernetes Service clusterIP.
    /// The Kubernetes Service itself does load-balance to the pods.
    /// By default, NativeLB is false.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nativeLB")]
    pub native_lb: Option<bool>,
    /// NodePortLB controls, when creating the load-balancer,
    /// whether the LB's children are directly the nodes internal IPs using the nodePort when the service type is NodePort.
    /// It allows services to be reachable when Traefik runs externally from the Kubernetes cluster but within the same network of the nodes.
    /// By default, NodePortLB is false.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nodePortLB")]
    pub node_port_lb: Option<bool>,
    /// PassHostHeader defines whether the client Host header is forwarded to the upstream Kubernetes Service.
    /// By default, passHostHeader is true.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "passHostHeader")]
    pub pass_host_header: Option<bool>,
    /// Port defines the port of a Kubernetes Service.
    /// This can be a reference to a named port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<IntOrString>,
    /// ResponseForwarding defines how Traefik forwards the response from the upstream Kubernetes Service to the client.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "responseForwarding")]
    pub response_forwarding: Option<TraefikServiceWeightedServicesResponseForwarding>,
    /// Scheme defines the scheme to use for the request to the upstream Kubernetes Service.
    /// It defaults to https when Kubernetes Service port is 443, http otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// ServersTransport defines the name of ServersTransport resource to use.
    /// It allows to configure the transport between Traefik and your servers.
    /// Can only be used on a Kubernetes Service.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "serversTransport")]
    pub servers_transport: Option<String>,
    /// Sticky defines the sticky sessions configuration.
    /// More info: https://doc.traefik.io/traefik/v3.0/routing/services/#sticky-sessions
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sticky: Option<TraefikServiceWeightedServicesSticky>,
    /// Strategy defines the load balancing strategy between the servers.
    /// RoundRobin is the only supported value at the moment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,
    /// Weight defines the weight and should only be specified when Name references a TraefikService object
    /// (and to be precise, one that embeds a Weighted Round Robin).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<i64>,
}

/// Service defines an upstream HTTP service to proxy traffic to.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum TraefikServiceWeightedServicesKind {
    Service,
    TraefikService,
}

/// ResponseForwarding defines how Traefik forwards the response from the upstream Kubernetes Service to the client.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TraefikServiceWeightedServicesResponseForwarding {
    /// FlushInterval defines the interval, in milliseconds, in between flushes to the client while copying the response body.
    /// A negative value means to flush immediately after each write to the client.
    /// This configuration is ignored when ReverseProxy recognizes a response as a streaming response;
    /// for such responses, writes are flushed to the client immediately.
    /// Default: 100ms
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "flushInterval")]
    pub flush_interval: Option<String>,
}

/// Sticky defines the sticky sessions configuration.
/// More info: https://doc.traefik.io/traefik/v3.0/routing/services/#sticky-sessions
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TraefikServiceWeightedServicesSticky {
    /// Cookie defines the sticky cookie configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie: Option<TraefikServiceWeightedServicesStickyCookie>,
}

/// Cookie defines the sticky cookie configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TraefikServiceWeightedServicesStickyCookie {
    /// HTTPOnly defines whether the cookie can be accessed by client-side APIs, such as JavaScript.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "httpOnly")]
    pub http_only: Option<bool>,
    /// MaxAge indicates the number of seconds until the cookie expires.
    /// When set to a negative number, the cookie expires immediately.
    /// When set to zero, the cookie never expires.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxAge")]
    pub max_age: Option<i64>,
    /// Name defines the Cookie name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// SameSite defines the same site policy.
    /// More info: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sameSite")]
    pub same_site: Option<String>,
    /// Secure defines whether the cookie can only be transmitted over an encrypted connection (i.e. HTTPS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secure: Option<bool>,
}

/// Sticky defines whether sticky sessions are enabled.
/// More info: https://doc.traefik.io/traefik/v3.0/routing/providers/kubernetes-crd/#stickiness-and-load-balancing
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TraefikServiceWeightedSticky {
    /// Cookie defines the sticky cookie configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie: Option<TraefikServiceWeightedStickyCookie>,
}

/// Cookie defines the sticky cookie configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TraefikServiceWeightedStickyCookie {
    /// HTTPOnly defines whether the cookie can be accessed by client-side APIs, such as JavaScript.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "httpOnly")]
    pub http_only: Option<bool>,
    /// MaxAge indicates the number of seconds until the cookie expires.
    /// When set to a negative number, the cookie expires immediately.
    /// When set to zero, the cookie never expires.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxAge")]
    pub max_age: Option<i64>,
    /// Name defines the Cookie name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// SameSite defines the same site policy.
    /// More info: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sameSite")]
    pub same_site: Option<String>,
    /// Secure defines whether the cookie can only be transmitted over an encrypted connection (i.e. HTTPS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secure: Option<bool>,
}

