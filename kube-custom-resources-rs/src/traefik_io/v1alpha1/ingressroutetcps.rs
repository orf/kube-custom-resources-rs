// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/traefik/traefik/traefik.io/v1alpha1/ingressroutetcps.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

/// IngressRouteTCPSpec defines the desired state of IngressRouteTCP.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "traefik.io", version = "v1alpha1", kind = "IngressRouteTCP", plural = "ingressroutetcps")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct IngressRouteTCPSpec {
    /// EntryPoints defines the list of entry point names to bind to.
    /// Entry points have to be configured in the static configuration.
    /// More info: https://doc.traefik.io/traefik/v3.0/routing/entrypoints/
    /// Default: all.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "entryPoints")]
    pub entry_points: Option<Vec<String>>,
    /// Routes defines the list of routes.
    pub routes: Vec<IngressRouteTCPRoutes>,
    /// TLS defines the TLS configuration on a layer 4 / TCP Route.
    /// More info: https://doc.traefik.io/traefik/v3.0/routing/routers/#tls_1
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<IngressRouteTCPTls>,
}

/// RouteTCP holds the TCP route configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct IngressRouteTCPRoutes {
    /// Match defines the router's rule.
    /// More info: https://doc.traefik.io/traefik/v3.0/routing/routers/#rule_1
    #[serde(rename = "match")]
    pub r#match: String,
    /// Middlewares defines the list of references to MiddlewareTCP resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub middlewares: Option<Vec<IngressRouteTCPRoutesMiddlewares>>,
    /// Priority defines the router's priority.
    /// More info: https://doc.traefik.io/traefik/v3.0/routing/routers/#priority_1
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<i64>,
    /// Services defines the list of TCP services.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<IngressRouteTCPRoutesServices>>,
    /// Syntax defines the router's rule syntax.
    /// More info: https://doc.traefik.io/traefik/v3.0/routing/routers/#rulesyntax_1
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syntax: Option<String>,
}

/// ObjectReference is a generic reference to a Traefik resource.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct IngressRouteTCPRoutesMiddlewares {
    /// Name defines the name of the referenced Traefik resource.
    pub name: String,
    /// Namespace defines the namespace of the referenced Traefik resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// ServiceTCP defines an upstream TCP service to proxy traffic to.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct IngressRouteTCPRoutesServices {
    /// Name defines the name of the referenced Kubernetes Service.
    pub name: String,
    /// Namespace defines the namespace of the referenced Kubernetes Service.
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
    /// Port defines the port of a Kubernetes Service.
    /// This can be a reference to a named port.
    pub port: IntOrString,
    /// ProxyProtocol defines the PROXY protocol configuration.
    /// More info: https://doc.traefik.io/traefik/v3.0/routing/services/#proxy-protocol
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "proxyProtocol")]
    pub proxy_protocol: Option<IngressRouteTCPRoutesServicesProxyProtocol>,
    /// ServersTransport defines the name of ServersTransportTCP resource to use.
    /// It allows to configure the transport between Traefik and your servers.
    /// Can only be used on a Kubernetes Service.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "serversTransport")]
    pub servers_transport: Option<String>,
    /// TerminationDelay defines the deadline that the proxy sets, after one of its connected peers indicates
    /// it has closed the writing capability of its connection, to close the reading capability as well,
    /// hence fully terminating the connection.
    /// It is a duration in milliseconds, defaulting to 100.
    /// A negative value means an infinite deadline (i.e. the reading capability is never closed).
    /// Deprecated: TerminationDelay is not supported APIVersion traefik.io/v1, please use ServersTransport to configure the TerminationDelay instead.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "terminationDelay")]
    pub termination_delay: Option<i64>,
    /// TLS determines whether to use TLS when dialing with the backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<bool>,
    /// Weight defines the weight used when balancing requests between multiple Kubernetes Service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<i64>,
}

/// ProxyProtocol defines the PROXY protocol configuration.
/// More info: https://doc.traefik.io/traefik/v3.0/routing/services/#proxy-protocol
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct IngressRouteTCPRoutesServicesProxyProtocol {
    /// Version defines the PROXY Protocol version to use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
}

/// TLS defines the TLS configuration on a layer 4 / TCP Route.
/// More info: https://doc.traefik.io/traefik/v3.0/routing/routers/#tls_1
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct IngressRouteTCPTls {
    /// CertResolver defines the name of the certificate resolver to use.
    /// Cert resolvers have to be configured in the static configuration.
    /// More info: https://doc.traefik.io/traefik/v3.0/https/acme/#certificate-resolvers
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "certResolver")]
    pub cert_resolver: Option<String>,
    /// Domains defines the list of domains that will be used to issue certificates.
    /// More info: https://doc.traefik.io/traefik/v3.0/routing/routers/#domains
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domains: Option<Vec<IngressRouteTCPTlsDomains>>,
    /// Options defines the reference to a TLSOption, that specifies the parameters of the TLS connection.
    /// If not defined, the `default` TLSOption is used.
    /// More info: https://doc.traefik.io/traefik/v3.0/https/tls/#tls-options
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<IngressRouteTCPTlsOptions>,
    /// Passthrough defines whether a TLS router will terminate the TLS connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passthrough: Option<bool>,
    /// SecretName is the name of the referenced Kubernetes Secret to specify the certificate details.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretName")]
    pub secret_name: Option<String>,
    /// Store defines the reference to the TLSStore, that will be used to store certificates.
    /// Please note that only `default` TLSStore can be used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<IngressRouteTCPTlsStore>,
}

/// Domain holds a domain name with SANs.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct IngressRouteTCPTlsDomains {
    /// Main defines the main domain name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main: Option<String>,
    /// SANs defines the subject alternative domain names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sans: Option<Vec<String>>,
}

/// Options defines the reference to a TLSOption, that specifies the parameters of the TLS connection.
/// If not defined, the `default` TLSOption is used.
/// More info: https://doc.traefik.io/traefik/v3.0/https/tls/#tls-options
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct IngressRouteTCPTlsOptions {
    /// Name defines the name of the referenced Traefik resource.
    pub name: String,
    /// Namespace defines the namespace of the referenced Traefik resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// Store defines the reference to the TLSStore, that will be used to store certificates.
/// Please note that only `default` TLSStore can be used.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct IngressRouteTCPTlsStore {
    /// Name defines the name of the referenced Traefik resource.
    pub name: String,
    /// Namespace defines the namespace of the referenced Traefik resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

