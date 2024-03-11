// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/openshift/api/route.openshift.io/v1/routes.yaml --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// spec is the desired state of the route
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "route.openshift.io", version = "v1", kind = "Route", plural = "routes")]
#[kube(namespaced)]
#[kube(status = "RouteStatus")]
#[kube(schema = "disabled")]
pub struct RouteSpec {
    /// alternateBackends allows up to 3 additional backends to be assigned to the route. Only the Service kind is allowed, and it will be defaulted to Service. Use the weight field in RouteTargetReference object to specify relative preference.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "alternateBackends")]
    pub alternate_backends: Option<Vec<RouteAlternateBackends>>,
    /// host is an alias/DNS that points to the service. Optional. If not specified a route name will typically be automatically chosen. Must follow DNS952 subdomain conventions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// httpHeaders defines policy for HTTP headers.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "httpHeaders")]
    pub http_headers: Option<RouteHttpHeaders>,
    /// path that the router watches for, to route traffic for to the service. Optional
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// If specified, the port to be used by the router. Most routers will use all endpoints exposed by the service by default - set this value to instruct routers which port to use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<RoutePort>,
    /// subdomain is a DNS subdomain that is requested within the ingress controller's domain (as a subdomain). If host is set this field is ignored. An ingress controller may choose to ignore this suggested name, in which case the controller will report the assigned name in the status.ingress array or refuse to admit the route. If this value is set and the server does not support this field host will be populated automatically. Otherwise host is left empty. The field may have multiple parts separated by a dot, but not all ingress controllers may honor the request. This field may not be changed after creation except by a user with the update routes/custom-host permission. 
    ///  Example: subdomain `frontend` automatically receives the router subdomain `apps.mycluster.com` to have a full hostname `frontend.apps.mycluster.com`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subdomain: Option<String>,
    /// The tls field provides the ability to configure certificates and termination for the route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<RouteTls>,
    /// to is an object the route should use as the primary backend. Only the Service kind is allowed, and it will be defaulted to Service. If the weight field (0-256 default 100) is set to zero, no traffic will be sent to this backend.
    pub to: RouteTo,
    /// Wildcard policy if any for the route. Currently only 'Subdomain' or 'None' is allowed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "wildcardPolicy")]
    pub wildcard_policy: Option<RouteWildcardPolicy>,
}

/// RouteTargetReference specifies the target that resolve into endpoints. Only the 'Service' kind is allowed. Use 'weight' field to emphasize one over others.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RouteAlternateBackends {
    /// The kind of target that the route is referring to. Currently, only 'Service' is allowed
    pub kind: RouteAlternateBackendsKind,
    /// name of the service/target that is being referred to. e.g. name of the service
    pub name: String,
    /// weight as an integer between 0 and 256, default 100, that specifies the target's relative weight against other target reference objects. 0 suppresses requests to this backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<i32>,
}

/// RouteTargetReference specifies the target that resolve into endpoints. Only the 'Service' kind is allowed. Use 'weight' field to emphasize one over others.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum RouteAlternateBackendsKind {
    Service,
    #[serde(rename = "")]
    KopiumEmpty,
}

/// httpHeaders defines policy for HTTP headers.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RouteHttpHeaders {
    /// actions specifies options for modifying headers and their values. Note that this option only applies to cleartext HTTP connections and to secure HTTP connections for which the ingress controller terminates encryption (that is, edge-terminated or reencrypt connections).  Headers cannot be modified for TLS passthrough connections. Setting the HSTS (`Strict-Transport-Security`) header is not supported via actions. `Strict-Transport-Security` may only be configured using the "haproxy.router.openshift.io/hsts_header" route annotation, and only in accordance with the policy specified in Ingress.Spec.RequiredHSTSPolicies. In case of HTTP request headers, the actions specified in spec.httpHeaders.actions on the Route will be executed after the actions specified in the IngressController's spec.httpHeaders.actions field. In case of HTTP response headers, the actions specified in spec.httpHeaders.actions on the IngressController will be executed after the actions specified in the Route's spec.httpHeaders.actions field. The headers set via this API will not appear in access logs. Any actions defined here are applied after any actions related to the following other fields: cache-control, spec.clientTLS, spec.httpHeaders.forwardedHeaderPolicy, spec.httpHeaders.uniqueId, and spec.httpHeaders.headerNameCaseAdjustments. The following header names are reserved and may not be modified via this API: Strict-Transport-Security, Proxy, Cookie, Set-Cookie. Note that the total size of all net added headers *after* interpolating dynamic values must not exceed the value of spec.tuningOptions.headerBufferMaxRewriteBytes on the IngressController. Please refer to the documentation for that API field for more details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<RouteHttpHeadersActions>,
}

/// actions specifies options for modifying headers and their values. Note that this option only applies to cleartext HTTP connections and to secure HTTP connections for which the ingress controller terminates encryption (that is, edge-terminated or reencrypt connections).  Headers cannot be modified for TLS passthrough connections. Setting the HSTS (`Strict-Transport-Security`) header is not supported via actions. `Strict-Transport-Security` may only be configured using the "haproxy.router.openshift.io/hsts_header" route annotation, and only in accordance with the policy specified in Ingress.Spec.RequiredHSTSPolicies. In case of HTTP request headers, the actions specified in spec.httpHeaders.actions on the Route will be executed after the actions specified in the IngressController's spec.httpHeaders.actions field. In case of HTTP response headers, the actions specified in spec.httpHeaders.actions on the IngressController will be executed after the actions specified in the Route's spec.httpHeaders.actions field. The headers set via this API will not appear in access logs. Any actions defined here are applied after any actions related to the following other fields: cache-control, spec.clientTLS, spec.httpHeaders.forwardedHeaderPolicy, spec.httpHeaders.uniqueId, and spec.httpHeaders.headerNameCaseAdjustments. The following header names are reserved and may not be modified via this API: Strict-Transport-Security, Proxy, Cookie, Set-Cookie. Note that the total size of all net added headers *after* interpolating dynamic values must not exceed the value of spec.tuningOptions.headerBufferMaxRewriteBytes on the IngressController. Please refer to the documentation for that API field for more details.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RouteHttpHeadersActions {
    /// request is a list of HTTP request headers to modify. Currently, actions may define to either `Set` or `Delete` headers values. Actions defined here will modify the request headers of all requests made through a route. These actions are applied to a specific Route defined within a cluster i.e. connections made through a route. Currently, actions may define to either `Set` or `Delete` headers values. Route actions will be executed after IngressController actions for request headers. Actions are applied in sequence as defined in this list. A maximum of 20 request header actions may be configured. You can use this field to specify HTTP request headers that should be set or deleted when forwarding connections from the client to your application. Sample fetchers allowed are "req.hdr" and "ssl_c_der". Converters allowed are "lower" and "base64". Example header values: "%[req.hdr(X-target),lower]", "%{+Q}[ssl_c_der,base64]". Any request header configuration applied directly via a Route resource using this API will override header configuration for a header of the same name applied via spec.httpHeaders.actions on the IngressController or route annotation. Note: This field cannot be used if your route uses TLS passthrough.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<Vec<RouteHttpHeadersActionsRequest>>,
    /// response is a list of HTTP response headers to modify. Currently, actions may define to either `Set` or `Delete` headers values. Actions defined here will modify the response headers of all requests made through a route. These actions are applied to a specific Route defined within a cluster i.e. connections made through a route. Route actions will be executed before IngressController actions for response headers. Actions are applied in sequence as defined in this list. A maximum of 20 response header actions may be configured. You can use this field to specify HTTP response headers that should be set or deleted when forwarding responses from your application to the client. Sample fetchers allowed are "res.hdr" and "ssl_c_der". Converters allowed are "lower" and "base64". Example header values: "%[res.hdr(X-target),lower]", "%{+Q}[ssl_c_der,base64]". Note: This field cannot be used if your route uses TLS passthrough.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<Vec<RouteHttpHeadersActionsResponse>>,
}

/// RouteHTTPHeader specifies configuration for setting or deleting an HTTP header.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RouteHttpHeadersActionsRequest {
    /// action specifies actions to perform on headers, such as setting or deleting headers.
    pub action: RouteHttpHeadersActionsRequestAction,
    /// name specifies the name of a header on which to perform an action. Its value must be a valid HTTP header name as defined in RFC 2616 section 4.2. The name must consist only of alphanumeric and the following special characters, "-!#$%&'*+.^_`". The following header names are reserved and may not be modified via this API: Strict-Transport-Security, Proxy, Cookie, Set-Cookie. It must be no more than 255 characters in length. Header name must be unique.
    pub name: String,
}

/// action specifies actions to perform on headers, such as setting or deleting headers.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RouteHttpHeadersActionsRequestAction {
    /// set defines the HTTP header that should be set: added if it doesn't exist or replaced if it does. This field is required when type is Set and forbidden otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set: Option<RouteHttpHeadersActionsRequestActionSet>,
    /// type defines the type of the action to be applied on the header. Possible values are Set or Delete. Set allows you to set HTTP request and response headers. Delete allows you to delete HTTP request and response headers.
    #[serde(rename = "type")]
    pub r#type: RouteHttpHeadersActionsRequestActionType,
}

/// set defines the HTTP header that should be set: added if it doesn't exist or replaced if it does. This field is required when type is Set and forbidden otherwise.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RouteHttpHeadersActionsRequestActionSet {
    /// value specifies a header value. Dynamic values can be added. The value will be interpreted as an HAProxy format string as defined in http://cbonte.github.io/haproxy-dconv/2.6/configuration.html#8.2.6 and may use HAProxy's %[] syntax and otherwise must be a valid HTTP header value as defined in https://datatracker.ietf.org/doc/html/rfc7230#section-3.2. The value of this field must be no more than 16384 characters in length. Note that the total size of all net added headers *after* interpolating dynamic values must not exceed the value of spec.tuningOptions.headerBufferMaxRewriteBytes on the IngressController.
    pub value: String,
}

/// action specifies actions to perform on headers, such as setting or deleting headers.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum RouteHttpHeadersActionsRequestActionType {
    Set,
    Delete,
}

/// RouteHTTPHeader specifies configuration for setting or deleting an HTTP header.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RouteHttpHeadersActionsResponse {
    /// action specifies actions to perform on headers, such as setting or deleting headers.
    pub action: RouteHttpHeadersActionsResponseAction,
    /// name specifies the name of a header on which to perform an action. Its value must be a valid HTTP header name as defined in RFC 2616 section 4.2. The name must consist only of alphanumeric and the following special characters, "-!#$%&'*+.^_`". The following header names are reserved and may not be modified via this API: Strict-Transport-Security, Proxy, Cookie, Set-Cookie. It must be no more than 255 characters in length. Header name must be unique.
    pub name: String,
}

/// action specifies actions to perform on headers, such as setting or deleting headers.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RouteHttpHeadersActionsResponseAction {
    /// set defines the HTTP header that should be set: added if it doesn't exist or replaced if it does. This field is required when type is Set and forbidden otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set: Option<RouteHttpHeadersActionsResponseActionSet>,
    /// type defines the type of the action to be applied on the header. Possible values are Set or Delete. Set allows you to set HTTP request and response headers. Delete allows you to delete HTTP request and response headers.
    #[serde(rename = "type")]
    pub r#type: RouteHttpHeadersActionsResponseActionType,
}

/// set defines the HTTP header that should be set: added if it doesn't exist or replaced if it does. This field is required when type is Set and forbidden otherwise.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RouteHttpHeadersActionsResponseActionSet {
    /// value specifies a header value. Dynamic values can be added. The value will be interpreted as an HAProxy format string as defined in http://cbonte.github.io/haproxy-dconv/2.6/configuration.html#8.2.6 and may use HAProxy's %[] syntax and otherwise must be a valid HTTP header value as defined in https://datatracker.ietf.org/doc/html/rfc7230#section-3.2. The value of this field must be no more than 16384 characters in length. Note that the total size of all net added headers *after* interpolating dynamic values must not exceed the value of spec.tuningOptions.headerBufferMaxRewriteBytes on the IngressController.
    pub value: String,
}

/// action specifies actions to perform on headers, such as setting or deleting headers.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum RouteHttpHeadersActionsResponseActionType {
    Set,
    Delete,
}

/// If specified, the port to be used by the router. Most routers will use all endpoints exposed by the service by default - set this value to instruct routers which port to use.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RoutePort {
    #[serde(rename = "targetPort")]
    pub target_port: IntOrString,
}

/// The tls field provides the ability to configure certificates and termination for the route.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RouteTls {
    /// caCertificate provides the cert authority certificate contents
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "caCertificate")]
    pub ca_certificate: Option<String>,
    /// certificate provides certificate contents. This should be a single serving certificate, not a certificate chain. Do not include a CA certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    /// destinationCACertificate provides the contents of the ca certificate of the final destination.  When using reencrypt termination this file should be provided in order to have routers use it for health checks on the secure connection. If this field is not specified, the router may provide its own destination CA and perform hostname validation using the short service name (service.namespace.svc), which allows infrastructure generated certificates to automatically verify.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "destinationCACertificate")]
    pub destination_ca_certificate: Option<String>,
    /// insecureEdgeTerminationPolicy indicates the desired behavior for insecure connections to a route. While each router may make its own decisions on which ports to expose, this is normally port 80. 
    ///  * Allow - traffic is sent to the server on the insecure port (edge/reencrypt terminations only) (default). * None - no traffic is allowed on the insecure port. * Redirect - clients are redirected to the secure port.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "insecureEdgeTerminationPolicy")]
    pub insecure_edge_termination_policy: Option<RouteTlsInsecureEdgeTerminationPolicy>,
    /// key provides key file contents
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// termination indicates termination type. 
    ///  * edge - TLS termination is done by the router and http is used to communicate with the backend (default) * passthrough - Traffic is sent straight to the destination without the router providing TLS termination * reencrypt - TLS termination is done by the router and https is used to communicate with the backend 
    ///  Note: passthrough termination is incompatible with httpHeader actions
    pub termination: RouteTlsTermination,
}

/// The tls field provides the ability to configure certificates and termination for the route.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum RouteTlsInsecureEdgeTerminationPolicy {
    Allow,
    None,
    Redirect,
    #[serde(rename = "")]
    KopiumEmpty,
}

/// The tls field provides the ability to configure certificates and termination for the route.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum RouteTlsTermination {
    #[serde(rename = "edge")]
    Edge,
    #[serde(rename = "reencrypt")]
    Reencrypt,
    #[serde(rename = "passthrough")]
    Passthrough,
}

/// to is an object the route should use as the primary backend. Only the Service kind is allowed, and it will be defaulted to Service. If the weight field (0-256 default 100) is set to zero, no traffic will be sent to this backend.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RouteTo {
    /// The kind of target that the route is referring to. Currently, only 'Service' is allowed
    pub kind: RouteToKind,
    /// name of the service/target that is being referred to. e.g. name of the service
    pub name: String,
    /// weight as an integer between 0 and 256, default 100, that specifies the target's relative weight against other target reference objects. 0 suppresses requests to this backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<i32>,
}

/// to is an object the route should use as the primary backend. Only the Service kind is allowed, and it will be defaulted to Service. If the weight field (0-256 default 100) is set to zero, no traffic will be sent to this backend.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum RouteToKind {
    Service,
    #[serde(rename = "")]
    KopiumEmpty,
}

/// spec is the desired state of the route
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum RouteWildcardPolicy {
    None,
    Subdomain,
    #[serde(rename = "")]
    KopiumEmpty,
}

/// status is the current state of the route
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RouteStatus {
    /// ingress describes the places where the route may be exposed. The list of ingress points may contain duplicate Host or RouterName values. Routes are considered live once they are `Ready`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress: Option<Vec<RouteStatusIngress>>,
}

/// RouteIngress holds information about the places where a route is exposed.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RouteStatusIngress {
    /// Conditions is the state of the route, may be empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// Host is the host string under which the route is exposed; this value is required
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// CanonicalHostname is the external host name for the router that can be used as a CNAME for the host requested for this route. This value is optional and may not be set in all cases.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "routerCanonicalHostname")]
    pub router_canonical_hostname: Option<String>,
    /// Name is a name chosen by the router to identify itself; this value is required
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "routerName")]
    pub router_name: Option<String>,
    /// Wildcard policy is the wildcard policy that was allowed where this route is exposed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "wildcardPolicy")]
    pub wildcard_policy: Option<String>,
}

