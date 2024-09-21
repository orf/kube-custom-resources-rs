// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kubernetes-sigs/gateway-api/gateway.networking.k8s.io/v1alpha2/backendlbpolicies.yaml --derive=Default --derive=PartialEq --smart-derive-elision
// kopium version: 0.21.1

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
}
use self::prelude::*;

/// Spec defines the desired state of BackendLBPolicy.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "gateway.networking.k8s.io", version = "v1alpha2", kind = "BackendLBPolicy", plural = "backendlbpolicies")]
#[kube(namespaced)]
#[kube(status = "BackendLBPolicyStatus")]
#[kube(schema = "disabled")]
#[kube(derive="Default")]
#[kube(derive="PartialEq")]
pub struct BackendLBPolicySpec {
    /// SessionPersistence defines and configures session persistence
    /// for the backend.
    /// 
    /// Support: Extended
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sessionPersistence")]
    pub session_persistence: Option<BackendLBPolicySessionPersistence>,
    /// TargetRef identifies an API object to apply policy to.
    /// Currently, Backends (i.e. Service, ServiceImport, or any
    /// implementation-specific backendRef) are the only valid API
    /// target references.
    #[serde(rename = "targetRefs")]
    pub target_refs: Vec<BackendLBPolicyTargetRefs>,
}

/// SessionPersistence defines and configures session persistence
/// for the backend.
/// 
/// Support: Extended
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackendLBPolicySessionPersistence {
    /// AbsoluteTimeout defines the absolute timeout of the persistent
    /// session. Once the AbsoluteTimeout duration has elapsed, the
    /// session becomes invalid.
    /// 
    /// Support: Extended
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "absoluteTimeout")]
    pub absolute_timeout: Option<String>,
    /// CookieConfig provides configuration settings that are specific
    /// to cookie-based session persistence.
    /// 
    /// Support: Core
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "cookieConfig")]
    pub cookie_config: Option<BackendLBPolicySessionPersistenceCookieConfig>,
    /// IdleTimeout defines the idle timeout of the persistent session.
    /// Once the session has been idle for more than the specified
    /// IdleTimeout duration, the session becomes invalid.
    /// 
    /// Support: Extended
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "idleTimeout")]
    pub idle_timeout: Option<String>,
    /// SessionName defines the name of the persistent session token
    /// which may be reflected in the cookie or the header. Users
    /// should avoid reusing session names to prevent unintended
    /// consequences, such as rejection or unpredictable behavior.
    /// 
    /// Support: Implementation-specific
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sessionName")]
    pub session_name: Option<String>,
    /// Type defines the type of session persistence such as through
    /// the use a header or cookie. Defaults to cookie based session
    /// persistence.
    /// 
    /// Support: Core for "Cookie" type
    /// 
    /// Support: Extended for "Header" type
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<BackendLBPolicySessionPersistenceType>,
}

/// CookieConfig provides configuration settings that are specific
/// to cookie-based session persistence.
/// 
/// Support: Core
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackendLBPolicySessionPersistenceCookieConfig {
    /// LifetimeType specifies whether the cookie has a permanent or
    /// session-based lifetime. A permanent cookie persists until its
    /// specified expiry time, defined by the Expires or Max-Age cookie
    /// attributes, while a session cookie is deleted when the current
    /// session ends.
    /// 
    /// When set to "Permanent", AbsoluteTimeout indicates the
    /// cookie's lifetime via the Expires or Max-Age cookie attributes
    /// and is required.
    /// 
    /// When set to "Session", AbsoluteTimeout indicates the
    /// absolute lifetime of the cookie tracked by the gateway and
    /// is optional.
    /// 
    /// Support: Core for "Session" type
    /// 
    /// Support: Extended for "Permanent" type
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lifetimeType")]
    pub lifetime_type: Option<BackendLBPolicySessionPersistenceCookieConfigLifetimeType>,
}

/// CookieConfig provides configuration settings that are specific
/// to cookie-based session persistence.
/// 
/// Support: Core
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum BackendLBPolicySessionPersistenceCookieConfigLifetimeType {
    Permanent,
    Session,
}

/// SessionPersistence defines and configures session persistence
/// for the backend.
/// 
/// Support: Extended
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum BackendLBPolicySessionPersistenceType {
    Cookie,
    Header,
}

/// LocalPolicyTargetReference identifies an API object to apply a direct or
/// inherited policy to. This should be used as part of Policy resources
/// that can target Gateway API resources. For more information on how this
/// policy attachment model works, and a sample Policy resource, refer to
/// the policy attachment documentation for Gateway API.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackendLBPolicyTargetRefs {
    /// Group is the group of the target resource.
    pub group: String,
    /// Kind is kind of the target resource.
    pub kind: String,
    /// Name is the name of the target resource.
    pub name: String,
}

/// Status defines the current state of BackendLBPolicy.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackendLBPolicyStatus {
    /// Ancestors is a list of ancestor resources (usually Gateways) that are
    /// associated with the policy, and the status of the policy with respect to
    /// each ancestor. When this policy attaches to a parent, the controller that
    /// manages the parent and the ancestors MUST add an entry to this list when
    /// the controller first sees the policy and SHOULD update the entry as
    /// appropriate when the relevant ancestor is modified.
    /// 
    /// Note that choosing the relevant ancestor is left to the Policy designers;
    /// an important part of Policy design is designing the right object level at
    /// which to namespace this status.
    /// 
    /// Note also that implementations MUST ONLY populate ancestor status for
    /// the Ancestor resources they are responsible for. Implementations MUST
    /// use the ControllerName field to uniquely identify the entries in this list
    /// that they are responsible for.
    /// 
    /// Note that to achieve this, the list of PolicyAncestorStatus structs
    /// MUST be treated as a map with a composite key, made up of the AncestorRef
    /// and ControllerName fields combined.
    /// 
    /// A maximum of 16 ancestors will be represented in this list. An empty list
    /// means the Policy is not relevant for any ancestors.
    /// 
    /// If this slice is full, implementations MUST NOT add further entries.
    /// Instead they MUST consider the policy unimplementable and signal that
    /// on any related resources such as the ancestor that would be referenced
    /// here. For example, if this list was full on BackendTLSPolicy, no
    /// additional Gateways would be able to reference the Service targeted by
    /// the BackendTLSPolicy.
    pub ancestors: Vec<BackendLBPolicyStatusAncestors>,
}

/// PolicyAncestorStatus describes the status of a route with respect to an
/// associated Ancestor.
/// 
/// Ancestors refer to objects that are either the Target of a policy or above it
/// in terms of object hierarchy. For example, if a policy targets a Service, the
/// Policy's Ancestors are, in order, the Service, the HTTPRoute, the Gateway, and
/// the GatewayClass. Almost always, in this hierarchy, the Gateway will be the most
/// useful object to place Policy status on, so we recommend that implementations
/// SHOULD use Gateway as the PolicyAncestorStatus object unless the designers
/// have a _very_ good reason otherwise.
/// 
/// In the context of policy attachment, the Ancestor is used to distinguish which
/// resource results in a distinct application of this policy. For example, if a policy
/// targets a Service, it may have a distinct result per attached Gateway.
/// 
/// Policies targeting the same resource may have different effects depending on the
/// ancestors of those resources. For example, different Gateways targeting the same
/// Service may have different capabilities, especially if they have different underlying
/// implementations.
/// 
/// For example, in BackendTLSPolicy, the Policy attaches to a Service that is
/// used as a backend in a HTTPRoute that is itself attached to a Gateway.
/// In this case, the relevant object for status is the Gateway, and that is the
/// ancestor object referred to in this status.
/// 
/// Note that a parent is also an ancestor, so for objects where the parent is the
/// relevant object for status, this struct SHOULD still be used.
/// 
/// This struct is intended to be used in a slice that's effectively a map,
/// with a composite key made up of the AncestorRef and the ControllerName.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackendLBPolicyStatusAncestors {
    /// AncestorRef corresponds with a ParentRef in the spec that this
    /// PolicyAncestorStatus struct describes the status of.
    #[serde(rename = "ancestorRef")]
    pub ancestor_ref: BackendLBPolicyStatusAncestorsAncestorRef,
    /// Conditions describes the status of the Policy with respect to the given Ancestor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// ControllerName is a domain/path string that indicates the name of the
    /// controller that wrote this status. This corresponds with the
    /// controllerName field on GatewayClass.
    /// 
    /// Example: "example.net/gateway-controller".
    /// 
    /// The format of this field is DOMAIN "/" PATH, where DOMAIN and PATH are
    /// valid Kubernetes names
    /// (https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names).
    /// 
    /// Controllers MUST populate this field when writing status. Controllers should ensure that
    /// entries to status populated with their ControllerName are cleaned up when they are no
    /// longer necessary.
    #[serde(rename = "controllerName")]
    pub controller_name: String,
}

/// AncestorRef corresponds with a ParentRef in the spec that this
/// PolicyAncestorStatus struct describes the status of.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackendLBPolicyStatusAncestorsAncestorRef {
    /// Group is the group of the referent.
    /// When unspecified, "gateway.networking.k8s.io" is inferred.
    /// To set the core API group (such as for a "Service" kind referent),
    /// Group must be explicitly set to "" (empty string).
    /// 
    /// Support: Core
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Kind is kind of the referent.
    /// 
    /// There are two kinds of parent resources with "Core" support:
    /// 
    /// * Gateway (Gateway conformance profile)
    /// * Service (Mesh conformance profile, ClusterIP Services only)
    /// 
    /// Support for other resources is Implementation-Specific.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Name is the name of the referent.
    /// 
    /// Support: Core
    pub name: String,
    /// Namespace is the namespace of the referent. When unspecified, this refers
    /// to the local namespace of the Route.
    /// 
    /// Note that there are specific rules for ParentRefs which cross namespace
    /// boundaries. Cross-namespace references are only valid if they are explicitly
    /// allowed by something in the namespace they are referring to. For example:
    /// Gateway has the AllowedRoutes field, and ReferenceGrant provides a
    /// generic way to enable any other kind of cross-namespace reference.
    /// 
    /// 
    /// ParentRefs from a Route to a Service in the same namespace are "producer"
    /// routes, which apply default routing rules to inbound connections from
    /// any namespace to the Service.
    /// 
    /// ParentRefs from a Route to a Service in a different namespace are
    /// "consumer" routes, and these routing rules are only applied to outbound
    /// connections originating from the same namespace as the Route, for which
    /// the intended destination of the connections are a Service targeted as a
    /// ParentRef of the Route.
    /// 
    /// 
    /// Support: Core
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Port is the network port this Route targets. It can be interpreted
    /// differently based on the type of parent resource.
    /// 
    /// When the parent resource is a Gateway, this targets all listeners
    /// listening on the specified port that also support this kind of Route(and
    /// select this Route). It's not recommended to set `Port` unless the
    /// networking behaviors specified in a Route must apply to a specific port
    /// as opposed to a listener(s) whose port(s) may be changed. When both Port
    /// and SectionName are specified, the name and port of the selected listener
    /// must match both specified values.
    /// 
    /// 
    /// When the parent resource is a Service, this targets a specific port in the
    /// Service spec. When both Port (experimental) and SectionName are specified,
    /// the name and port of the selected port must match both specified values.
    /// 
    /// 
    /// Implementations MAY choose to support other parent resources.
    /// Implementations supporting other types of parent resources MUST clearly
    /// document how/if Port is interpreted.
    /// 
    /// For the purpose of status, an attachment is considered successful as
    /// long as the parent resource accepts it partially. For example, Gateway
    /// listeners can restrict which Routes can attach to them by Route kind,
    /// namespace, or hostname. If 1 of 2 Gateway listeners accept attachment
    /// from the referencing Route, the Route MUST be considered successfully
    /// attached. If no Gateway listeners accept attachment from this Route,
    /// the Route MUST be considered detached from the Gateway.
    /// 
    /// Support: Extended
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<i32>,
    /// SectionName is the name of a section within the target resource. In the
    /// following resources, SectionName is interpreted as the following:
    /// 
    /// * Gateway: Listener name. When both Port (experimental) and SectionName
    /// are specified, the name and port of the selected listener must match
    /// both specified values.
    /// * Service: Port name. When both Port (experimental) and SectionName
    /// are specified, the name and port of the selected listener must match
    /// both specified values.
    /// 
    /// Implementations MAY choose to support attaching Routes to other resources.
    /// If that is the case, they MUST clearly document how SectionName is
    /// interpreted.
    /// 
    /// When unspecified (empty string), this will reference the entire resource.
    /// For the purpose of status, an attachment is considered successful if at
    /// least one section in the parent resource accepts it. For example, Gateway
    /// listeners can restrict which Routes can attach to them by Route kind,
    /// namespace, or hostname. If 1 of 2 Gateway listeners accept attachment from
    /// the referencing Route, the Route MUST be considered successfully
    /// attached. If no Gateway listeners accept attachment from this Route, the
    /// Route MUST be considered detached from the Gateway.
    /// 
    /// Support: Core
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sectionName")]
    pub section_name: Option<String>,
}

