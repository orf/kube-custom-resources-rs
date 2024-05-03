// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kyverno/kyverno/kyverno.io/v2/policyexceptions.yaml --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use std::collections::BTreeMap;
}
use self::prelude::*;

/// Spec declares policy exception behaviors.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "kyverno.io", version = "v2", kind = "PolicyException", plural = "policyexceptions")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
#[kube(derive="PartialEq")]
pub struct PolicyExceptionSpec {
    /// Background controls if exceptions are applied to existing policies during a background scan.
    /// Optional. Default value is "true". The value must be set to "false" if the policy rule
    /// uses variables that are only available in the admission review request (e.g. user name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background: Option<bool>,
    /// Conditions are used to determine if a resource applies to the exception by evaluating a
    /// set of conditions. The declaration can contain nested `any` or `all` statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<PolicyExceptionConditions>,
    /// Exceptions is a list policy/rules to be excluded
    pub exceptions: Vec<PolicyExceptionExceptions>,
    /// Match defines match clause used to check if a resource applies to the exception
    #[serde(rename = "match")]
    pub r#match: PolicyExceptionMatch,
    /// PodSecurity specifies the Pod Security Standard controls to be excluded.
    /// Applicable only to policies that have validate.podSecurity subrule.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "podSecurity")]
    pub pod_security: Option<Vec<PolicyExceptionPodSecurity>>,
}

/// Conditions are used to determine if a resource applies to the exception by evaluating a
/// set of conditions. The declaration can contain nested `any` or `all` statements.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PolicyExceptionConditions {
    /// AllConditions enable variable-based conditional rule execution. This is useful for
    /// finer control of when an rule is applied. A condition can reference object data
    /// using JMESPath notation.
    /// Here, all of the conditions need to pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub all: Option<Vec<PolicyExceptionConditionsAll>>,
    /// AnyConditions enable variable-based conditional rule execution. This is useful for
    /// finer control of when an rule is applied. A condition can reference object data
    /// using JMESPath notation.
    /// Here, at least one of the conditions need to pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub any: Option<Vec<PolicyExceptionConditionsAny>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PolicyExceptionConditionsAll {
    /// Key is the context entry (using JMESPath) for conditional rule evaluation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<serde_json::Value>,
    /// Message is an optional display message
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Operator is the conditional operation to perform. Valid operators are:
    /// Equals, NotEquals, In, AnyIn, AllIn, NotIn, AnyNotIn, AllNotIn, GreaterThanOrEquals,
    /// GreaterThan, LessThanOrEquals, LessThan, DurationGreaterThanOrEquals, DurationGreaterThan,
    /// DurationLessThanOrEquals, DurationLessThan
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<PolicyExceptionConditionsAllOperator>,
    /// Value is the conditional value, or set of values. The values can be fixed set
    /// or can be variables declared using JMESPath.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum PolicyExceptionConditionsAllOperator {
    Equals,
    NotEquals,
    AnyIn,
    AllIn,
    AnyNotIn,
    AllNotIn,
    GreaterThanOrEquals,
    GreaterThan,
    LessThanOrEquals,
    LessThan,
    DurationGreaterThanOrEquals,
    DurationGreaterThan,
    DurationLessThanOrEquals,
    DurationLessThan,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PolicyExceptionConditionsAny {
    /// Key is the context entry (using JMESPath) for conditional rule evaluation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<serde_json::Value>,
    /// Message is an optional display message
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Operator is the conditional operation to perform. Valid operators are:
    /// Equals, NotEquals, In, AnyIn, AllIn, NotIn, AnyNotIn, AllNotIn, GreaterThanOrEquals,
    /// GreaterThan, LessThanOrEquals, LessThan, DurationGreaterThanOrEquals, DurationGreaterThan,
    /// DurationLessThanOrEquals, DurationLessThan
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<PolicyExceptionConditionsAnyOperator>,
    /// Value is the conditional value, or set of values. The values can be fixed set
    /// or can be variables declared using JMESPath.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum PolicyExceptionConditionsAnyOperator {
    Equals,
    NotEquals,
    AnyIn,
    AllIn,
    AnyNotIn,
    AllNotIn,
    GreaterThanOrEquals,
    GreaterThan,
    LessThanOrEquals,
    LessThan,
    DurationGreaterThanOrEquals,
    DurationGreaterThan,
    DurationLessThanOrEquals,
    DurationLessThan,
}

/// Exception stores infos about a policy and rules
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PolicyExceptionExceptions {
    /// PolicyName identifies the policy to which the exception is applied.
    /// The policy name uses the format <namespace>/<name> unless it
    /// references a ClusterPolicy.
    #[serde(rename = "policyName")]
    pub policy_name: String,
    /// RuleNames identifies the rules to which the exception is applied.
    #[serde(rename = "ruleNames")]
    pub rule_names: Vec<String>,
}

/// Match defines match clause used to check if a resource applies to the exception
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PolicyExceptionMatch {
    /// All allows specifying resources which will be ANDed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub all: Option<Vec<PolicyExceptionMatchAll>>,
    /// Any allows specifying resources which will be ORed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub any: Option<Vec<PolicyExceptionMatchAny>>,
}

/// ResourceFilter allow users to "AND" or "OR" between resources
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PolicyExceptionMatchAll {
    /// ClusterRoles is the list of cluster-wide role names for the user.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clusterRoles")]
    pub cluster_roles: Option<Vec<String>>,
    /// ResourceDescription contains information about the resource being created or modified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<PolicyExceptionMatchAllResources>,
    /// Roles is the list of namespaced role names for the user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    /// Subjects is the list of subject names like users, user groups, and service accounts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subjects: Option<Vec<PolicyExceptionMatchAllSubjects>>,
}

/// ResourceDescription contains information about the resource being created or modified.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PolicyExceptionMatchAllResources {
    /// Annotations is a  map of annotations (key-value pairs of type string). Annotation keys
    /// and values support the wildcard characters "*" (matches zero or many characters) and
    /// "?" (matches at least one character).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
    /// Kinds is a list of resource kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<String>>,
    /// Name is the name of the resource. The name supports wildcard characters
    /// "*" (matches zero or many characters) and "?" (at least one character).
    /// NOTE: "Name" is being deprecated in favor of "Names".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Names are the names of the resources. Each name supports wildcard characters
    /// "*" (matches zero or many characters) and "?" (at least one character).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
    /// NamespaceSelector is a label selector for the resource namespace. Label keys and values
    /// in `matchLabels` support the wildcard characters `*` (matches zero or many characters)
    /// and `?` (matches one character).Wildcards allows writing label selectors like
    /// ["storage.k8s.io/*": "*"]. Note that using ["*" : "*"] matches any key and value but
    /// does not match an empty label set.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "namespaceSelector")]
    pub namespace_selector: Option<PolicyExceptionMatchAllResourcesNamespaceSelector>,
    /// Namespaces is a list of namespaces names. Each name supports wildcard characters
    /// "*" (matches zero or many characters) and "?" (at least one character).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<Vec<String>>,
    /// Operations can contain values ["CREATE, "UPDATE", "CONNECT", "DELETE"], which are used to match a specific action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operations: Option<Vec<String>>,
    /// Selector is a label selector. Label keys and values in `matchLabels` support the wildcard
    /// characters `*` (matches zero or many characters) and `?` (matches one character).
    /// Wildcards allows writing label selectors like ["storage.k8s.io/*": "*"]. Note that
    /// using ["*" : "*"] matches any key and value but does not match an empty label set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<PolicyExceptionMatchAllResourcesSelector>,
}

/// NamespaceSelector is a label selector for the resource namespace. Label keys and values
/// in `matchLabels` support the wildcard characters `*` (matches zero or many characters)
/// and `?` (matches one character).Wildcards allows writing label selectors like
/// ["storage.k8s.io/*": "*"]. Note that using ["*" : "*"] matches any key and value but
/// does not match an empty label set.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PolicyExceptionMatchAllResourcesNamespaceSelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<PolicyExceptionMatchAllResourcesNamespaceSelectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels
    /// map is equivalent to an element of matchExpressions, whose key field is "key", the
    /// operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that
/// relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PolicyExceptionMatchAllResourcesNamespaceSelectorMatchExpressions {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values.
    /// Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn,
    /// the values array must be non-empty. If the operator is Exists or DoesNotExist,
    /// the values array must be empty. This array is replaced during a strategic
    /// merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// Selector is a label selector. Label keys and values in `matchLabels` support the wildcard
/// characters `*` (matches zero or many characters) and `?` (matches one character).
/// Wildcards allows writing label selectors like ["storage.k8s.io/*": "*"]. Note that
/// using ["*" : "*"] matches any key and value but does not match an empty label set.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PolicyExceptionMatchAllResourcesSelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<PolicyExceptionMatchAllResourcesSelectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels
    /// map is equivalent to an element of matchExpressions, whose key field is "key", the
    /// operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that
/// relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PolicyExceptionMatchAllResourcesSelectorMatchExpressions {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values.
    /// Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn,
    /// the values array must be non-empty. If the operator is Exists or DoesNotExist,
    /// the values array must be empty. This array is replaced during a strategic
    /// merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// Subject contains a reference to the object or user identities a role binding applies to.  This can either hold a direct API object reference,
/// or a value for non-objects such as user and group names.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PolicyExceptionMatchAllSubjects {
    /// APIGroup holds the API group of the referenced subject.
    /// Defaults to "" for ServiceAccount subjects.
    /// Defaults to "rbac.authorization.k8s.io" for User and Group subjects.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiGroup")]
    pub api_group: Option<String>,
    /// Kind of object being referenced. Values defined by this API group are "User", "Group", and "ServiceAccount".
    /// If the Authorizer does not recognized the kind value, the Authorizer should report an error.
    pub kind: String,
    /// Name of the object being referenced.
    pub name: String,
    /// Namespace of the referenced object.  If the object kind is non-namespace, such as "User" or "Group", and this value is not empty
    /// the Authorizer should report an error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// ResourceFilter allow users to "AND" or "OR" between resources
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PolicyExceptionMatchAny {
    /// ClusterRoles is the list of cluster-wide role names for the user.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clusterRoles")]
    pub cluster_roles: Option<Vec<String>>,
    /// ResourceDescription contains information about the resource being created or modified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<PolicyExceptionMatchAnyResources>,
    /// Roles is the list of namespaced role names for the user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    /// Subjects is the list of subject names like users, user groups, and service accounts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subjects: Option<Vec<PolicyExceptionMatchAnySubjects>>,
}

/// ResourceDescription contains information about the resource being created or modified.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PolicyExceptionMatchAnyResources {
    /// Annotations is a  map of annotations (key-value pairs of type string). Annotation keys
    /// and values support the wildcard characters "*" (matches zero or many characters) and
    /// "?" (matches at least one character).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
    /// Kinds is a list of resource kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<String>>,
    /// Name is the name of the resource. The name supports wildcard characters
    /// "*" (matches zero or many characters) and "?" (at least one character).
    /// NOTE: "Name" is being deprecated in favor of "Names".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Names are the names of the resources. Each name supports wildcard characters
    /// "*" (matches zero or many characters) and "?" (at least one character).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
    /// NamespaceSelector is a label selector for the resource namespace. Label keys and values
    /// in `matchLabels` support the wildcard characters `*` (matches zero or many characters)
    /// and `?` (matches one character).Wildcards allows writing label selectors like
    /// ["storage.k8s.io/*": "*"]. Note that using ["*" : "*"] matches any key and value but
    /// does not match an empty label set.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "namespaceSelector")]
    pub namespace_selector: Option<PolicyExceptionMatchAnyResourcesNamespaceSelector>,
    /// Namespaces is a list of namespaces names. Each name supports wildcard characters
    /// "*" (matches zero or many characters) and "?" (at least one character).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<Vec<String>>,
    /// Operations can contain values ["CREATE, "UPDATE", "CONNECT", "DELETE"], which are used to match a specific action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operations: Option<Vec<String>>,
    /// Selector is a label selector. Label keys and values in `matchLabels` support the wildcard
    /// characters `*` (matches zero or many characters) and `?` (matches one character).
    /// Wildcards allows writing label selectors like ["storage.k8s.io/*": "*"]. Note that
    /// using ["*" : "*"] matches any key and value but does not match an empty label set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<PolicyExceptionMatchAnyResourcesSelector>,
}

/// NamespaceSelector is a label selector for the resource namespace. Label keys and values
/// in `matchLabels` support the wildcard characters `*` (matches zero or many characters)
/// and `?` (matches one character).Wildcards allows writing label selectors like
/// ["storage.k8s.io/*": "*"]. Note that using ["*" : "*"] matches any key and value but
/// does not match an empty label set.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PolicyExceptionMatchAnyResourcesNamespaceSelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<PolicyExceptionMatchAnyResourcesNamespaceSelectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels
    /// map is equivalent to an element of matchExpressions, whose key field is "key", the
    /// operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that
/// relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PolicyExceptionMatchAnyResourcesNamespaceSelectorMatchExpressions {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values.
    /// Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn,
    /// the values array must be non-empty. If the operator is Exists or DoesNotExist,
    /// the values array must be empty. This array is replaced during a strategic
    /// merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// Selector is a label selector. Label keys and values in `matchLabels` support the wildcard
/// characters `*` (matches zero or many characters) and `?` (matches one character).
/// Wildcards allows writing label selectors like ["storage.k8s.io/*": "*"]. Note that
/// using ["*" : "*"] matches any key and value but does not match an empty label set.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PolicyExceptionMatchAnyResourcesSelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<PolicyExceptionMatchAnyResourcesSelectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels
    /// map is equivalent to an element of matchExpressions, whose key field is "key", the
    /// operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that
/// relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PolicyExceptionMatchAnyResourcesSelectorMatchExpressions {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values.
    /// Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn,
    /// the values array must be non-empty. If the operator is Exists or DoesNotExist,
    /// the values array must be empty. This array is replaced during a strategic
    /// merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// Subject contains a reference to the object or user identities a role binding applies to.  This can either hold a direct API object reference,
/// or a value for non-objects such as user and group names.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PolicyExceptionMatchAnySubjects {
    /// APIGroup holds the API group of the referenced subject.
    /// Defaults to "" for ServiceAccount subjects.
    /// Defaults to "rbac.authorization.k8s.io" for User and Group subjects.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiGroup")]
    pub api_group: Option<String>,
    /// Kind of object being referenced. Values defined by this API group are "User", "Group", and "ServiceAccount".
    /// If the Authorizer does not recognized the kind value, the Authorizer should report an error.
    pub kind: String,
    /// Name of the object being referenced.
    pub name: String,
    /// Namespace of the referenced object.  If the object kind is non-namespace, such as "User" or "Group", and this value is not empty
    /// the Authorizer should report an error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// PodSecurityStandard specifies the Pod Security Standard controls to be excluded.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PolicyExceptionPodSecurity {
    /// ControlName specifies the name of the Pod Security Standard control.
    /// See: https://kubernetes.io/docs/concepts/security/pod-security-standards/
    #[serde(rename = "controlName")]
    pub control_name: PolicyExceptionPodSecurityControlName,
    /// Images selects matching containers and applies the container level PSS.
    /// Each image is the image name consisting of the registry address, repository, image, and tag.
    /// Empty list matches no containers, PSS checks are applied at the pod level only.
    /// Wildcards ('*' and '?') are allowed. See: https://kubernetes.io/docs/concepts/containers/images.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub images: Option<Vec<String>>,
    /// RestrictedField selects the field for the given Pod Security Standard control.
    /// When not set, all restricted fields for the control are selected.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "restrictedField")]
    pub restricted_field: Option<String>,
    /// Values defines the allowed values that can be excluded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// PodSecurityStandard specifies the Pod Security Standard controls to be excluded.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum PolicyExceptionPodSecurityControlName {
    HostProcess,
    #[serde(rename = "Host Namespaces")]
    HostNamespaces,
    #[serde(rename = "Privileged Containers")]
    PrivilegedContainers,
    Capabilities,
    #[serde(rename = "HostPath Volumes")]
    HostPathVolumes,
    #[serde(rename = "Host Ports")]
    HostPorts,
    AppArmor,
    #[serde(rename = "SELinux")]
    SeLinux,
    #[serde(rename = "/proc Mount Type")]
    ProcMountType,
    Seccomp,
    Sysctls,
    #[serde(rename = "Volume Types")]
    VolumeTypes,
    #[serde(rename = "Privilege Escalation")]
    PrivilegeEscalation,
    #[serde(rename = "Running as Non-root")]
    RunningAsNonRoot,
    #[serde(rename = "Running as Non-root user")]
    RunningAsNonRootUser,
}

