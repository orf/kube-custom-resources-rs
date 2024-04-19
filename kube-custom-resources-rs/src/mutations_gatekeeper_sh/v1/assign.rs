// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/open-policy-agent/gatekeeper/mutations.gatekeeper.sh/v1/assign.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// AssignSpec defines the desired state of Assign.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "mutations.gatekeeper.sh", version = "v1", kind = "Assign", plural = "assign")]
#[kube(status = "AssignStatus")]
#[kube(schema = "disabled")]
pub struct AssignSpec {
    /// ApplyTo lists the specific groups, versions and kinds a mutation will be applied to.
    /// This is necessary because every mutation implies part of an object schema and object
    /// schemas are associated with specific GVKs.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "applyTo")]
    pub apply_to: Option<Vec<AssignApplyTo>>,
    /// Location describes the path to be mutated, for example: `spec.containers[name: main]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// Match allows the user to limit which resources get mutated.
    /// Individual match criteria are AND-ed together. An undefined
    /// match criteria matches everything.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "match")]
    pub r#match: Option<AssignMatch>,
    /// Parameters define the behavior of the mutator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<AssignParameters>,
}

/// ApplyTo determines what GVKs items the mutation should apply to.
/// Globs are not allowed.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AssignApplyTo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub versions: Option<Vec<String>>,
}

/// Match allows the user to limit which resources get mutated.
/// Individual match criteria are AND-ed together. An undefined
/// match criteria matches everything.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AssignMatch {
    /// ExcludedNamespaces is a list of namespace names. If defined, a
    /// constraint only applies to resources not in a listed namespace.
    /// ExcludedNamespaces also supports a prefix or suffix based glob.  For example,
    /// `excludedNamespaces: [kube-*]` matches both `kube-system` and
    /// `kube-public`, and `excludedNamespaces: [*-system]` matches both `kube-system` and
    /// `gatekeeper-system`.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "excludedNamespaces")]
    pub excluded_namespaces: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<AssignMatchKinds>>,
    /// LabelSelector is the combination of two optional fields: `matchLabels`
    /// and `matchExpressions`.  These two fields provide different methods of
    /// selecting or excluding k8s objects based on the label keys and values
    /// included in object metadata.  All selection expressions from both
    /// sections are ANDed to determine if an object meets the cumulative
    /// requirements of the selector.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "labelSelector")]
    pub label_selector: Option<AssignMatchLabelSelector>,
    /// Name is the name of an object.  If defined, it will match against objects with the specified
    /// name.  Name also supports a prefix or suffix glob.  For example, `name: pod-*` would match
    /// both `pod-a` and `pod-b`, and `name: *-pod` would match both `a-pod` and `b-pod`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// NamespaceSelector is a label selector against an object's containing
    /// namespace or the object itself, if the object is a namespace.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "namespaceSelector")]
    pub namespace_selector: Option<AssignMatchNamespaceSelector>,
    /// Namespaces is a list of namespace names. If defined, a constraint only
    /// applies to resources in a listed namespace.  Namespaces also supports a
    /// prefix or suffix based glob.  For example, `namespaces: [kube-*]` matches both
    /// `kube-system` and `kube-public`, and `namespaces: [*-system]` matches both
    /// `kube-system` and `gatekeeper-system`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<Vec<String>>,
    /// Scope determines if cluster-scoped and/or namespaced-scoped resources
    /// are matched.  Accepts `*`, `Cluster`, or `Namespaced`. (defaults to `*`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Source determines whether generated or original resources are matched.
    /// Accepts `Generated`|`Original`|`All` (defaults to `All`). A value of
    /// `Generated` will only match generated resources, while `Original` will only
    /// match regular resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<AssignMatchSource>,
}

/// Kinds accepts a list of objects with apiGroups and kinds fields
/// that list the groups/kinds of objects to which the mutation will apply.
/// If multiple groups/kinds objects are specified,
/// only one match is needed for the resource to be in scope.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AssignMatchKinds {
    /// APIGroups is the API groups the resources belong to. '*' is all groups.
    /// If '*' is present, the length of the slice must be one.
    /// Required.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiGroups")]
    pub api_groups: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<String>>,
}

/// LabelSelector is the combination of two optional fields: `matchLabels`
/// and `matchExpressions`.  These two fields provide different methods of
/// selecting or excluding k8s objects based on the label keys and values
/// included in object metadata.  All selection expressions from both
/// sections are ANDed to determine if an object meets the cumulative
/// requirements of the selector.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AssignMatchLabelSelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<AssignMatchLabelSelectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels
    /// map is equivalent to an element of matchExpressions, whose key field is "key", the
    /// operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that
/// relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AssignMatchLabelSelectorMatchExpressions {
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

/// NamespaceSelector is a label selector against an object's containing
/// namespace or the object itself, if the object is a namespace.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AssignMatchNamespaceSelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<AssignMatchNamespaceSelectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels
    /// map is equivalent to an element of matchExpressions, whose key field is "key", the
    /// operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that
/// relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AssignMatchNamespaceSelectorMatchExpressions {
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

/// Match allows the user to limit which resources get mutated.
/// Individual match criteria are AND-ed together. An undefined
/// match criteria matches everything.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum AssignMatchSource {
    All,
    Generated,
    Original,
}

/// Parameters define the behavior of the mutator.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AssignParameters {
    /// Assign.value holds the value to be assigned
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assign: Option<AssignParametersAssign>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "pathTests")]
    pub path_tests: Option<Vec<AssignParametersPathTests>>,
}

/// Assign.value holds the value to be assigned
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AssignParametersAssign {
    /// ExternalData describes the external data provider to be used for mutation.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "externalData")]
    pub external_data: Option<AssignParametersAssignExternalData>,
    /// FromMetadata assigns a value from the specified metadata field.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "fromMetadata")]
    pub from_metadata: Option<AssignParametersAssignFromMetadata>,
    /// Value is a constant value that will be assigned to `location`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<BTreeMap<String, serde_json::Value>>,
}

/// ExternalData describes the external data provider to be used for mutation.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AssignParametersAssignExternalData {
    /// DataSource specifies where to extract the data that will be sent
    /// to the external data provider as parameters.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dataSource")]
    pub data_source: Option<AssignParametersAssignExternalDataDataSource>,
    /// Default specifies the default value to use when the external data
    /// provider returns an error and the failure policy is set to "UseDefault".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// FailurePolicy specifies the policy to apply when the external data
    /// provider returns an error.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "failurePolicy")]
    pub failure_policy: Option<AssignParametersAssignExternalDataFailurePolicy>,
    /// Provider is the name of the external data provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

/// ExternalData describes the external data provider to be used for mutation.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum AssignParametersAssignExternalDataDataSource {
    ValueAtLocation,
    Username,
}

/// ExternalData describes the external data provider to be used for mutation.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum AssignParametersAssignExternalDataFailurePolicy {
    UseDefault,
    Ignore,
    Fail,
}

/// FromMetadata assigns a value from the specified metadata field.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AssignParametersAssignFromMetadata {
    /// Field specifies which metadata field provides the assigned value. Valid fields are `namespace` and `name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

/// PathTest allows the user to customize how the mutation works if parent
/// paths are missing. It traverses the list in order. All sub paths are
/// tested against the provided condition, if the test fails, the mutation is
/// not applied. All `subPath` entries must be a prefix of `location`. Any
/// glob characters will take on the same value as was used to
/// expand the matching glob in `location`.
/// 
/// 
/// Available Tests:
/// * MustExist    - the path must exist or do not mutate
/// * MustNotExist - the path must not exist or do not mutate.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AssignParametersPathTests {
    /// Condition describes whether the path either MustExist or MustNotExist in the original object
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<AssignParametersPathTestsCondition>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "subPath")]
    pub sub_path: Option<String>,
}

/// PathTest allows the user to customize how the mutation works if parent
/// paths are missing. It traverses the list in order. All sub paths are
/// tested against the provided condition, if the test fails, the mutation is
/// not applied. All `subPath` entries must be a prefix of `location`. Any
/// glob characters will take on the same value as was used to
/// expand the matching glob in `location`.
/// 
/// 
/// Available Tests:
/// * MustExist    - the path must exist or do not mutate
/// * MustNotExist - the path must not exist or do not mutate.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum AssignParametersPathTestsCondition {
    MustExist,
    MustNotExist,
}

/// AssignStatus defines the observed state of Assign.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AssignStatus {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "byPod")]
    pub by_pod: Option<Vec<AssignStatusByPod>>,
}

/// MutatorPodStatusStatus defines the observed state of MutatorPodStatus.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AssignStatusByPod {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<AssignStatusByPodErrors>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Storing the mutator UID allows us to detect drift, such as
    /// when a mutator has been recreated after its CRD was deleted
    /// out from under it, interrupting the watch
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "mutatorUID")]
    pub mutator_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operations: Option<Vec<String>>,
}

/// MutatorError represents a single error caught while adding a mutator to a system.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AssignStatusByPodErrors {
    pub message: String,
    /// Type indicates a specific class of error for use by controller code.
    /// If not present, the error should be treated as not matching any known type.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
}

