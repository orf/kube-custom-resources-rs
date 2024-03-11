// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/couchbase-partners/helm-charts/couchbase.com/v2/couchbasescopegroups.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// Spec defines the desired state of the resource.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "couchbase.com", version = "v2", kind = "CouchbaseScopeGroup", plural = "couchbasescopegroups")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct CouchbaseScopeGroupSpec {
    /// Collections defines how to collate collections included in this scope or scope group. Any of the provided methods may be used to collate a set of collections to manage.  Collated collections must have unique names, otherwise it is considered ambiguous, and an error condition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collections: Option<CouchbaseScopeGroupCollections>,
    /// Names specifies the names of the scopes.  Unlike CouchbaseScope, which specifies a single scope, a scope group specifies multiple, and the scope group must specify at least one scope name. Any scope names specified must be unique. Scope names must be 1-251 characters in length, contain only [a-zA-Z0-9_-%] and not start with either _ or %.
    pub names: Vec<String>,
}

/// Collections defines how to collate collections included in this scope or scope group. Any of the provided methods may be used to collate a set of collections to manage.  Collated collections must have unique names, otherwise it is considered ambiguous, and an error condition.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CouchbaseScopeGroupCollections {
    /// Managed indicates whether collections within this scope are managed. If not then you can dynamically create and delete collections with the Couchbase UI or SDKs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed: Option<bool>,
    /// PreserveDefaultCollection indicates whether the Operator should manage the default collection within the default scope.  The default collection can be deleted, but can not be recreated by Couchbase Server.  By setting this field to `true`, the Operator will implicitly manage the default collection within the default scope.  The default collection cannot be modified and will have no document time-to-live (TTL).  When set to `false`, the operator will not manage the default collection, which will be deleted and cannot be used or recreated.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "preserveDefaultCollection")]
    pub preserve_default_collection: Option<bool>,
    /// Resources is an explicit list of named resources that will be considered for inclusion in this scope or scopes.  If a resource reference doesn't match a resource, then no error conditions are raised due to undefined resource creation ordering and eventual consistency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<CouchbaseScopeGroupCollectionsResources>>,
    /// Selector allows resources to be implicitly considered for inclusion in this scope or scopes.  More info: https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.21/#labelselector-v1-meta
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<CouchbaseScopeGroupCollectionsSelector>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CouchbaseScopeGroupCollectionsResources {
    /// Kind indicates the kind of resource that is being referenced.  A scope can only reference `CouchbaseCollection` and `CouchbaseCollectionGroup` resource kinds.  This field defaults to `CouchbaseCollection` if not specified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<CouchbaseScopeGroupCollectionsResourcesKind>,
    /// Name is the name of the Kubernetes resource name that is being referenced. Legal collection names have a maximum length of 251 characters and may be composed of any character from "a-z", "A-Z", "0-9" and "_-%".
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum CouchbaseScopeGroupCollectionsResourcesKind {
    CouchbaseCollection,
    CouchbaseCollectionGroup,
}

/// Selector allows resources to be implicitly considered for inclusion in this scope or scopes.  More info: https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.21/#labelselector-v1-meta
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CouchbaseScopeGroupCollectionsSelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<CouchbaseScopeGroupCollectionsSelectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CouchbaseScopeGroupCollectionsSelectorMatchExpressions {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

