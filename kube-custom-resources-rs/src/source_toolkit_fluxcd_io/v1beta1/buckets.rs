// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/fluxcd/source-controller/source.toolkit.fluxcd.io/v1beta1/buckets.yaml --derive=PartialEq
// kopium version: 0.16.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// BucketSpec defines the desired state of an S3 compatible bucket
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "source.toolkit.fluxcd.io", version = "v1beta1", kind = "Bucket", plural = "buckets")]
#[kube(namespaced)]
#[kube(status = "BucketStatus")]
#[kube(schema = "disabled")]
pub struct BucketSpec {
    /// AccessFrom defines an Access Control List for allowing cross-namespace references to this object.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "accessFrom")]
    pub access_from: Option<BucketAccessFrom>,
    /// The bucket name.
    #[serde(rename = "bucketName")]
    pub bucket_name: String,
    /// The bucket endpoint address.
    pub endpoint: String,
    /// Ignore overrides the set of excluded patterns in the .sourceignore format (which is the same as .gitignore). If not provided, a default will be used, consult the documentation for your version to find out what those are.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ignore: Option<String>,
    /// Insecure allows connecting to a non-TLS S3 HTTP endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,
    /// The interval at which to check for bucket updates.
    pub interval: String,
    /// The S3 compatible storage provider name, default ('generic').
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<BucketProvider>,
    /// The bucket region.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// The name of the secret containing authentication credentials for the Bucket.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretRef")]
    pub secret_ref: Option<BucketSecretRef>,
    /// This flag tells the controller to suspend the reconciliation of this source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspend: Option<bool>,
    /// The timeout for download operations, defaults to 60s.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
}

/// AccessFrom defines an Access Control List for allowing cross-namespace references to this object.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BucketAccessFrom {
    /// NamespaceSelectors is the list of namespace selectors to which this ACL applies. Items in this list are evaluated using a logical OR operation.
    #[serde(rename = "namespaceSelectors")]
    pub namespace_selectors: Vec<BucketAccessFromNamespaceSelectors>,
}

/// NamespaceSelector selects the namespaces to which this ACL applies. An empty map of MatchLabels matches all namespaces in a cluster.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BucketAccessFromNamespaceSelectors {
    /// MatchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// BucketSpec defines the desired state of an S3 compatible bucket
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum BucketProvider {
    #[serde(rename = "generic")]
    Generic,
    #[serde(rename = "aws")]
    Aws,
    #[serde(rename = "gcp")]
    Gcp,
}

/// The name of the secret containing authentication credentials for the Bucket.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BucketSecretRef {
    /// Name of the referent.
    pub name: String,
}

/// BucketStatus defines the observed state of a bucket
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BucketStatus {
    /// Artifact represents the output of the last successful Bucket sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<BucketStatusArtifact>,
    /// Conditions holds the conditions for the Bucket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<BucketStatusConditions>>,
    /// LastHandledReconcileAt holds the value of the most recent reconcile request value, so a change of the annotation value can be detected.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastHandledReconcileAt")]
    pub last_handled_reconcile_at: Option<String>,
    /// ObservedGeneration is the last observed generation.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
    /// URL is the download link for the artifact output of the last Bucket sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Artifact represents the output of the last successful Bucket sync.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BucketStatusArtifact {
    /// Checksum is the SHA256 checksum of the artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
    /// LastUpdateTime is the timestamp corresponding to the last update of this artifact.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastUpdateTime")]
    pub last_update_time: Option<String>,
    /// Path is the relative file path of this artifact.
    pub path: String,
    /// Revision is a human readable identifier traceable in the origin source system. It can be a Git commit SHA, Git tag, a Helm index timestamp, a Helm chart version, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    /// URL is the HTTP address of this artifact.
    pub url: String,
}

/// Condition contains details for one aspect of the current state of this API Resource. --- This struct is intended for direct use as an array at the field path .status.conditions.  For example, 
///  type FooStatus struct{ // Represents the observations of a foo's current state. // Known .status.conditions.type are: "Available", "Progressing", and "Degraded" // +patchMergeKey=type // +patchStrategy=merge // +listType=map // +listMapKey=type Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"` 
///  // other fields }
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BucketStatusConditions {
    /// lastTransitionTime is the last time the condition transitioned from one status to another. This should be when the underlying condition changed.  If that is not known, then using the time when the API field changed is acceptable.
    #[serde(rename = "lastTransitionTime")]
    pub last_transition_time: String,
    /// message is a human readable message indicating details about the transition. This may be an empty string.
    pub message: String,
    /// observedGeneration represents the .metadata.generation that the condition was set based upon. For instance, if .metadata.generation is currently 12, but the .status.conditions[x].observedGeneration is 9, the condition is out of date with respect to the current state of the instance.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
    /// reason contains a programmatic identifier indicating the reason for the condition's last transition. Producers of specific condition types may define expected values and meanings for this field, and whether the values are considered a guaranteed API. The value should be a CamelCase string. This field may not be empty.
    pub reason: String,
    /// status of the condition, one of True, False, Unknown.
    pub status: BucketStatusConditionsStatus,
    /// type of condition in CamelCase or in foo.example.com/CamelCase. --- Many .condition.type values are consistent across resources like Available, but because arbitrary conditions can be useful (see .node.status.conditions), the ability to deconflict is important. The regex it matches is (dns1123SubdomainFmt/)?(qualifiedNameFmt)
    #[serde(rename = "type")]
    pub r#type: String,
}

/// Condition contains details for one aspect of the current state of this API Resource. --- This struct is intended for direct use as an array at the field path .status.conditions.  For example, 
///  type FooStatus struct{ // Represents the observations of a foo's current state. // Known .status.conditions.type are: "Available", "Progressing", and "Degraded" // +patchMergeKey=type // +patchStrategy=merge // +listType=map // +listMapKey=type Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"` 
///  // other fields }
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum BucketStatusConditionsStatus {
    True,
    False,
    Unknown,
}
