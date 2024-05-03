// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/fluxcd/image-reflector-controller/image.toolkit.fluxcd.io/v1beta2/imagerepositories.yaml --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use std::collections::BTreeMap;
    pub use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
}
use self::prelude::*;

/// ImageRepositorySpec defines the parameters for scanning an image
/// repository, e.g., `fluxcd/flux`.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "image.toolkit.fluxcd.io", version = "v1beta2", kind = "ImageRepository", plural = "imagerepositories")]
#[kube(namespaced)]
#[kube(status = "ImageRepositoryStatus")]
#[kube(schema = "disabled")]
#[kube(derive="PartialEq")]
pub struct ImageRepositorySpec {
    /// AccessFrom defines an ACL for allowing cross-namespace references
    /// to the ImageRepository object based on the caller's namespace labels.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "accessFrom")]
    pub access_from: Option<ImageRepositoryAccessFrom>,
    /// CertSecretRef can be given the name of a Secret containing
    /// either or both of
    /// 
    /// 
    /// - a PEM-encoded client certificate (`tls.crt`) and private
    /// key (`tls.key`);
    /// - a PEM-encoded CA certificate (`ca.crt`)
    /// 
    /// 
    /// and whichever are supplied, will be used for connecting to the
    /// registry. The client cert and key are useful if you are
    /// authenticating with a certificate; the CA cert is useful if
    /// you are using a self-signed server certificate. The Secret must
    /// be of type `Opaque` or `kubernetes.io/tls`.
    /// 
    /// 
    /// Note: Support for the `caFile`, `certFile` and `keyFile` keys has
    /// been deprecated.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "certSecretRef")]
    pub cert_secret_ref: Option<ImageRepositoryCertSecretRef>,
    /// ExclusionList is a list of regex strings used to exclude certain tags
    /// from being stored in the database.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "exclusionList")]
    pub exclusion_list: Option<Vec<String>>,
    /// Image is the name of the image repository
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Insecure allows connecting to a non-TLS HTTP container registry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,
    /// Interval is the length of time to wait between
    /// scans of the image repository.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,
    /// The provider used for authentication, can be 'aws', 'azure', 'gcp' or 'generic'.
    /// When not specified, defaults to 'generic'.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<ImageRepositoryProvider>,
    /// SecretRef can be given the name of a secret containing
    /// credentials to use for the image registry. The secret should be
    /// created with `kubectl create secret docker-registry`, or the
    /// equivalent.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretRef")]
    pub secret_ref: Option<ImageRepositorySecretRef>,
    /// ServiceAccountName is the name of the Kubernetes ServiceAccount used to authenticate
    /// the image pull if the service account has attached pull secrets.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "serviceAccountName")]
    pub service_account_name: Option<String>,
    /// This flag tells the controller to suspend subsequent image scans.
    /// It does not apply to already started scans. Defaults to false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspend: Option<bool>,
    /// Timeout for image scanning.
    /// Defaults to 'Interval' duration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
}

/// AccessFrom defines an ACL for allowing cross-namespace references
/// to the ImageRepository object based on the caller's namespace labels.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ImageRepositoryAccessFrom {
    /// NamespaceSelectors is the list of namespace selectors to which this ACL applies.
    /// Items in this list are evaluated using a logical OR operation.
    #[serde(rename = "namespaceSelectors")]
    pub namespace_selectors: Vec<ImageRepositoryAccessFromNamespaceSelectors>,
}

/// NamespaceSelector selects the namespaces to which this ACL applies.
/// An empty map of MatchLabels matches all namespaces in a cluster.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ImageRepositoryAccessFromNamespaceSelectors {
    /// MatchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels
    /// map is equivalent to an element of matchExpressions, whose key field is "key", the
    /// operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// CertSecretRef can be given the name of a Secret containing
/// either or both of
/// 
/// 
/// - a PEM-encoded client certificate (`tls.crt`) and private
/// key (`tls.key`);
/// - a PEM-encoded CA certificate (`ca.crt`)
/// 
/// 
/// and whichever are supplied, will be used for connecting to the
/// registry. The client cert and key are useful if you are
/// authenticating with a certificate; the CA cert is useful if
/// you are using a self-signed server certificate. The Secret must
/// be of type `Opaque` or `kubernetes.io/tls`.
/// 
/// 
/// Note: Support for the `caFile`, `certFile` and `keyFile` keys has
/// been deprecated.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ImageRepositoryCertSecretRef {
    /// Name of the referent.
    pub name: String,
}

/// ImageRepositorySpec defines the parameters for scanning an image
/// repository, e.g., `fluxcd/flux`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ImageRepositoryProvider {
    #[serde(rename = "generic")]
    Generic,
    #[serde(rename = "aws")]
    Aws,
    #[serde(rename = "azure")]
    Azure,
    #[serde(rename = "gcp")]
    Gcp,
}

/// SecretRef can be given the name of a secret containing
/// credentials to use for the image registry. The secret should be
/// created with `kubectl create secret docker-registry`, or the
/// equivalent.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ImageRepositorySecretRef {
    /// Name of the referent.
    pub name: String,
}

/// ImageRepositoryStatus defines the observed state of ImageRepository
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ImageRepositoryStatus {
    /// CanonicalName is the name of the image repository with all the
    /// implied bits made explicit; e.g., `docker.io/library/alpine`
    /// rather than `alpine`.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "canonicalImageName")]
    pub canonical_image_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// LastHandledReconcileAt holds the value of the most recent
    /// reconcile request value, so a change of the annotation value
    /// can be detected.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastHandledReconcileAt")]
    pub last_handled_reconcile_at: Option<String>,
    /// LastScanResult contains the number of fetched tags.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastScanResult")]
    pub last_scan_result: Option<ImageRepositoryStatusLastScanResult>,
    /// ObservedExclusionList is a list of observed exclusion list. It reflects
    /// the exclusion rules used for the observed scan result in
    /// spec.lastScanResult.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedExclusionList")]
    pub observed_exclusion_list: Option<Vec<String>>,
    /// ObservedGeneration is the last reconciled generation.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
}

/// LastScanResult contains the number of fetched tags.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ImageRepositoryStatusLastScanResult {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "latestTags")]
    pub latest_tags: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "scanTime")]
    pub scan_time: Option<String>,
    #[serde(rename = "tagCount")]
    pub tag_count: i64,
}

