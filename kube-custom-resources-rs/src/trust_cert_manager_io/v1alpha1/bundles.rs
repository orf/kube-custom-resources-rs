// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/cert-manager/trust-manager/trust.cert-manager.io/v1alpha1/bundles.yaml --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// Desired state of the Bundle resource.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "trust.cert-manager.io", version = "v1alpha1", kind = "Bundle", plural = "bundles")]
#[kube(status = "BundleStatus")]
#[kube(schema = "disabled")]
pub struct BundleSpec {
    /// Sources is a set of references to data whose data will sync to the target.
    pub sources: Vec<BundleSources>,
    /// Target is the target location in all namespaces to sync source data to.
    pub target: BundleTarget,
}

/// BundleSource is the set of sources whose data will be appended and synced to
/// the BundleTarget in all Namespaces.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BundleSources {
    /// ConfigMap is a reference (by name) to a ConfigMap's `data` key, or to a
    /// list of ConfigMap's `data` key using label selector, in the trust Namespace.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "configMap")]
    pub config_map: Option<BundleSourcesConfigMap>,
    /// InLine is a simple string to append as the source data.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "inLine")]
    pub in_line: Option<String>,
    /// Secret is a reference (by name) to a Secret's `data` key, or to a
    /// list of Secret's `data` key using label selector, in the trust Namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<BundleSourcesSecret>,
    /// UseDefaultCAs, when true, requests the default CA bundle to be used as a source.
    /// Default CAs are available if trust-manager was installed via Helm
    /// or was otherwise set up to include a package-injecting init container by using the
    /// "--default-package-location" flag when starting the trust-manager controller.
    /// If default CAs were not configured at start-up, any request to use the default
    /// CAs will fail.
    /// The version of the default CA package which is used for a Bundle is stored in the
    /// defaultCAPackageVersion field of the Bundle's status field.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "useDefaultCAs")]
    pub use_default_c_as: Option<bool>,
}

/// ConfigMap is a reference (by name) to a ConfigMap's `data` key, or to a
/// list of ConfigMap's `data` key using label selector, in the trust Namespace.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BundleSourcesConfigMap {
    /// Key is the key of the entry in the object's `data` field to be used.
    pub key: String,
    /// Name is the name of the source object in the trust Namespace.
    /// This field must be left empty when `selector` is set
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Selector is the label selector to use to fetch a list of objects. Must not be set
    /// when `Name` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<BundleSourcesConfigMapSelector>,
}

/// Selector is the label selector to use to fetch a list of objects. Must not be set
/// when `Name` is set.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BundleSourcesConfigMapSelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<BundleSourcesConfigMapSelectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels
    /// map is equivalent to an element of matchExpressions, whose key field is "key", the
    /// operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that
/// relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BundleSourcesConfigMapSelectorMatchExpressions {
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

/// Secret is a reference (by name) to a Secret's `data` key, or to a
/// list of Secret's `data` key using label selector, in the trust Namespace.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BundleSourcesSecret {
    /// Key is the key of the entry in the object's `data` field to be used.
    pub key: String,
    /// Name is the name of the source object in the trust Namespace.
    /// This field must be left empty when `selector` is set
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Selector is the label selector to use to fetch a list of objects. Must not be set
    /// when `Name` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<BundleSourcesSecretSelector>,
}

/// Selector is the label selector to use to fetch a list of objects. Must not be set
/// when `Name` is set.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BundleSourcesSecretSelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<BundleSourcesSecretSelectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels
    /// map is equivalent to an element of matchExpressions, whose key field is "key", the
    /// operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that
/// relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BundleSourcesSecretSelectorMatchExpressions {
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

/// Target is the target location in all namespaces to sync source data to.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BundleTarget {
    /// AdditionalFormats specifies any additional formats to write to the target
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "additionalFormats")]
    pub additional_formats: Option<BundleTargetAdditionalFormats>,
    /// ConfigMap is the target ConfigMap in Namespaces that all Bundle source
    /// data will be synced to.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "configMap")]
    pub config_map: Option<BundleTargetConfigMap>,
    /// NamespaceSelector will, if set, only sync the target resource in
    /// Namespaces which match the selector.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "namespaceSelector")]
    pub namespace_selector: Option<BundleTargetNamespaceSelector>,
    /// Secret is the target Secret that all Bundle source data will be synced to.
    /// Using Secrets as targets is only supported if enabled at trust-manager startup.
    /// By default, trust-manager has no permissions for writing to secrets and can only read secrets in the trust namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<BundleTargetSecret>,
}

/// AdditionalFormats specifies any additional formats to write to the target
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BundleTargetAdditionalFormats {
    /// JKS requests a JKS-formatted binary trust bundle to be written to the target.
    /// The bundle has "changeit" as the default password.
    /// For more information refer to this link https://cert-manager.io/docs/faq/#keystore-passwords
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jks: Option<BundleTargetAdditionalFormatsJks>,
    /// PKCS12 requests a PKCS12-formatted binary trust bundle to be written to the target.
    /// The bundle is by default created without a password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pkcs12: Option<BundleTargetAdditionalFormatsPkcs12>,
}

/// JKS requests a JKS-formatted binary trust bundle to be written to the target.
/// The bundle has "changeit" as the default password.
/// For more information refer to this link https://cert-manager.io/docs/faq/#keystore-passwords
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BundleTargetAdditionalFormatsJks {
    /// Key is the key of the entry in the object's `data` field to be used.
    pub key: String,
    /// Password for JKS trust store
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// PKCS12 requests a PKCS12-formatted binary trust bundle to be written to the target.
/// The bundle is by default created without a password.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BundleTargetAdditionalFormatsPkcs12 {
    /// Key is the key of the entry in the object's `data` field to be used.
    pub key: String,
    /// Password for PKCS12 trust store
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// ConfigMap is the target ConfigMap in Namespaces that all Bundle source
/// data will be synced to.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BundleTargetConfigMap {
    /// Key is the key of the entry in the object's `data` field to be used.
    pub key: String,
}

/// NamespaceSelector will, if set, only sync the target resource in
/// Namespaces which match the selector.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BundleTargetNamespaceSelector {
    /// MatchLabels matches on the set of labels that must be present on a
    /// Namespace for the Bundle target to be synced there.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// Secret is the target Secret that all Bundle source data will be synced to.
/// Using Secrets as targets is only supported if enabled at trust-manager startup.
/// By default, trust-manager has no permissions for writing to secrets and can only read secrets in the trust namespace.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BundleTargetSecret {
    /// Key is the key of the entry in the object's `data` field to be used.
    pub key: String,
}

/// Status of the Bundle. This is set and managed automatically.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BundleStatus {
    /// List of status conditions to indicate the status of the Bundle.
    /// Known condition types are `Bundle`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// DefaultCAPackageVersion, if set and non-empty, indicates the version information
    /// which was retrieved when the set of default CAs was requested in the bundle
    /// source. This should only be set if useDefaultCAs was set to "true" on a source,
    /// and will be the same for the same version of a bundle with identical certificates.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "defaultCAVersion")]
    pub default_ca_version: Option<String>,
}

