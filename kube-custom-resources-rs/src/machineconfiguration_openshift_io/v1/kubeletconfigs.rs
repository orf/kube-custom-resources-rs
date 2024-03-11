// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/openshift/api/machineconfiguration.openshift.io/v1/kubeletconfigs.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// KubeletConfigSpec defines the desired state of KubeletConfig
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "machineconfiguration.openshift.io", version = "v1", kind = "KubeletConfig", plural = "kubeletconfigs")]
#[kube(status = "KubeletConfigStatus")]
#[kube(schema = "disabled")]
pub struct KubeletConfigSpec {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "autoSizingReserved")]
    pub auto_sizing_reserved: Option<bool>,
    /// kubeletConfig fields are defined in kubernetes upstream. Please refer to the types defined in the version/commit used by OpenShift of the upstream kubernetes. It's important to note that, since the fields of the kubelet configuration are directly fetched from upstream the validation of those values is handled directly by the kubelet. Please refer to the upstream version of the relevant kubernetes for the valid values of these fields. Invalid values of the kubelet configuration fields may render cluster nodes unusable.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "kubeletConfig")]
    pub kubelet_config: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "logLevel")]
    pub log_level: Option<i32>,
    /// MachineConfigPoolSelector selects which pools the KubeletConfig shoud apply to. A nil selector will result in no pools being selected.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "machineConfigPoolSelector")]
    pub machine_config_pool_selector: Option<KubeletConfigMachineConfigPoolSelector>,
    /// If unset, the default is based on the apiservers.config.openshift.io/cluster resource. Note that only Old and Intermediate profiles are currently supported, and the maximum available minTLSVersion is VersionTLS12.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "tlsSecurityProfile")]
    pub tls_security_profile: Option<KubeletConfigTlsSecurityProfile>,
}

/// MachineConfigPoolSelector selects which pools the KubeletConfig shoud apply to. A nil selector will result in no pools being selected.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct KubeletConfigMachineConfigPoolSelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<KubeletConfigMachineConfigPoolSelectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct KubeletConfigMachineConfigPoolSelectorMatchExpressions {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// If unset, the default is based on the apiservers.config.openshift.io/cluster resource. Note that only Old and Intermediate profiles are currently supported, and the maximum available minTLSVersion is VersionTLS12.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct KubeletConfigTlsSecurityProfile {
    /// custom is a user-defined TLS security profile. Be extremely careful using a custom profile as invalid configurations can be catastrophic. An example custom profile looks like this: 
    ///  ciphers: 
    ///  - ECDHE-ECDSA-CHACHA20-POLY1305 
    ///  - ECDHE-RSA-CHACHA20-POLY1305 
    ///  - ECDHE-RSA-AES128-GCM-SHA256 
    ///  - ECDHE-ECDSA-AES128-GCM-SHA256 
    ///  minTLSVersion: VersionTLS11
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom: Option<KubeletConfigTlsSecurityProfileCustom>,
    /// intermediate is a TLS security profile based on: 
    ///  https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_.28recommended.29 
    ///  and looks like this (yaml): 
    ///  ciphers: 
    ///  - TLS_AES_128_GCM_SHA256 
    ///  - TLS_AES_256_GCM_SHA384 
    ///  - TLS_CHACHA20_POLY1305_SHA256 
    ///  - ECDHE-ECDSA-AES128-GCM-SHA256 
    ///  - ECDHE-RSA-AES128-GCM-SHA256 
    ///  - ECDHE-ECDSA-AES256-GCM-SHA384 
    ///  - ECDHE-RSA-AES256-GCM-SHA384 
    ///  - ECDHE-ECDSA-CHACHA20-POLY1305 
    ///  - ECDHE-RSA-CHACHA20-POLY1305 
    ///  - DHE-RSA-AES128-GCM-SHA256 
    ///  - DHE-RSA-AES256-GCM-SHA384 
    ///  minTLSVersion: VersionTLS12
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediate: Option<KubeletConfigTlsSecurityProfileIntermediate>,
    /// modern is a TLS security profile based on: 
    ///  https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility 
    ///  and looks like this (yaml): 
    ///  ciphers: 
    ///  - TLS_AES_128_GCM_SHA256 
    ///  - TLS_AES_256_GCM_SHA384 
    ///  - TLS_CHACHA20_POLY1305_SHA256 
    ///  minTLSVersion: VersionTLS13
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modern: Option<KubeletConfigTlsSecurityProfileModern>,
    /// old is a TLS security profile based on: 
    ///  https://wiki.mozilla.org/Security/Server_Side_TLS#Old_backward_compatibility 
    ///  and looks like this (yaml): 
    ///  ciphers: 
    ///  - TLS_AES_128_GCM_SHA256 
    ///  - TLS_AES_256_GCM_SHA384 
    ///  - TLS_CHACHA20_POLY1305_SHA256 
    ///  - ECDHE-ECDSA-AES128-GCM-SHA256 
    ///  - ECDHE-RSA-AES128-GCM-SHA256 
    ///  - ECDHE-ECDSA-AES256-GCM-SHA384 
    ///  - ECDHE-RSA-AES256-GCM-SHA384 
    ///  - ECDHE-ECDSA-CHACHA20-POLY1305 
    ///  - ECDHE-RSA-CHACHA20-POLY1305 
    ///  - DHE-RSA-AES128-GCM-SHA256 
    ///  - DHE-RSA-AES256-GCM-SHA384 
    ///  - DHE-RSA-CHACHA20-POLY1305 
    ///  - ECDHE-ECDSA-AES128-SHA256 
    ///  - ECDHE-RSA-AES128-SHA256 
    ///  - ECDHE-ECDSA-AES128-SHA 
    ///  - ECDHE-RSA-AES128-SHA 
    ///  - ECDHE-ECDSA-AES256-SHA384 
    ///  - ECDHE-RSA-AES256-SHA384 
    ///  - ECDHE-ECDSA-AES256-SHA 
    ///  - ECDHE-RSA-AES256-SHA 
    ///  - DHE-RSA-AES128-SHA256 
    ///  - DHE-RSA-AES256-SHA256 
    ///  - AES128-GCM-SHA256 
    ///  - AES256-GCM-SHA384 
    ///  - AES128-SHA256 
    ///  - AES256-SHA256 
    ///  - AES128-SHA 
    ///  - AES256-SHA 
    ///  - DES-CBC3-SHA 
    ///  minTLSVersion: VersionTLS10
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old: Option<KubeletConfigTlsSecurityProfileOld>,
    /// type is one of Old, Intermediate, Modern or Custom. Custom provides the ability to specify individual TLS security profile parameters. Old, Intermediate and Modern are TLS security profiles based on: 
    ///  https://wiki.mozilla.org/Security/Server_Side_TLS#Recommended_configurations 
    ///  The profiles are intent based, so they may change over time as new ciphers are developed and existing ciphers are found to be insecure.  Depending on precisely which ciphers are available to a process, the list may be reduced. 
    ///  Note that the Modern profile is currently not supported because it is not yet well adopted by common software libraries.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<KubeletConfigTlsSecurityProfileType>,
}

/// custom is a user-defined TLS security profile. Be extremely careful using a custom profile as invalid configurations can be catastrophic. An example custom profile looks like this: 
///  ciphers: 
///  - ECDHE-ECDSA-CHACHA20-POLY1305 
///  - ECDHE-RSA-CHACHA20-POLY1305 
///  - ECDHE-RSA-AES128-GCM-SHA256 
///  - ECDHE-ECDSA-AES128-GCM-SHA256 
///  minTLSVersion: VersionTLS11
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct KubeletConfigTlsSecurityProfileCustom {
    /// ciphers is used to specify the cipher algorithms that are negotiated during the TLS handshake.  Operators may remove entries their operands do not support.  For example, to use DES-CBC3-SHA  (yaml): 
    ///  ciphers: - DES-CBC3-SHA
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphers: Option<Vec<String>>,
    /// minTLSVersion is used to specify the minimal version of the TLS protocol that is negotiated during the TLS handshake. For example, to use TLS versions 1.1, 1.2 and 1.3 (yaml): 
    ///  minTLSVersion: VersionTLS11 
    ///  NOTE: currently the highest minTLSVersion allowed is VersionTLS12
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "minTLSVersion")]
    pub min_tls_version: Option<KubeletConfigTlsSecurityProfileCustomMinTlsVersion>,
}

/// custom is a user-defined TLS security profile. Be extremely careful using a custom profile as invalid configurations can be catastrophic. An example custom profile looks like this: 
///  ciphers: 
///  - ECDHE-ECDSA-CHACHA20-POLY1305 
///  - ECDHE-RSA-CHACHA20-POLY1305 
///  - ECDHE-RSA-AES128-GCM-SHA256 
///  - ECDHE-ECDSA-AES128-GCM-SHA256 
///  minTLSVersion: VersionTLS11
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum KubeletConfigTlsSecurityProfileCustomMinTlsVersion {
    #[serde(rename = "VersionTLS10")]
    VersionTls10,
    #[serde(rename = "VersionTLS11")]
    VersionTls11,
    #[serde(rename = "VersionTLS12")]
    VersionTls12,
    #[serde(rename = "VersionTLS13")]
    VersionTls13,
}

/// intermediate is a TLS security profile based on: 
///  https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_.28recommended.29 
///  and looks like this (yaml): 
///  ciphers: 
///  - TLS_AES_128_GCM_SHA256 
///  - TLS_AES_256_GCM_SHA384 
///  - TLS_CHACHA20_POLY1305_SHA256 
///  - ECDHE-ECDSA-AES128-GCM-SHA256 
///  - ECDHE-RSA-AES128-GCM-SHA256 
///  - ECDHE-ECDSA-AES256-GCM-SHA384 
///  - ECDHE-RSA-AES256-GCM-SHA384 
///  - ECDHE-ECDSA-CHACHA20-POLY1305 
///  - ECDHE-RSA-CHACHA20-POLY1305 
///  - DHE-RSA-AES128-GCM-SHA256 
///  - DHE-RSA-AES256-GCM-SHA384 
///  minTLSVersion: VersionTLS12
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct KubeletConfigTlsSecurityProfileIntermediate {
}

/// modern is a TLS security profile based on: 
///  https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility 
///  and looks like this (yaml): 
///  ciphers: 
///  - TLS_AES_128_GCM_SHA256 
///  - TLS_AES_256_GCM_SHA384 
///  - TLS_CHACHA20_POLY1305_SHA256 
///  minTLSVersion: VersionTLS13
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct KubeletConfigTlsSecurityProfileModern {
}

/// old is a TLS security profile based on: 
///  https://wiki.mozilla.org/Security/Server_Side_TLS#Old_backward_compatibility 
///  and looks like this (yaml): 
///  ciphers: 
///  - TLS_AES_128_GCM_SHA256 
///  - TLS_AES_256_GCM_SHA384 
///  - TLS_CHACHA20_POLY1305_SHA256 
///  - ECDHE-ECDSA-AES128-GCM-SHA256 
///  - ECDHE-RSA-AES128-GCM-SHA256 
///  - ECDHE-ECDSA-AES256-GCM-SHA384 
///  - ECDHE-RSA-AES256-GCM-SHA384 
///  - ECDHE-ECDSA-CHACHA20-POLY1305 
///  - ECDHE-RSA-CHACHA20-POLY1305 
///  - DHE-RSA-AES128-GCM-SHA256 
///  - DHE-RSA-AES256-GCM-SHA384 
///  - DHE-RSA-CHACHA20-POLY1305 
///  - ECDHE-ECDSA-AES128-SHA256 
///  - ECDHE-RSA-AES128-SHA256 
///  - ECDHE-ECDSA-AES128-SHA 
///  - ECDHE-RSA-AES128-SHA 
///  - ECDHE-ECDSA-AES256-SHA384 
///  - ECDHE-RSA-AES256-SHA384 
///  - ECDHE-ECDSA-AES256-SHA 
///  - ECDHE-RSA-AES256-SHA 
///  - DHE-RSA-AES128-SHA256 
///  - DHE-RSA-AES256-SHA256 
///  - AES128-GCM-SHA256 
///  - AES256-GCM-SHA384 
///  - AES128-SHA256 
///  - AES256-SHA256 
///  - AES128-SHA 
///  - AES256-SHA 
///  - DES-CBC3-SHA 
///  minTLSVersion: VersionTLS10
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct KubeletConfigTlsSecurityProfileOld {
}

/// If unset, the default is based on the apiservers.config.openshift.io/cluster resource. Note that only Old and Intermediate profiles are currently supported, and the maximum available minTLSVersion is VersionTLS12.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum KubeletConfigTlsSecurityProfileType {
    Old,
    Intermediate,
    Modern,
    Custom,
}

/// KubeletConfigStatus defines the observed state of a KubeletConfig
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct KubeletConfigStatus {
    /// conditions represents the latest available observations of current state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// observedGeneration represents the generation observed by the controller.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
}

