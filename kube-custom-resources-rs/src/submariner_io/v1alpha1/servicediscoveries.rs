// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/submariner-io/submariner-operator/submariner.io/v1alpha1/servicediscoveries.yaml --derive=Default --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use std::collections::BTreeMap;
}
use self::prelude::*;

/// ServiceDiscoverySpec defines the desired state of ServiceDiscovery.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "submariner.io", version = "v1alpha1", kind = "ServiceDiscovery", plural = "servicediscoveries")]
#[kube(namespaced)]
#[kube(status = "ServiceDiscoveryStatus")]
#[kube(schema = "disabled")]
#[kube(derive="Default")]
#[kube(derive="PartialEq")]
pub struct ServiceDiscoverySpec {
    #[serde(rename = "brokerK8sApiServer")]
    pub broker_k8s_api_server: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "brokerK8sApiServerToken")]
    pub broker_k8s_api_server_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "brokerK8sCA")]
    pub broker_k8s_ca: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "brokerK8sInsecure")]
    pub broker_k8s_insecure: Option<bool>,
    #[serde(rename = "brokerK8sRemoteNamespace")]
    pub broker_k8s_remote_namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "brokerK8sSecret")]
    pub broker_k8s_secret: Option<String>,
    #[serde(rename = "clusterID")]
    pub cluster_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "coreDNSCustomConfig")]
    pub core_dns_custom_config: Option<ServiceDiscoveryCoreDnsCustomConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "customDomains")]
    pub custom_domains: Option<Vec<String>>,
    pub debug: bool,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "globalnetEnabled")]
    pub globalnet_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "haltOnCertificateError")]
    pub halt_on_certificate_error: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "imageOverrides")]
    pub image_overrides: Option<BTreeMap<String, String>>,
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nodeSelector")]
    pub node_selector: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tolerations: Option<Vec<ServiceDiscoveryTolerations>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ServiceDiscoveryCoreDnsCustomConfig {
    /// Name of the custom CoreDNS configmap.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "configMapName")]
    pub config_map_name: Option<String>,
    /// Namespace of the custom CoreDNS configmap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// The pod this Toleration is attached to tolerates any taint that matches the triple <key,value,effect> using the matching operator <operator>.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ServiceDiscoveryTolerations {
    /// Effect indicates the taint effect to match. Empty means match all taint effects. When specified, allowed values are NoSchedule, PreferNoSchedule and NoExecute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<String>,
    /// Key is the taint key that the toleration applies to. Empty means match all taint keys. If the key is empty, operator must be Exists; this combination means to match all values and all keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Operator represents a key's relationship to the value. Valid operators are Exists and Equal. Defaults to Equal. Exists is equivalent to wildcard for value, so that a pod can tolerate all taints of a particular category.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    /// TolerationSeconds represents the period of time the toleration (which must be of effect NoExecute, otherwise this field is ignored) tolerates the taint. By default, it is not set, which means tolerate the taint forever (do not evict). Zero and negative values will be treated as 0 (evict immediately) by the system.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "tolerationSeconds")]
    pub toleration_seconds: Option<i64>,
    /// Value is the taint value the toleration matches to. If the operator is Exists, the value should be empty, otherwise just a regular string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// ServiceDiscoveryStatus defines the observed state of ServiceDiscovery.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ServiceDiscoveryStatus {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "deploymentInfo")]
    pub deployment_info: Option<ServiceDiscoveryStatusDeploymentInfo>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ServiceDiscoveryStatusDeploymentInfo {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "cloudProvider")]
    pub cloud_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "kubernetesType")]
    pub kubernetes_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "kubernetesTypeVersion")]
    pub kubernetes_type_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "kubernetesVersion")]
    pub kubernetes_version: Option<String>,
}

