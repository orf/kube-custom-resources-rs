// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/istio/istio/networking.istio.io/v1beta1/proxyconfigs.yaml --derive=Default --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use std::collections::BTreeMap;
}
use self::prelude::*;

/// Provides configuration for individual workloads. See more details at: https://istio.io/docs/reference/config/networking/proxy-config.html
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "networking.istio.io", version = "v1beta1", kind = "ProxyConfig", plural = "proxyconfigs")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
#[kube(derive="Default")]
#[kube(derive="PartialEq")]
pub struct ProxyConfigSpec {
    /// The number of worker threads to run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<i32>,
    /// Additional environment variables for the proxy.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "environmentVariables")]
    pub environment_variables: Option<BTreeMap<String, String>>,
    /// Specifies the details of the proxy image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<ProxyConfigImage>,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<ProxyConfigSelector>,
}

/// Specifies the details of the proxy image.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ProxyConfigImage {
    /// The image type of the image.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "imageType")]
    pub image_type: Option<String>,
}

/// Optional.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ProxyConfigSelector {
    /// One or more labels that indicate a specific set of pods/VMs on which a policy should be applied.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

