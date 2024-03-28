// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/stolostron/cluster-templates-operator/clustertemplate.openshift.io/v1alpha1/config.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};

#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "clustertemplate.openshift.io", version = "v1alpha1", kind = "Config", plural = "config")]
#[kube(schema = "disabled")]
pub struct ConfigSpec {
    /// ArgoCd namespace where the ArgoCD instance is running
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "argoCDNamespace")]
    pub argo_cd_namespace: Option<String>,
    /// Override default timeout for logging into the new cluster. The default is set to 10 minutes
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "loginAttemptTimeoutOverride")]
    pub login_attempt_timeout_override: Option<String>,
    /// Flag that indicate if UI console plugin should be deployed
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "uiEnabled")]
    pub ui_enabled: Option<bool>,
    /// Custom UI image
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "uiImage")]
    pub ui_image: Option<String>,
}
