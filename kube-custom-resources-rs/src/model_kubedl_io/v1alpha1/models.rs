// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kubedl-io/kubedl/model.kubedl.io/v1alpha1/models.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};

#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "model.kubedl.io", version = "v1alpha1", kind = "Model", plural = "models")]
#[kube(namespaced)]
#[kube(status = "ModelStatus")]
#[kube(schema = "disabled")]
pub struct ModelSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModelStatus {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "latestVersion")]
    pub latest_version: Option<ModelStatusLatestVersion>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModelStatusLatestVersion {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "imageName")]
    pub image_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "modelVersion")]
    pub model_version: Option<String>,
}

