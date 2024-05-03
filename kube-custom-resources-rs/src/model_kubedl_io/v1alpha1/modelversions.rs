// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kubedl-io/kubedl/model.kubedl.io/v1alpha1/modelversions.yaml --derive=Default --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use std::collections::BTreeMap;
}
use self::prelude::*;

#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "model.kubedl.io", version = "v1alpha1", kind = "ModelVersion", plural = "modelversions")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
#[kube(derive="Default")]
#[kube(derive="PartialEq")]
pub struct ModelVersionSpec {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "createdBy")]
    pub created_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "imageRepo")]
    pub image_repo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "imageTag")]
    pub image_tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "modelName")]
    pub model_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<ModelVersionStorage>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModelVersionStorage {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "AWSEfs")]
    pub aws_efs: Option<ModelVersionStorageAwsEfs>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "localStorage")]
    pub local_storage: Option<ModelVersionStorageLocalStorage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nfs: Option<ModelVersionStorageNfs>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModelVersionStorageAwsEfs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "volumeHandle")]
    pub volume_handle: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModelVersionStorageLocalStorage {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "mountPath")]
    pub mount_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nodeName")]
    pub node_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModelVersionStorageNfs {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "mountPath")]
    pub mount_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModelVersionStatus {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "finishTime")]
    pub finish_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "imageBuildPhase")]
    pub image_build_phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

