// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kubean-io/kubean/kubean.io/v1alpha1/manifests.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "kubean.io", version = "v1alpha1", kind = "Manifest", plural = "manifests")]
#[kube(status = "ManifestStatus")]
#[kube(schema = "disabled")]
pub struct ManifestSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<ManifestComponents>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docker: Option<Vec<ManifestDocker>>,
    /// KubeanVersion , the tag of kubean-io
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "kubeanVersion")]
    pub kubean_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "kubesprayVersion")]
    pub kubespray_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "localService")]
    pub local_service: Option<ManifestLocalService>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ManifestComponents {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "defaultVersion")]
    pub default_version: Option<String>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "versionRange")]
    pub version_range: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ManifestDocker {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "defaultVersion")]
    pub default_version: Option<String>,
    pub os: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "versionRange")]
    pub version_range: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ManifestLocalService {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "filesRepo")]
    pub files_repo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "hostsMap")]
    pub hosts_map: Option<Vec<ManifestLocalServiceHostsMap>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "imageRepo")]
    pub image_repo: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "imageRepoAuth")]
    pub image_repo_auth: Option<Vec<ManifestLocalServiceImageRepoAuth>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "imageRepoScheme")]
    pub image_repo_scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "yumRepos")]
    pub yum_repos: Option<BTreeMap<String, String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ManifestLocalServiceHostsMap {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ManifestLocalServiceImageRepoAuth {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "imageRepoAddress")]
    pub image_repo_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "passwordBase64")]
    pub password_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "userName")]
    pub user_name: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ManifestStatus {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "localAvailable")]
    pub local_available: Option<ManifestStatusLocalAvailable>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ManifestStatusLocalAvailable {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<ManifestStatusLocalAvailableComponents>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docker: Option<Vec<ManifestStatusLocalAvailableDocker>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "kubesprayImage")]
    pub kubespray_image: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ManifestStatusLocalAvailableComponents {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "versionRange")]
    pub version_range: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ManifestStatusLocalAvailableDocker {
    pub os: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "versionRange")]
    pub version_range: Option<Vec<String>>,
}

