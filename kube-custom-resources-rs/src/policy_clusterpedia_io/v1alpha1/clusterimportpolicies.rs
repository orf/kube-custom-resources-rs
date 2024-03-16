// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/clusterpedia-io/clusterpedia/policy.clusterpedia.io/v1alpha1/clusterimportpolicies.yaml --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "policy.clusterpedia.io", version = "v1alpha1", kind = "ClusterImportPolicy", plural = "clusterimportpolicies")]
#[kube(status = "ClusterImportPolicyStatus")]
#[kube(schema = "disabled")]
pub struct ClusterImportPolicySpec {
    #[serde(rename = "creationCondition")]
    pub creation_condition: String,
    #[serde(rename = "nameTemplate")]
    pub name_template: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<ClusterImportPolicyReferences>>,
    pub source: ClusterImportPolicySource,
    pub template: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterImportPolicyReferences {
    pub group: String,
    pub key: String,
    #[serde(rename = "nameTemplate")]
    pub name_template: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "namespaceTemplate")]
    pub namespace_template: Option<String>,
    pub resource: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub versions: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterImportPolicySource {
    pub group: String,
    pub resource: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "selectorTemplate")]
    pub selector_template: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub versions: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterImportPolicyStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
}

