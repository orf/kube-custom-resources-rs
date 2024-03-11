// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/KaotoIO/kaoto-operator/designer.kaoto.io/v1alpha1/kaotoes.yaml --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// KaotoSpec defines the desired state of Kaoto.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "designer.kaoto.io", version = "v1alpha1", kind = "Kaoto", plural = "kaotoes")]
#[kube(namespaced)]
#[kube(status = "KaotoStatus")]
#[kube(schema = "disabled")]
pub struct KaotoSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress: Option<KaotoIngress>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KaotoIngress {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// KaotoStatus defines the observed state of Kaoto.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KaotoStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
    pub phase: String,
}

