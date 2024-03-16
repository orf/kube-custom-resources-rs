// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/shipwright-io/operator/operator.shipwright.io/v1alpha1/shipwrightbuilds.yaml --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// ShipwrightBuildSpec defines the configuration of a Shipwright Build deployment.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "operator.shipwright.io", version = "v1alpha1", kind = "ShipwrightBuild", plural = "shipwrightbuilds")]
#[kube(status = "ShipwrightBuildStatus")]
#[kube(schema = "disabled")]
pub struct ShipwrightBuildSpec {
    /// TargetNamespace is the target namespace where Shipwright's build controller will be deployed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "targetNamespace")]
    pub target_namespace: Option<String>,
}

/// ShipwrightBuildStatus defines the observed state of ShipwrightBuild
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ShipwrightBuildStatus {
    /// Conditions holds the latest available observations of a resource's current state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
}

