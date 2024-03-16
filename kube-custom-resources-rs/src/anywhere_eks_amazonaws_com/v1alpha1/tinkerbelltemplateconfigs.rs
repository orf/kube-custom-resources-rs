// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws/eks-anywhere/anywhere.eks.amazonaws.com/v1alpha1/tinkerbelltemplateconfigs.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// TinkerbellTemplateConfigSpec defines the desired state of TinkerbellTemplateConfig.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "anywhere.eks.amazonaws.com", version = "v1alpha1", kind = "TinkerbellTemplateConfig", plural = "tinkerbelltemplateconfigs")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct TinkerbellTemplateConfigSpec {
    /// Template defines a Tinkerbell workflow template with specific tasks and actions.
    pub template: TinkerbellTemplateConfigTemplate,
}

/// Template defines a Tinkerbell workflow template with specific tasks and actions.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TinkerbellTemplateConfigTemplate {
    pub global_timeout: i64,
    pub id: String,
    pub name: String,
    pub tasks: Vec<TinkerbellTemplateConfigTemplateTasks>,
    pub version: String,
}

/// Task represents a task to be executed as part of a workflow.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TinkerbellTemplateConfigTemplateTasks {
    pub actions: Vec<TinkerbellTemplateConfigTemplateTasksActions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<BTreeMap<String, String>>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volumes: Option<Vec<String>>,
    pub worker: String,
}

/// Action is the basic executional unit for a workflow.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TinkerbellTemplateConfigTemplateTasksActions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<BTreeMap<String, String>>,
    pub image: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "on-failure")]
    pub on_failure: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "on-timeout")]
    pub on_timeout: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<String>,
    pub timeout: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volumes: Option<Vec<String>>,
}

/// TinkerbellTemplateConfigStatus defines the observed state of TinkerbellTemplateConfig.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TinkerbellTemplateConfigStatus {
}

