// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/tinkerbell/tink/tinkerbell.org/v1alpha1/workflows.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// WorkflowSpec defines the desired state of Workflow.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "tinkerbell.org", version = "v1alpha1", kind = "Workflow", plural = "workflows")]
#[kube(namespaced)]
#[kube(status = "WorkflowStatus")]
#[kube(schema = "disabled")]
pub struct WorkflowSpec {
    /// A mapping of template devices to hadware mac addresses
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "hardwareMap")]
    pub hardware_map: Option<BTreeMap<String, String>>,
    /// Name of the Hardware associated with this workflow.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "hardwareRef")]
    pub hardware_ref: Option<String>,
    /// Name of the Template associated with this workflow.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "templateRef")]
    pub template_ref: Option<String>,
}

/// WorkflowStatus defines the observed state of Workflow.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct WorkflowStatus {
    /// GlobalTimeout represents the max execution time
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "globalTimeout")]
    pub global_timeout: Option<i64>,
    /// State is the state of the workflow in Tinkerbell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Tasks are the tasks to be completed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tasks: Option<Vec<WorkflowStatusTasks>>,
}

/// Task represents a series of actions to be completed by a worker.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct WorkflowStatusTasks {
    pub actions: Vec<WorkflowStatusTasksActions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<BTreeMap<String, String>>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volumes: Option<Vec<String>>,
    pub worker: String,
}

/// Action represents a workflow action.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct WorkflowStatusTasksActions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seconds: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "startedAt")]
    pub started_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volumes: Option<Vec<String>>,
}

