// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/tinkerbell/tink/tinkerbell.org/v1alpha2/workflows.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "tinkerbell.org", version = "v1alpha2", kind = "Workflow", plural = "workflows")]
#[kube(namespaced)]
#[kube(status = "WorkflowStatus")]
#[kube(schema = "disabled")]
pub struct WorkflowSpec {
    /// HardwareRef is a reference to a Hardware resource this workflow will execute on.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "hardwareRef")]
    pub hardware_ref: Option<WorkflowHardwareRef>,
    /// TemplateParams are a list of key-value pairs that are injected into templates at render
    /// time. TemplateParams are exposed to templates using a top level .Params key.
    /// 
    /// 
    /// For example, TemplateParams = {"foo": "bar"}, the foo key can be accessed via .Params.foo.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "templateParams")]
    pub template_params: Option<BTreeMap<String, String>>,
    /// TemplateRef is a reference to a Template resource used to render workflow actions.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "templateRef")]
    pub template_ref: Option<WorkflowTemplateRef>,
    /// TimeoutSeconds defines the time the workflow has to complete. The timer begins when the first
    /// action is requested. When set to 0, no timeout is applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<i64>,
}

/// HardwareRef is a reference to a Hardware resource this workflow will execute on.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct WorkflowHardwareRef {
    /// Name of the referent.
    /// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
    /// TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// TemplateRef is a reference to a Template resource used to render workflow actions.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct WorkflowTemplateRef {
    /// Name of the referent.
    /// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
    /// TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct WorkflowStatus {
    /// Actions is a list of action states.
    pub actions: Vec<WorkflowStatusActions>,
    /// Conditions details a set of observations about the Workflow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// LastTransition is the observed time when State transitioned last.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastTransitioned")]
    pub last_transitioned: Option<String>,
    /// StartedAt is the time the first action was requested. Nil indicates the Workflow has not
    /// started.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "startedAt")]
    pub started_at: Option<String>,
    /// State describes the current state of the Workflow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// ActionStatus describes status information about an action.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct WorkflowStatusActions {
    /// FailureMessage is a free-form user friendly message describing why the Action entered the
    /// ActionStateFailed state. Typically, this is an elaboration on the Reason.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "failureMessage")]
    pub failure_message: Option<String>,
    /// FailureReason is a short CamelCase word or phrase describing why the Action entered
    /// ActionStateFailed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "failureReason")]
    pub failure_reason: Option<String>,
    /// ID uniquely identifies the action status.
    pub id: String,
    /// LastTransition is the observed time when State transitioned last.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastTransitioned")]
    pub last_transitioned: Option<String>,
    /// Rendered is the rendered action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rendered: Option<WorkflowStatusActionsRendered>,
    /// StartedAt is the time the action was started as reported by the client. Nil indicates the
    /// Action has not started.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "startedAt")]
    pub started_at: Option<String>,
    /// State describes the current state of the action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// Rendered is the rendered action.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct WorkflowStatusActionsRendered {
    /// Args are a set of arguments to be passed to the command executed by the container on
    /// launch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    /// Cmd defines the command to use when launching the image. It overrides the default command
    /// of the action. It must be a unix path to an executable program.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmd: Option<String>,
    /// Env defines environment variables used when launching the container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<BTreeMap<String, String>>,
    /// Image is an OCI image.
    pub image: String,
    /// Name is a name for the action.
    pub name: String,
    /// Namespace defines the Linux namespaces this container should execute in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<WorkflowStatusActionsRenderedNamespaces>,
    /// Volumes defines the volumes to mount into the container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volumes: Option<Vec<String>>,
}

/// Namespace defines the Linux namespaces this container should execute in.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct WorkflowStatusActionsRenderedNamespaces {
    /// Network defines the network namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// PID defines the PID namespace
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<i64>,
}

