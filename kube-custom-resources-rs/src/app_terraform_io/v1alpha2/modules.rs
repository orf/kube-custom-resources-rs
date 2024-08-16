// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/hashicorp/terraform-cloud-operator/app.terraform.io/v1alpha2/modules.yaml --derive=Default --derive=PartialEq --smart-derive-elision
// kopium version: 0.20.1

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
}
use self::prelude::*;

/// ModuleSpec defines the desired state of Module.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "app.terraform.io", version = "v1alpha2", kind = "Module", plural = "modules")]
#[kube(namespaced)]
#[kube(status = "ModuleStatus")]
#[kube(schema = "disabled")]
#[kube(derive="Default")]
#[kube(derive="PartialEq")]
pub struct ModuleSpec {
    /// Specify whether or not to execute a Destroy run when the object is deleted from the Kubernetes.
    /// Default: `false`.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "destroyOnDeletion")]
    pub destroy_on_deletion: Option<bool>,
    /// Module source and version to execute.
    pub module: ModuleModule,
    /// Name of the module that will be uploaded and executed.
    /// Default: `this`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Organization name where the Workspace will be created.
    /// More information:
    ///   - https://developer.hashicorp.com/terraform/cloud-docs/users-teams-organizations/organizations
    pub organization: String,
    /// Module outputs to store in ConfigMap(non-sensitive) or Secret(sensitive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outputs: Option<Vec<ModuleOutputs>>,
    /// Allows executing a new Run without changing any Workspace or Module attributes.
    /// Example: kubectl patch <KIND> <NAME> --type=merge --patch '{"spec": {"restartedAt": "'\`date -u -Iseconds\`'"}}'
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "restartedAt")]
    pub restarted_at: Option<String>,
    /// API Token to be used for API calls.
    pub token: ModuleToken,
    /// Variables to pass to the module, they must exist in the Workspace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variables: Option<Vec<ModuleVariables>>,
    /// Workspace to execute the module.
    pub workspace: ModuleWorkspace,
}

/// Module source and version to execute.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModuleModule {
    /// Non local Terraform module source.
    /// More information:
    ///   - https://developer.hashicorp.com/terraform/language/modules/sources
    pub source: String,
    /// Terraform module version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Module outputs to store in ConfigMap(non-sensitive) or Secret(sensitive).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModuleOutputs {
    /// Output name must match with the module output.
    pub name: String,
    /// Specify whether or not the output is sensitive.
    /// Default: `false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<bool>,
}

/// API Token to be used for API calls.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModuleToken {
    /// Selects a key of a secret in the workspace's namespace
    #[serde(rename = "secretKeyRef")]
    pub secret_key_ref: ModuleTokenSecretKeyRef,
}

/// Selects a key of a secret in the workspace's namespace
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModuleTokenSecretKeyRef {
    /// The key of the secret to select from.  Must be a valid secret key.
    pub key: String,
    /// Name of the referent.
    /// This field is effectively required, but due to backwards compatibility is
    /// allowed to be empty. Instances of this type with an empty value here are
    /// almost certainly wrong.
    /// TODO: Add other useful fields. apiVersion, kind, uid?
    /// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
    /// TODO: Drop `kubebuilder:default` when controller-gen doesn't need it https://github.com/kubernetes-sigs/kubebuilder/issues/3896.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Specify whether the Secret or its key must be defined
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// Variables to pass to the module.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModuleVariables {
    /// Variable name must exist in the Workspace.
    pub name: String,
}

/// Workspace to execute the module.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModuleWorkspace {
    /// Module Workspace ID.
    /// Must match pattern: `^ws-[a-zA-Z0-9]+$`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Module Workspace Name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// ModuleStatus defines the observed state of Module.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModuleStatus {
    /// A configuration version is a resource used to reference the uploaded configuration files.
    /// More information:
    ///   - https://developer.hashicorp.com/terraform/cloud-docs/api-docs/configuration-versions
    ///   - https://developer.hashicorp.com/terraform/cloud-docs/run/api
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "configurationVersion")]
    pub configuration_version: Option<ModuleStatusConfigurationVersion>,
    /// Workspace Destroy Run status.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "destroyRunID")]
    pub destroy_run_id: Option<String>,
    /// Real world state generation.
    #[serde(rename = "observedGeneration")]
    pub observed_generation: i64,
    /// Module Outputs status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<ModuleStatusOutput>,
    /// Workspace Runs status.
    /// More information:
    ///   - https://developer.hashicorp.com/terraform/cloud-docs/run/states
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<ModuleStatusRun>,
    /// Workspace ID where the module is running.
    #[serde(rename = "workspaceID")]
    pub workspace_id: String,
}

/// A configuration version is a resource used to reference the uploaded configuration files.
/// More information:
///   - https://developer.hashicorp.com/terraform/cloud-docs/api-docs/configuration-versions
///   - https://developer.hashicorp.com/terraform/cloud-docs/run/api
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModuleStatusConfigurationVersion {
    /// Configuration Version ID.
    pub id: String,
    /// Configuration Version Status.
    pub status: String,
}

/// Module Outputs status.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModuleStatusOutput {
    /// Run ID of the latest run that updated the outputs.
    #[serde(rename = "runID")]
    pub run_id: String,
}

/// Workspace Runs status.
/// More information:
///   - https://developer.hashicorp.com/terraform/cloud-docs/run/states
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModuleStatusRun {
    /// The configuration version of this run.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "configurationVersion")]
    pub configuration_version: Option<String>,
    /// Current(both active and finished) HCP Terraform run ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Run ID of the latest run that could update the outputs.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "outputRunID")]
    pub output_run_id: Option<String>,
    /// Current(both active and finished) HCP Terraform run status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

