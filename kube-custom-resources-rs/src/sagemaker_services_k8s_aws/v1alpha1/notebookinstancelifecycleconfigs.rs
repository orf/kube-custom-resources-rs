// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/sagemaker-controller/sagemaker.services.k8s.aws/v1alpha1/notebookinstancelifecycleconfigs.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// NotebookInstanceLifecycleConfigSpec defines the desired state of NotebookInstanceLifecycleConfig.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "sagemaker.services.k8s.aws", version = "v1alpha1", kind = "NotebookInstanceLifecycleConfig", plural = "notebookinstancelifecycleconfigs")]
#[kube(namespaced)]
#[kube(status = "NotebookInstanceLifecycleConfigStatus")]
#[kube(schema = "disabled")]
pub struct NotebookInstanceLifecycleConfigSpec {
    /// The name of the lifecycle configuration.
    #[serde(rename = "notebookInstanceLifecycleConfigName")]
    pub notebook_instance_lifecycle_config_name: String,
    /// A shell script that runs only once, when you create a notebook instance.
    /// The shell script must be a base64-encoded string.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "onCreate")]
    pub on_create: Option<Vec<NotebookInstanceLifecycleConfigOnCreate>>,
    /// A shell script that runs every time you start a notebook instance, including
    /// when you create the notebook instance. The shell script must be a base64-encoded
    /// string.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "onStart")]
    pub on_start: Option<Vec<NotebookInstanceLifecycleConfigOnStart>>,
}

/// Contains the notebook instance lifecycle configuration script.
/// 
/// 
/// Each lifecycle configuration script has a limit of 16384 characters.
/// 
/// 
/// The value of the $PATH environment variable that is available to both scripts
/// is /sbin:bin:/usr/sbin:/usr/bin.
/// 
/// 
/// View Amazon CloudWatch Logs for notebook instance lifecycle configurations
/// in log group /aws/sagemaker/NotebookInstances in log stream [notebook-instance-name]/[LifecycleConfigHook].
/// 
/// 
/// Lifecycle configuration scripts cannot run for longer than 5 minutes. If
/// a script runs for longer than 5 minutes, it fails and the notebook instance
/// is not created or started.
/// 
/// 
/// For information about notebook instance lifestyle configurations, see Step
/// 2.1: (Optional) Customize a Notebook Instance (https://docs.aws.amazon.com/sagemaker/latest/dg/notebook-lifecycle-config.html).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct NotebookInstanceLifecycleConfigOnCreate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

/// Contains the notebook instance lifecycle configuration script.
/// 
/// 
/// Each lifecycle configuration script has a limit of 16384 characters.
/// 
/// 
/// The value of the $PATH environment variable that is available to both scripts
/// is /sbin:bin:/usr/sbin:/usr/bin.
/// 
/// 
/// View Amazon CloudWatch Logs for notebook instance lifecycle configurations
/// in log group /aws/sagemaker/NotebookInstances in log stream [notebook-instance-name]/[LifecycleConfigHook].
/// 
/// 
/// Lifecycle configuration scripts cannot run for longer than 5 minutes. If
/// a script runs for longer than 5 minutes, it fails and the notebook instance
/// is not created or started.
/// 
/// 
/// For information about notebook instance lifestyle configurations, see Step
/// 2.1: (Optional) Customize a Notebook Instance (https://docs.aws.amazon.com/sagemaker/latest/dg/notebook-lifecycle-config.html).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct NotebookInstanceLifecycleConfigOnStart {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

/// NotebookInstanceLifecycleConfigStatus defines the observed state of NotebookInstanceLifecycleConfig
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct NotebookInstanceLifecycleConfigStatus {
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
    /// that is used to contain resource sync state, account ownership,
    /// constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<NotebookInstanceLifecycleConfigStatusAckResourceMetadata>,
    /// All CRS managed by ACK have a common `Status.Conditions` member that
    /// contains a collection of `ackv1alpha1.Condition` objects that describe
    /// the various terminal states of the CR and its backend AWS service API
    /// resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// A timestamp that tells when the lifecycle configuration was created.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "creationTime")]
    pub creation_time: Option<String>,
    /// A timestamp that tells when the lifecycle configuration was last modified.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastModifiedTime")]
    pub last_modified_time: Option<String>,
}

/// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
/// that is used to contain resource sync state, account ownership,
/// constructed ARN for the resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct NotebookInstanceLifecycleConfigStatusAckResourceMetadata {
    /// ARN is the Amazon Resource Name for the resource. This is a
    /// globally-unique identifier and is set only by the ACK service controller
    /// once the controller has orchestrated the creation of the resource OR
    /// when it has verified that an "adopted" resource (a resource where the
    /// ARN annotation was set by the Kubernetes user on the CR) exists and
    /// matches the supplied CR's Spec field values.
    /// TODO(vijat@): Find a better strategy for resources that do not have ARN in CreateOutputResponse
    /// https://github.com/aws/aws-controllers-k8s/issues/270
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arn: Option<String>,
    /// OwnerAccountID is the AWS Account ID of the account that owns the
    /// backend AWS service API resource.
    #[serde(rename = "ownerAccountID")]
    pub owner_account_id: String,
    /// Region is the AWS region in which the resource exists or will exist.
    pub region: String,
}

