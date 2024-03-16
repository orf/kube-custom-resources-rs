// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/sagemaker-controller/sagemaker.services.k8s.aws/v1alpha1/apps.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// AppSpec defines the desired state of App.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "sagemaker.services.k8s.aws", version = "v1alpha1", kind = "App", plural = "apps")]
#[kube(namespaced)]
#[kube(status = "AppStatus")]
#[kube(schema = "disabled")]
pub struct AppSpec {
    /// The name of the app.
    #[serde(rename = "appName")]
    pub app_name: String,
    /// The type of app.
    #[serde(rename = "appType")]
    pub app_type: String,
    /// The domain ID.
    #[serde(rename = "domainID")]
    pub domain_id: String,
    /// The instance type and the Amazon Resource Name (ARN) of the SageMaker image
    /// created on the instance.
    /// 
    /// 
    /// The value of InstanceType passed as part of the ResourceSpec in the CreateApp
    /// call overrides the value passed as part of the ResourceSpec configured for
    /// the user profile or the domain. If InstanceType is not specified in any of
    /// those three ResourceSpec values for a KernelGateway app, the CreateApp call
    /// fails with a request validation error.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "resourceSpec")]
    pub resource_spec: Option<AppResourceSpec>,
    /// Each tag consists of a key and an optional value. Tag keys must be unique
    /// per resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<AppTags>>,
    /// The user profile name. If this value is not set, then SpaceName must be set.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "userProfileName")]
    pub user_profile_name: Option<String>,
}

/// The instance type and the Amazon Resource Name (ARN) of the SageMaker image
/// created on the instance.
/// 
/// 
/// The value of InstanceType passed as part of the ResourceSpec in the CreateApp
/// call overrides the value passed as part of the ResourceSpec configured for
/// the user profile or the domain. If InstanceType is not specified in any of
/// those three ResourceSpec values for a KernelGateway app, the CreateApp call
/// fails with a request validation error.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AppResourceSpec {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "instanceType")]
    pub instance_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lifecycleConfigARN")]
    pub lifecycle_config_arn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sageMakerImageARN")]
    pub sage_maker_image_arn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sageMakerImageVersionARN")]
    pub sage_maker_image_version_arn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sageMakerImageVersionAlias")]
    pub sage_maker_image_version_alias: Option<String>,
}

/// A tag object that consists of a key and an optional value, used to manage
/// metadata for SageMaker Amazon Web Services resources.
/// 
/// 
/// You can add tags to notebook instances, training jobs, hyperparameter tuning
/// jobs, batch transform jobs, models, labeling jobs, work teams, endpoint configurations,
/// and endpoints. For more information on adding tags to SageMaker resources,
/// see AddTags (https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_AddTags.html).
/// 
/// 
/// For more information on adding metadata to your Amazon Web Services resources
/// with tagging, see Tagging Amazon Web Services resources (https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html).
/// For advice on best practices for managing Amazon Web Services resources with
/// tagging, see Tagging Best Practices: Implement an Effective Amazon Web Services
/// Resource Tagging Strategy (https://d1.awsstatic.com/whitepapers/aws-tagging-best-practices.pdf).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AppTags {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// AppStatus defines the observed state of App
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AppStatus {
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
    /// that is used to contain resource sync state, account ownership,
    /// constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<AppStatusAckResourceMetadata>,
    /// All CRS managed by ACK have a common `Status.Conditions` member that
    /// contains a collection of `ackv1alpha1.Condition` objects that describe
    /// the various terminal states of the CR and its backend AWS service API
    /// resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// The status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
/// that is used to contain resource sync state, account ownership,
/// constructed ARN for the resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AppStatusAckResourceMetadata {
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

