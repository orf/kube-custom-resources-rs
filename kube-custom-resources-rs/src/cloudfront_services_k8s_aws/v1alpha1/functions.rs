// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/cloudfront-controller/cloudfront.services.k8s.aws/v1alpha1/functions.yaml --derive=Default --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
}
use self::prelude::*;

/// FunctionSpec defines the desired state of Function.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "cloudfront.services.k8s.aws", version = "v1alpha1", kind = "Function", plural = "functions")]
#[kube(namespaced)]
#[kube(status = "FunctionStatus")]
#[kube(schema = "disabled")]
#[kube(derive="Default")]
#[kube(derive="PartialEq")]
pub struct FunctionSpec {
    /// The function code. For more information about writing a CloudFront function,
    /// see Writing function code for CloudFront Functions (https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/writing-function-code.html)
    /// in the Amazon CloudFront Developer Guide.
    #[serde(rename = "functionCode")]
    pub function_code: String,
    /// Configuration information about the function, including an optional comment
    /// and the function's runtime.
    #[serde(rename = "functionConfig")]
    pub function_config: FunctionFunctionConfig,
    /// A name to identify the function.
    pub name: String,
}

/// Configuration information about the function, including an optional comment
/// and the function's runtime.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FunctionFunctionConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
}

/// FunctionStatus defines the observed state of Function
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FunctionStatus {
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
    /// that is used to contain resource sync state, account ownership,
    /// constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<FunctionStatusAckResourceMetadata>,
    /// All CRS managed by ACK have a common `Status.Conditions` member that
    /// contains a collection of `ackv1alpha1.Condition` objects that describe
    /// the various terminal states of the CR and its backend AWS service API
    /// resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// The version identifier for the current version of the CloudFront function.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "eTag")]
    pub e_tag: Option<String>,
    /// Contains configuration information and metadata about a CloudFront function.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "functionSummary")]
    pub function_summary: Option<FunctionStatusFunctionSummary>,
    /// The URL of the CloudFront function. Use the URL to manage the function with
    /// the CloudFront API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

/// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
/// that is used to contain resource sync state, account ownership,
/// constructed ARN for the resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FunctionStatusAckResourceMetadata {
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

/// Contains configuration information and metadata about a CloudFront function.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FunctionStatusFunctionSummary {
    /// Contains configuration information about a CloudFront function.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "functionConfig")]
    pub function_config: Option<FunctionStatusFunctionSummaryFunctionConfig>,
    /// Contains metadata about a CloudFront function.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "functionMetadata")]
    pub function_metadata: Option<FunctionStatusFunctionSummaryFunctionMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Contains configuration information about a CloudFront function.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FunctionStatusFunctionSummaryFunctionConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
}

/// Contains metadata about a CloudFront function.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FunctionStatusFunctionSummaryFunctionMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "createdTime")]
    pub created_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "functionARN")]
    pub function_arn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastModifiedTime")]
    pub last_modified_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
}

