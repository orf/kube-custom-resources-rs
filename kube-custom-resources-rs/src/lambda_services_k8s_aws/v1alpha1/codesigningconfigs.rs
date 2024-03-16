// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/lambda-controller/lambda.services.k8s.aws/v1alpha1/codesigningconfigs.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// CodeSigningConfigSpec defines the desired state of CodeSigningConfig.
/// 
/// 
/// Details about a Code signing configuration (https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html).
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "lambda.services.k8s.aws", version = "v1alpha1", kind = "CodeSigningConfig", plural = "codesigningconfigs")]
#[kube(namespaced)]
#[kube(status = "CodeSigningConfigStatus")]
#[kube(schema = "disabled")]
pub struct CodeSigningConfigSpec {
    /// Signing profiles for this code signing configuration.
    #[serde(rename = "allowedPublishers")]
    pub allowed_publishers: CodeSigningConfigAllowedPublishers,
    /// The code signing policies define the actions to take if the validation checks
    /// fail.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "codeSigningPolicies")]
    pub code_signing_policies: Option<CodeSigningConfigCodeSigningPolicies>,
    /// Descriptive name for this code signing configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Signing profiles for this code signing configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CodeSigningConfigAllowedPublishers {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "signingProfileVersionARNs")]
    pub signing_profile_version_ar_ns: Option<Vec<String>>,
}

/// The code signing policies define the actions to take if the validation checks
/// fail.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CodeSigningConfigCodeSigningPolicies {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "untrustedArtifactOnDeployment")]
    pub untrusted_artifact_on_deployment: Option<String>,
}

/// CodeSigningConfigStatus defines the observed state of CodeSigningConfig
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CodeSigningConfigStatus {
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
    /// that is used to contain resource sync state, account ownership,
    /// constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<CodeSigningConfigStatusAckResourceMetadata>,
    /// Unique identifer for the Code signing configuration.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "codeSigningConfigID")]
    pub code_signing_config_id: Option<String>,
    /// All CRS managed by ACK have a common `Status.Conditions` member that
    /// contains a collection of `ackv1alpha1.Condition` objects that describe
    /// the various terminal states of the CR and its backend AWS service API
    /// resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// The date and time that the Code signing configuration was last modified,
    /// in ISO-8601 format (YYYY-MM-DDThh:mm:ss.sTZD).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastModified")]
    pub last_modified: Option<String>,
}

/// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
/// that is used to contain resource sync state, account ownership,
/// constructed ARN for the resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CodeSigningConfigStatusAckResourceMetadata {
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

