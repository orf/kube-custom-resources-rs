// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/apigatewayv2-controller/apigatewayv2.services.k8s.aws/v1alpha1/authorizers.yaml --derive=Default --derive=PartialEq
// kopium version: 0.16.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// AuthorizerSpec defines the desired state of Authorizer. 
///  Represents an authorizer.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "apigatewayv2.services.k8s.aws", version = "v1alpha1", kind = "Authorizer", plural = "authorizers")]
#[kube(namespaced)]
#[kube(status = "AuthorizerStatus")]
#[kube(schema = "disabled")]
pub struct AuthorizerSpec {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiID")]
    pub api_id: Option<String>,
    /// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference type to provide more user friendly syntax for references using 'from' field Ex: APIIDRef: 
    ///  from: name: my-api
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiRef")]
    pub api_ref: Option<AuthorizerApiRef>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "authorizerCredentialsARN")]
    pub authorizer_credentials_arn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "authorizerPayloadFormatVersion")]
    pub authorizer_payload_format_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "authorizerResultTTLInSeconds")]
    pub authorizer_result_ttl_in_seconds: Option<i64>,
    #[serde(rename = "authorizerType")]
    pub authorizer_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "authorizerURI")]
    pub authorizer_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "enableSimpleResponses")]
    pub enable_simple_responses: Option<bool>,
    #[serde(rename = "identitySource")]
    pub identity_source: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "identityValidationExpression")]
    pub identity_validation_expression: Option<String>,
    /// Represents the configuration of a JWT authorizer. Required for the JWT authorizer type. Supported only for HTTP APIs.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "jwtConfiguration")]
    pub jwt_configuration: Option<AuthorizerJwtConfiguration>,
    pub name: String,
}

/// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference type to provide more user friendly syntax for references using 'from' field Ex: APIIDRef: 
///  from: name: my-api
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AuthorizerApiRef {
    /// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<AuthorizerApiRefFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AuthorizerApiRefFrom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Represents the configuration of a JWT authorizer. Required for the JWT authorizer type. Supported only for HTTP APIs.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AuthorizerJwtConfiguration {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<Vec<String>>,
    /// A string representation of a URI with a length between [1-2048].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
}

/// AuthorizerStatus defines the observed state of Authorizer
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AuthorizerStatus {
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member that is used to contain resource sync state, account ownership, constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<AuthorizerStatusAckResourceMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "authorizerID")]
    pub authorizer_id: Option<String>,
    /// All CRS managed by ACK have a common `Status.Conditions` member that contains a collection of `ackv1alpha1.Condition` objects that describe the various terminal states of the CR and its backend AWS service API resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<AuthorizerStatusConditions>>,
}

/// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member that is used to contain resource sync state, account ownership, constructed ARN for the resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AuthorizerStatusAckResourceMetadata {
    /// ARN is the Amazon Resource Name for the resource. This is a globally-unique identifier and is set only by the ACK service controller once the controller has orchestrated the creation of the resource OR when it has verified that an "adopted" resource (a resource where the ARN annotation was set by the Kubernetes user on the CR) exists and matches the supplied CR's Spec field values. TODO(vijat@): Find a better strategy for resources that do not have ARN in CreateOutputResponse https://github.com/aws/aws-controllers-k8s/issues/270
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arn: Option<String>,
    /// OwnerAccountID is the AWS Account ID of the account that owns the backend AWS service API resource.
    #[serde(rename = "ownerAccountID")]
    pub owner_account_id: String,
    /// Region is the AWS region in which the resource exists or will exist.
    pub region: String,
}

/// Condition is the common struct used by all CRDs managed by ACK service controllers to indicate terminal states  of the CR and its backend AWS service API resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AuthorizerStatusConditions {
    /// Last time the condition transitioned from one status to another.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastTransitionTime")]
    pub last_transition_time: Option<String>,
    /// A human readable message indicating details about the transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// The reason for the condition's last transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Status of the condition, one of True, False, Unknown.
    pub status: String,
    /// Type is the type of the Condition
    #[serde(rename = "type")]
    pub r#type: String,
}
