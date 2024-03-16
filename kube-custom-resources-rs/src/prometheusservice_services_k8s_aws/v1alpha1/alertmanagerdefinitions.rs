// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/prometheusservice-controller/prometheusservice.services.k8s.aws/v1alpha1/alertmanagerdefinitions.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// AlertManagerDefinitionSpec defines the desired state of AlertManagerDefinition.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "prometheusservice.services.k8s.aws", version = "v1alpha1", kind = "AlertManagerDefinition", plural = "alertmanagerdefinitions")]
#[kube(namespaced)]
#[kube(status = "AlertManagerDefinitionStatus")]
#[kube(schema = "disabled")]
pub struct AlertManagerDefinitionSpec {
    pub configuration: String,
    /// The ID of the workspace in which to create the alert manager definition.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "workspaceID")]
    pub workspace_id: Option<String>,
    /// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference
    /// type to provide more user friendly syntax for references using 'from' field
    /// Ex:
    /// APIIDRef:
    /// 
    /// 
    /// 	from:
    /// 	  name: my-api
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "workspaceRef")]
    pub workspace_ref: Option<AlertManagerDefinitionWorkspaceRef>,
}

/// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference
/// type to provide more user friendly syntax for references using 'from' field
/// Ex:
/// APIIDRef:
/// 
/// 
/// 	from:
/// 	  name: my-api
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AlertManagerDefinitionWorkspaceRef {
    /// AWSResourceReference provides all the values necessary to reference another
    /// k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<AlertManagerDefinitionWorkspaceRefFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another
/// k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AlertManagerDefinitionWorkspaceRefFrom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// AlertManagerDefinitionStatus defines the observed state of AlertManagerDefinition
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AlertManagerDefinitionStatus {
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
    /// that is used to contain resource sync state, account ownership,
    /// constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<AlertManagerDefinitionStatusAckResourceMetadata>,
    /// All CRS managed by ACK have a common `Status.Conditions` member that
    /// contains a collection of `ackv1alpha1.Condition` objects that describe
    /// the various terminal states of the CR and its backend AWS service API
    /// resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// Status code of this definition.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "statusCode")]
    pub status_code: Option<String>,
    /// The reason for failure if any.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "statusReason")]
    pub status_reason: Option<String>,
}

/// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
/// that is used to contain resource sync state, account ownership,
/// constructed ARN for the resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AlertManagerDefinitionStatusAckResourceMetadata {
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

