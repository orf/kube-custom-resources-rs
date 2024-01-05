// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/ec2-controller/ec2.services.k8s.aws/v1alpha1/transitgateways.yaml --derive=Default --derive=PartialEq
// kopium version: 0.16.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// TransitGatewaySpec defines the desired state of TransitGateway. 
///  Describes a transit gateway.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "ec2.services.k8s.aws", version = "v1alpha1", kind = "TransitGateway", plural = "transitgateways")]
#[kube(namespaced)]
#[kube(status = "TransitGatewayStatus")]
#[kube(schema = "disabled")]
pub struct TransitGatewaySpec {
    /// A description of the transit gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The transit gateway options.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<TransitGatewayOptions>,
    /// The tags. The value parameter is required, but if you don't want the tag to have a value, specify the parameter with no value, and we set the value to an empty string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<TransitGatewayTags>>,
}

/// The transit gateway options.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TransitGatewayOptions {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "amazonSideASN")]
    pub amazon_side_asn: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "autoAcceptSharedAttachments")]
    pub auto_accept_shared_attachments: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "defaultRouteTableAssociation")]
    pub default_route_table_association: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "defaultRouteTablePropagation")]
    pub default_route_table_propagation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dnsSupport")]
    pub dns_support: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "multicastSupport")]
    pub multicast_support: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "transitGatewayCIDRBlocks")]
    pub transit_gateway_cidr_blocks: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vpnECMPSupport")]
    pub vpn_ecmp_support: Option<String>,
}

/// Describes a tag.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TransitGatewayTags {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// TransitGatewayStatus defines the observed state of TransitGateway
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TransitGatewayStatus {
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member that is used to contain resource sync state, account ownership, constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<TransitGatewayStatusAckResourceMetadata>,
    /// All CRS managed by ACK have a common `Status.Conditions` member that contains a collection of `ackv1alpha1.Condition` objects that describe the various terminal states of the CR and its backend AWS service API resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<TransitGatewayStatusConditions>>,
    /// The creation time.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "creationTime")]
    pub creation_time: Option<String>,
    /// The ID of the Amazon Web Services account that owns the transit gateway.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ownerID")]
    pub owner_id: Option<String>,
    /// The state of the transit gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// The ID of the transit gateway.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "transitGatewayID")]
    pub transit_gateway_id: Option<String>,
}

/// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member that is used to contain resource sync state, account ownership, constructed ARN for the resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TransitGatewayStatusAckResourceMetadata {
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
pub struct TransitGatewayStatusConditions {
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
