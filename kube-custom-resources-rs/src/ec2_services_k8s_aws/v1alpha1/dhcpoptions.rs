// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/ec2-controller/ec2.services.k8s.aws/v1alpha1/dhcpoptions.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// DhcpOptionsSpec defines the desired state of DhcpOptions.
/// 
/// 
/// Describes a set of DHCP options.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "ec2.services.k8s.aws", version = "v1alpha1", kind = "DHCPOptions", plural = "dhcpoptions")]
#[kube(namespaced)]
#[kube(status = "DHCPOptionsStatus")]
#[kube(schema = "disabled")]
pub struct DHCPOptionsSpec {
    /// A DHCP configuration option.
    #[serde(rename = "dhcpConfigurations")]
    pub dhcp_configurations: Vec<DHCPOptionsDhcpConfigurations>,
    /// The tags. The value parameter is required, but if you don't want the tag
    /// to have a value, specify the parameter with no value, and we set the value
    /// to an empty string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<DHCPOptionsTags>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpc: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vpcRefs")]
    pub vpc_refs: Option<Vec<DHCPOptionsVpcRefs>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct DHCPOptionsDhcpConfigurations {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// Describes a tag.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct DHCPOptionsTags {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
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
pub struct DHCPOptionsVpcRefs {
    /// AWSResourceReference provides all the values necessary to reference another
    /// k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<DHCPOptionsVpcRefsFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another
/// k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct DHCPOptionsVpcRefsFrom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// DHCPOptionsStatus defines the observed state of DHCPOptions
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct DHCPOptionsStatus {
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
    /// that is used to contain resource sync state, account ownership,
    /// constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<DHCPOptionsStatusAckResourceMetadata>,
    /// All CRS managed by ACK have a common `Status.Conditions` member that
    /// contains a collection of `ackv1alpha1.Condition` objects that describe
    /// the various terminal states of the CR and its backend AWS service API
    /// resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// The ID of the set of DHCP options.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dhcpOptionsID")]
    pub dhcp_options_id: Option<String>,
    /// The ID of the Amazon Web Services account that owns the DHCP options set.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ownerID")]
    pub owner_id: Option<String>,
}

/// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
/// that is used to contain resource sync state, account ownership,
/// constructed ARN for the resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct DHCPOptionsStatusAckResourceMetadata {
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

