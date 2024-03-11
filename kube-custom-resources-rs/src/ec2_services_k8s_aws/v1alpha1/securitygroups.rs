// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/ec2-controller/ec2.services.k8s.aws/v1alpha1/securitygroups.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// SecurityGroupSpec defines the desired state of SecurityGroup.
/// 
/// 
/// Describes a security group.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "ec2.services.k8s.aws", version = "v1alpha1", kind = "SecurityGroup", plural = "securitygroups")]
#[kube(namespaced)]
#[kube(status = "SecurityGroupStatus")]
#[kube(schema = "disabled")]
pub struct SecurityGroupSpec {
    /// A description for the security group. This is informational only.
    /// 
    /// 
    /// Constraints: Up to 255 characters in length
    /// 
    /// 
    /// Constraints for EC2-Classic: ASCII characters
    /// 
    /// 
    /// Constraints for EC2-VPC: a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=&;{}!$*
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "egressRules")]
    pub egress_rules: Option<Vec<SecurityGroupEgressRules>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ingressRules")]
    pub ingress_rules: Option<Vec<SecurityGroupIngressRules>>,
    /// The name of the security group.
    /// 
    /// 
    /// Constraints: Up to 255 characters in length. Cannot start with sg-.
    /// 
    /// 
    /// Constraints for EC2-Classic: ASCII characters
    /// 
    /// 
    /// Constraints for EC2-VPC: a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=&;{}!$*
    pub name: String,
    /// The tags. The value parameter is required, but if you don't want the tag
    /// to have a value, specify the parameter with no value, and we set the value
    /// to an empty string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<SecurityGroupTags>>,
    /// [EC2-VPC] The ID of the VPC. Required for EC2-VPC.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vpcID")]
    pub vpc_id: Option<String>,
    /// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference
    /// type to provide more user friendly syntax for references using 'from' field
    /// Ex:
    /// APIIDRef:
    /// 
    /// 
    /// 	from:
    /// 	  name: my-api
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vpcRef")]
    pub vpc_ref: Option<SecurityGroupVpcRef>,
}

/// Describes a set of permissions for a security group rule.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SecurityGroupEgressRules {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "fromPort")]
    pub from_port: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ipProtocol")]
    pub ip_protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ipRanges")]
    pub ip_ranges: Option<Vec<SecurityGroupEgressRulesIpRanges>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ipv6Ranges")]
    pub ipv6_ranges: Option<Vec<SecurityGroupEgressRulesIpv6Ranges>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "prefixListIDs")]
    pub prefix_list_i_ds: Option<Vec<SecurityGroupEgressRulesPrefixListIDs>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "toPort")]
    pub to_port: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "userIDGroupPairs")]
    pub user_id_group_pairs: Option<Vec<SecurityGroupEgressRulesUserIdGroupPairs>>,
}

/// Describes an IPv4 range.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SecurityGroupEgressRulesIpRanges {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "cidrIP")]
    pub cidr_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// [EC2-VPC only] Describes an IPv6 range.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SecurityGroupEgressRulesIpv6Ranges {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "cidrIPv6")]
    pub cidr_i_pv6: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Describes a prefix list ID.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SecurityGroupEgressRulesPrefixListIDs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "prefixListID")]
    pub prefix_list_id: Option<String>,
}

/// Describes a security group and Amazon Web Services account ID pair.
/// 
/// 
/// We are retiring EC2-Classic on August 15, 2022. We recommend that you migrate
/// from EC2-Classic to a VPC. For more information, see Migrate from EC2-Classic
/// to a VPC (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/vpc-migrate.html)
/// in the Amazon Elastic Compute Cloud User Guide.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SecurityGroupEgressRulesUserIdGroupPairs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "groupID")]
    pub group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "groupName")]
    pub group_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "peeringStatus")]
    pub peering_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "userID")]
    pub user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vpcID")]
    pub vpc_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vpcPeeringConnectionID")]
    pub vpc_peering_connection_id: Option<String>,
}

/// Describes a set of permissions for a security group rule.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SecurityGroupIngressRules {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "fromPort")]
    pub from_port: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ipProtocol")]
    pub ip_protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ipRanges")]
    pub ip_ranges: Option<Vec<SecurityGroupIngressRulesIpRanges>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ipv6Ranges")]
    pub ipv6_ranges: Option<Vec<SecurityGroupIngressRulesIpv6Ranges>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "prefixListIDs")]
    pub prefix_list_i_ds: Option<Vec<SecurityGroupIngressRulesPrefixListIDs>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "toPort")]
    pub to_port: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "userIDGroupPairs")]
    pub user_id_group_pairs: Option<Vec<SecurityGroupIngressRulesUserIdGroupPairs>>,
}

/// Describes an IPv4 range.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SecurityGroupIngressRulesIpRanges {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "cidrIP")]
    pub cidr_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// [EC2-VPC only] Describes an IPv6 range.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SecurityGroupIngressRulesIpv6Ranges {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "cidrIPv6")]
    pub cidr_i_pv6: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Describes a prefix list ID.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SecurityGroupIngressRulesPrefixListIDs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "prefixListID")]
    pub prefix_list_id: Option<String>,
}

/// Describes a security group and Amazon Web Services account ID pair.
/// 
/// 
/// We are retiring EC2-Classic on August 15, 2022. We recommend that you migrate
/// from EC2-Classic to a VPC. For more information, see Migrate from EC2-Classic
/// to a VPC (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/vpc-migrate.html)
/// in the Amazon Elastic Compute Cloud User Guide.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SecurityGroupIngressRulesUserIdGroupPairs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "groupID")]
    pub group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "groupName")]
    pub group_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "peeringStatus")]
    pub peering_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "userID")]
    pub user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vpcID")]
    pub vpc_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vpcPeeringConnectionID")]
    pub vpc_peering_connection_id: Option<String>,
}

/// Describes a tag.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SecurityGroupTags {
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
pub struct SecurityGroupVpcRef {
    /// AWSResourceReference provides all the values necessary to reference another
    /// k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<SecurityGroupVpcRefFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another
/// k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SecurityGroupVpcRefFrom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// SecurityGroupStatus defines the observed state of SecurityGroup
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SecurityGroupStatus {
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
    /// that is used to contain resource sync state, account ownership,
    /// constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<SecurityGroupStatusAckResourceMetadata>,
    /// All CRS managed by ACK have a common `Status.Conditions` member that
    /// contains a collection of `ackv1alpha1.Condition` objects that describe
    /// the various terminal states of the CR and its backend AWS service API
    /// resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// The ID of the security group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Information about security group rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<SecurityGroupStatusRules>>,
}

/// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
/// that is used to contain resource sync state, account ownership,
/// constructed ARN for the resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SecurityGroupStatusAckResourceMetadata {
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

/// Describes a security group rule.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SecurityGroupStatusRules {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "cidrIPv4")]
    pub cidr_i_pv4: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "cidrIPv6")]
    pub cidr_i_pv6: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "fromPort")]
    pub from_port: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ipProtocol")]
    pub ip_protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "isEgress")]
    pub is_egress: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "prefixListID")]
    pub prefix_list_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "securityGroupRuleID")]
    pub security_group_rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<SecurityGroupStatusRulesTags>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "toPort")]
    pub to_port: Option<i64>,
}

/// Describes a tag.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SecurityGroupStatusRulesTags {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

