// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/organizations-controller/organizations.services.k8s.aws/v1alpha1/organizationalunits.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// OrganizationalUnitSpec defines the desired state of OrganizationalUnit.
/// 
/// 
/// Contains details about an organizational unit (OU). An OU is a container
/// of Amazon Web Services accounts within a root of an organization. Policies
/// that are attached to an OU apply to all accounts contained in that OU and
/// in any child OUs.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "organizations.services.k8s.aws", version = "v1alpha1", kind = "OrganizationalUnit", plural = "organizationalunits")]
#[kube(namespaced)]
#[kube(status = "OrganizationalUnitStatus")]
#[kube(schema = "disabled")]
pub struct OrganizationalUnitSpec {
    /// The friendly name to assign to the new OU.
    pub name: String,
    /// The unique identifier (ID) of the parent root or OU that you want to create
    /// the new OU in.
    /// 
    /// 
    /// The regex pattern (http://wikipedia.org/wiki/regex) for a parent ID string
    /// requires one of the following:
    /// 
    /// 
    ///    * Root - A string that begins with "r-" followed by from 4 to 32 lowercase
    ///    letters or digits.
    /// 
    /// 
    ///    * Organizational unit (OU) - A string that begins with "ou-" followed
    ///    by from 4 to 32 lowercase letters or digits (the ID of the root that the
    ///    OU is in). This string is followed by a second "-" dash and from 8 to
    ///    32 additional lowercase letters or digits.
    #[serde(rename = "parentID")]
    pub parent_id: String,
    /// A list of tags that you want to attach to the newly created OU. For each
    /// tag in the list, you must specify both a tag key and a value. You can set
    /// the value to an empty string, but you can't set it to null. For more information
    /// about tagging, see Tagging Organizations resources (https://docs.aws.amazon.com/organizations/latest/userguide/orgs_tagging.html)
    /// in the Organizations User Guide.
    /// 
    /// 
    /// If any one of the tags is invalid or if you exceed the allowed number of
    /// tags for an OU, then the entire request fails and the OU is not created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<OrganizationalUnitTags>>,
}

/// A custom key-value pair associated with a resource within your organization.
/// 
/// 
/// You can attach tags to any of the following organization resources.
/// 
/// 
///    * Amazon Web Services account
/// 
/// 
///    * Organizational unit (OU)
/// 
/// 
///    * Organization root
/// 
/// 
///    * Policy
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct OrganizationalUnitTags {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// OrganizationalUnitStatus defines the observed state of OrganizationalUnit
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct OrganizationalUnitStatus {
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
    /// that is used to contain resource sync state, account ownership,
    /// constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<OrganizationalUnitStatusAckResourceMetadata>,
    /// All CRS managed by ACK have a common `Status.Conditions` member that
    /// contains a collection of `ackv1alpha1.Condition` objects that describe
    /// the various terminal states of the CR and its backend AWS service API
    /// resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// The unique identifier (ID) associated with this OU.
    /// 
    /// 
    /// The regex pattern (http://wikipedia.org/wiki/regex) for an organizational
    /// unit ID string requires "ou-" followed by from 4 to 32 lowercase letters
    /// or digits (the ID of the root that contains the OU). This string is followed
    /// by a second "-" dash and from 8 to 32 additional lowercase letters or digits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
/// that is used to contain resource sync state, account ownership,
/// constructed ARN for the resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct OrganizationalUnitStatusAckResourceMetadata {
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

