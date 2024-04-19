// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/iam-controller/iam.services.k8s.aws/v1alpha1/users.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// UserSpec defines the desired state of User.
/// 
/// 
/// Contains information about an IAM user entity.
/// 
/// 
/// This data type is used as a response element in the following operations:
/// 
/// 
///    * CreateUser
/// 
/// 
///    * GetUser
/// 
/// 
///    * ListUsers
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "iam.services.k8s.aws", version = "v1alpha1", kind = "User", plural = "users")]
#[kube(namespaced)]
#[kube(status = "UserStatus")]
#[kube(schema = "disabled")]
pub struct UserSpec {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "inlinePolicies")]
    pub inline_policies: Option<BTreeMap<String, String>>,
    /// The name of the user to create.
    /// 
    /// 
    /// IAM user, group, role, and policy names must be unique within the account.
    /// Names are not distinguished by case. For example, you cannot create resources
    /// named both "MyResource" and "myresource".
    pub name: String,
    /// The path for the user name. For more information about paths, see IAM identifiers
    /// (https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html)
    /// in the IAM User Guide.
    /// 
    /// 
    /// This parameter is optional. If it is not included, it defaults to a slash
    /// (/).
    /// 
    /// 
    /// This parameter allows (through its regex pattern (http://wikipedia.org/wiki/regex))
    /// a string of characters consisting of either a forward slash (/) by itself
    /// or a string that must begin and end with forward slashes. In addition, it
    /// can contain any ASCII character from the ! (\u0021) through the DEL character
    /// (\u007F), including most punctuation characters, digits, and upper and lowercased
    /// letters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The ARN of the managed policy that is used to set the permissions boundary
    /// for the user.
    /// 
    /// 
    /// A permissions boundary policy defines the maximum permissions that identity-based
    /// policies can grant to an entity, but does not grant permissions. Permissions
    /// boundaries do not define the maximum permissions that a resource-based policy
    /// can grant to an entity. To learn more, see Permissions boundaries for IAM
    /// entities (https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
    /// in the IAM User Guide.
    /// 
    /// 
    /// For more information about policy types, see Policy types (https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#access_policy-types)
    /// in the IAM User Guide.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "permissionsBoundary")]
    pub permissions_boundary: Option<String>,
    /// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference
    /// type to provide more user friendly syntax for references using 'from' field
    /// Ex:
    /// APIIDRef:
    /// 
    /// 
    /// 	from:
    /// 	  name: my-api
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "permissionsBoundaryRef")]
    pub permissions_boundary_ref: Option<UserPermissionsBoundaryRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policies: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "policyRefs")]
    pub policy_refs: Option<Vec<UserPolicyRefs>>,
    /// A list of tags that you want to attach to the new user. Each tag consists
    /// of a key name and an associated value. For more information about tagging,
    /// see Tagging IAM resources (https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html)
    /// in the IAM User Guide.
    /// 
    /// 
    /// If any one of the tags is invalid or if you exceed the allowed maximum number
    /// of tags, then the entire request fails and the resource is not created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<UserTags>>,
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
pub struct UserPermissionsBoundaryRef {
    /// AWSResourceReference provides all the values necessary to reference another
    /// k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<UserPermissionsBoundaryRefFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another
/// k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct UserPermissionsBoundaryRefFrom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
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
pub struct UserPolicyRefs {
    /// AWSResourceReference provides all the values necessary to reference another
    /// k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<UserPolicyRefsFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another
/// k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct UserPolicyRefsFrom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// A structure that represents user-provided metadata that can be associated
/// with an IAM resource. For more information about tagging, see Tagging IAM
/// resources (https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html)
/// in the IAM User Guide.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct UserTags {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// UserStatus defines the observed state of User
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct UserStatus {
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
    /// that is used to contain resource sync state, account ownership,
    /// constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<UserStatusAckResourceMetadata>,
    /// All CRS managed by ACK have a common `Status.Conditions` member that
    /// contains a collection of `ackv1alpha1.Condition` objects that describe
    /// the various terminal states of the CR and its backend AWS service API
    /// resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// The date and time, in ISO 8601 date-time format (http://www.iso.org/iso/iso8601),
    /// when the user was created.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "createDate")]
    pub create_date: Option<String>,
    /// The date and time, in ISO 8601 date-time format (http://www.iso.org/iso/iso8601),
    /// when the user's password was last used to sign in to an Amazon Web Services
    /// website. For a list of Amazon Web Services websites that capture a user's
    /// last sign-in time, see the Credential reports (https://docs.aws.amazon.com/IAM/latest/UserGuide/credential-reports.html)
    /// topic in the IAM User Guide. If a password is used more than once in a five-minute
    /// span, only the first use is returned in this field. If the field is null
    /// (no value), then it indicates that they never signed in with a password.
    /// This can be because:
    /// 
    /// 
    ///    * The user never had a password.
    /// 
    /// 
    ///    * A password exists but has not been used since IAM started tracking this
    ///    information on October 20, 2014.
    /// 
    /// 
    /// A null value does not mean that the user never had a password. Also, if the
    /// user does not currently have a password but had one in the past, then this
    /// field contains the date and time the most recent password was used.
    /// 
    /// 
    /// This value is returned only in the GetUser and ListUsers operations.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "passwordLastUsed")]
    pub password_last_used: Option<String>,
    /// The stable and unique string identifying the user. For more information about
    /// IDs, see IAM identifiers (https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html)
    /// in the IAM User Guide.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "userID")]
    pub user_id: Option<String>,
}

/// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
/// that is used to contain resource sync state, account ownership,
/// constructed ARN for the resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct UserStatusAckResourceMetadata {
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

