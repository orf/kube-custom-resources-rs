// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/memorydb-controller/memorydb.services.k8s.aws/v1alpha1/users.yaml --derive=Default --derive=PartialEq
// kopium version: 0.16.5

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// UserSpec defines the desired state of User. 
///  You create users and assign them specific permissions by using an access string. You assign the users to Access Control Lists aligned with a specific role (administrators, human resources) that are then deployed to one or more MemoryDB clusters.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "memorydb.services.k8s.aws", version = "v1alpha1", kind = "User", plural = "users")]
#[kube(namespaced)]
#[kube(status = "UserStatus")]
#[kube(schema = "disabled")]
pub struct UserSpec {
    /// Access permissions string used for this user.
    #[serde(rename = "accessString")]
    pub access_string: String,
    /// Denotes the user's authentication properties, such as whether it requires a password to authenticate.
    #[serde(rename = "authenticationMode")]
    pub authentication_mode: UserAuthenticationMode,
    /// The name of the user. This value must be unique as it also serves as the user identifier.
    pub name: String,
    /// A list of tags to be added to this resource. A tag is a key-value pair. A tag key must be accompanied by a tag value, although null is accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<UserTags>>,
}

/// Denotes the user's authentication properties, such as whether it requires a password to authenticate.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct UserAuthenticationMode {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passwords: Option<Vec<UserAuthenticationModePasswords>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type_")]
    pub r#type: Option<String>,
}

/// SecretKeyReference combines a k8s corev1.SecretReference with a specific key within the referred-to Secret
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct UserAuthenticationModePasswords {
    /// Key is the key within the secret
    pub key: String,
    /// name is unique within a namespace to reference a secret resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// namespace defines the space within which the secret name must be unique.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// A tag that can be added to an MemoryDB resource. Tags are composed of a Key/Value pair. You can use tags to categorize and track all your MemoryDB resources. When you add or remove tags on clusters, those actions will be replicated to all nodes in the cluster. A tag with a null Value is permitted. For more information, see Tagging your MemoryDB resources (https://docs.aws.amazon.com/MemoryDB/latest/devguide/tagging-resources.html)
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
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member that is used to contain resource sync state, account ownership, constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<UserStatusAckResourceMetadata>,
    /// The names of the Access Control Lists to which the user belongs
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "aclNames")]
    pub acl_names: Option<Vec<String>>,
    /// Denotes whether the user requires a password to authenticate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<UserStatusAuthentication>,
    /// All CRS managed by ACK have a common `Status.Conditions` member that contains a collection of `ackv1alpha1.Condition` objects that describe the various terminal states of the CR and its backend AWS service API resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<UserStatusConditions>>,
    /// A list of events. Each element in the list contains detailed information about one event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<UserStatusEvents>>,
    /// The minimum engine version supported for the user
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "minimumEngineVersion")]
    pub minimum_engine_version: Option<String>,
    /// Indicates the user status. Can be "active", "modifying" or "deleting".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member that is used to contain resource sync state, account ownership, constructed ARN for the resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct UserStatusAckResourceMetadata {
    /// ARN is the Amazon Resource Name for the resource. This is a globally-unique identifier and is set only by the ACK service controller once the controller has orchestrated the creation of the resource OR when it has verified that an "adopted" resource (a resource where the ARN annotation was set by the Kubernetes user on the CR) exists and matches the supplied CR's Spec field values. TODO(vijat@): Find a better strategy for resources that do not have ARN in CreateOutputResponse https://github.com/aws/aws-controllers-k8s/issues/270
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arn: Option<String>,
    /// OwnerAccountID is the AWS Account ID of the account that owns the backend AWS service API resource.
    #[serde(rename = "ownerAccountID")]
    pub owner_account_id: String,
    /// Region is the AWS region in which the resource exists or will exist.
    pub region: String,
}

/// Denotes whether the user requires a password to authenticate.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct UserStatusAuthentication {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "passwordCount")]
    pub password_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type_")]
    pub r#type: Option<String>,
}

/// Condition is the common struct used by all CRDs managed by ACK service controllers to indicate terminal states  of the CR and its backend AWS service API resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct UserStatusConditions {
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

/// Represents a single occurrence of something interesting within the system. Some examples of events are creating a cluster or adding or removing a node.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct UserStatusEvents {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sourceName")]
    pub source_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sourceType")]
    pub source_type: Option<String>,
}
