// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/efs-controller/efs.services.k8s.aws/v1alpha1/mounttargets.yaml --derive=Default --derive=PartialEq
// kopium version: 0.16.5

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// MountTargetSpec defines the desired state of MountTarget.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "efs.services.k8s.aws", version = "v1alpha1", kind = "MountTarget", plural = "mounttargets")]
#[kube(namespaced)]
#[kube(status = "MountTargetStatus")]
#[kube(schema = "disabled")]
pub struct MountTargetSpec {
    /// The ID of the file system for which to create the mount target.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "fileSystemID")]
    pub file_system_id: Option<String>,
    /// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference
    /// type to provide more user friendly syntax for references using 'from' field
    /// Ex:
    /// APIIDRef:
    /// 
    /// 
    /// 	from:
    /// 	  name: my-api
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "fileSystemRef")]
    pub file_system_ref: Option<MountTargetFileSystemRef>,
    /// Valid IPv4 address within the address range of the specified subnet.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ipAddress")]
    pub ip_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "securityGroupRefs")]
    pub security_group_refs: Option<Vec<MountTargetSecurityGroupRefs>>,
    /// Up to five VPC security group IDs, of the form sg-xxxxxxxx. These must be
    /// for the same VPC as subnet specified.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "securityGroups")]
    pub security_groups: Option<Vec<String>>,
    /// The ID of the subnet to add the mount target in. For One Zone file systems,
    /// use the subnet that is associated with the file system's Availability Zone.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "subnetID")]
    pub subnet_id: Option<String>,
    /// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference
    /// type to provide more user friendly syntax for references using 'from' field
    /// Ex:
    /// APIIDRef:
    /// 
    /// 
    /// 	from:
    /// 	  name: my-api
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "subnetRef")]
    pub subnet_ref: Option<MountTargetSubnetRef>,
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
pub struct MountTargetFileSystemRef {
    /// AWSResourceReference provides all the values necessary to reference another
    /// k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<MountTargetFileSystemRefFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another
/// k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MountTargetFileSystemRefFrom {
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
pub struct MountTargetSecurityGroupRefs {
    /// AWSResourceReference provides all the values necessary to reference another
    /// k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<MountTargetSecurityGroupRefsFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another
/// k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MountTargetSecurityGroupRefsFrom {
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
pub struct MountTargetSubnetRef {
    /// AWSResourceReference provides all the values necessary to reference another
    /// k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<MountTargetSubnetRefFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another
/// k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MountTargetSubnetRefFrom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// MountTargetStatus defines the observed state of MountTarget
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MountTargetStatus {
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
    /// that is used to contain resource sync state, account ownership,
    /// constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<MountTargetStatusAckResourceMetadata>,
    /// The unique and consistent identifier of the Availability Zone that the mount
    /// target resides in. For example, use1-az1 is an AZ ID for the us-east-1 Region
    /// and it has the same location in every Amazon Web Services account.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "availabilityZoneID")]
    pub availability_zone_id: Option<String>,
    /// The name of the Availability Zone in which the mount target is located. Availability
    /// Zones are independently mapped to names for each Amazon Web Services account.
    /// For example, the Availability Zone us-east-1a for your Amazon Web Services
    /// account might not be the same location as us-east-1a for another Amazon Web
    /// Services account.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "availabilityZoneName")]
    pub availability_zone_name: Option<String>,
    /// All CRS managed by ACK have a common `Status.Conditions` member that
    /// contains a collection of `ackv1alpha1.Condition` objects that describe
    /// the various terminal states of the CR and its backend AWS service API
    /// resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<MountTargetStatusConditions>>,
    /// Lifecycle state of the mount target.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lifeCycleState")]
    pub life_cycle_state: Option<String>,
    /// System-assigned mount target ID.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "mountTargetID")]
    pub mount_target_id: Option<String>,
    /// The ID of the network interface that Amazon EFS created when it created the
    /// mount target.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "networkInterfaceID")]
    pub network_interface_id: Option<String>,
    /// Amazon Web Services account ID that owns the resource.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ownerID")]
    pub owner_id: Option<String>,
    /// The virtual private cloud (VPC) ID that the mount target is configured in.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vpcID")]
    pub vpc_id: Option<String>,
}

/// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
/// that is used to contain resource sync state, account ownership,
/// constructed ARN for the resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MountTargetStatusAckResourceMetadata {
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

/// Condition is the common struct used by all CRDs managed by ACK service
/// controllers to indicate terminal states  of the CR and its backend AWS
/// service API resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MountTargetStatusConditions {
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
