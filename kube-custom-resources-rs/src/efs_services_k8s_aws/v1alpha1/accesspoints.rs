// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/efs-controller/efs.services.k8s.aws/v1alpha1/accesspoints.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// AccessPointSpec defines the desired state of AccessPoint.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "efs.services.k8s.aws", version = "v1alpha1", kind = "AccessPoint", plural = "accesspoints")]
#[kube(namespaced)]
#[kube(status = "AccessPointStatus")]
#[kube(schema = "disabled")]
pub struct AccessPointSpec {
    /// The ID of the EFS file system that the access point provides access to.
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
    pub file_system_ref: Option<AccessPointFileSystemRef>,
    /// The operating system user and group applied to all file system requests made
    /// using the access point.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "posixUser")]
    pub posix_user: Option<AccessPointPosixUser>,
    /// Specifies the directory on the EFS file system that the access point exposes
    /// as the root directory of your file system to NFS clients using the access
    /// point. The clients using the access point can only access the root directory
    /// and below. If the RootDirectory > Path specified does not exist, Amazon EFS
    /// creates it and applies the CreationInfo settings when a client connects to
    /// an access point. When specifying a RootDirectory, you must provide the Path,
    /// and the CreationInfo.
    /// 
    /// 
    /// Amazon EFS creates a root directory only if you have provided the CreationInfo:
    /// OwnUid, OwnGID, and permissions for the directory. If you do not provide
    /// this information, Amazon EFS does not create the root directory. If the root
    /// directory does not exist, attempts to mount using the access point will fail.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "rootDirectory")]
    pub root_directory: Option<AccessPointRootDirectory>,
    /// Creates tags associated with the access point. Each tag is a key-value pair,
    /// each key must be unique. For more information, see Tagging Amazon Web Services
    /// resources (https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html)
    /// in the Amazon Web Services General Reference Guide.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<AccessPointTags>>,
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
pub struct AccessPointFileSystemRef {
    /// AWSResourceReference provides all the values necessary to reference another
    /// k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<AccessPointFileSystemRefFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another
/// k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AccessPointFileSystemRefFrom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// The operating system user and group applied to all file system requests made
/// using the access point.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AccessPointPosixUser {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gid: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secondaryGIDs")]
    pub secondary_gi_ds: Option<Vec<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<i64>,
}

/// Specifies the directory on the EFS file system that the access point exposes
/// as the root directory of your file system to NFS clients using the access
/// point. The clients using the access point can only access the root directory
/// and below. If the RootDirectory > Path specified does not exist, Amazon EFS
/// creates it and applies the CreationInfo settings when a client connects to
/// an access point. When specifying a RootDirectory, you must provide the Path,
/// and the CreationInfo.
/// 
/// 
/// Amazon EFS creates a root directory only if you have provided the CreationInfo:
/// OwnUid, OwnGID, and permissions for the directory. If you do not provide
/// this information, Amazon EFS does not create the root directory. If the root
/// directory does not exist, attempts to mount using the access point will fail.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AccessPointRootDirectory {
    /// Required if the RootDirectory > Path specified does not exist. Specifies
    /// the POSIX IDs and permissions to apply to the access point's RootDirectory
    /// > Path. If the access point root directory does not exist, EFS creates it
    /// with these settings when a client connects to the access point. When specifying
    /// CreationInfo, you must include values for all properties.
    /// 
    /// 
    /// Amazon EFS creates a root directory only if you have provided the CreationInfo:
    /// OwnUid, OwnGID, and permissions for the directory. If you do not provide
    /// this information, Amazon EFS does not create the root directory. If the root
    /// directory does not exist, attempts to mount using the access point will fail.
    /// 
    /// 
    /// If you do not provide CreationInfo and the specified RootDirectory does not
    /// exist, attempts to mount the file system using the access point will fail.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "creationInfo")]
    pub creation_info: Option<AccessPointRootDirectoryCreationInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// Required if the RootDirectory > Path specified does not exist. Specifies
/// the POSIX IDs and permissions to apply to the access point's RootDirectory
/// > Path. If the access point root directory does not exist, EFS creates it
/// with these settings when a client connects to the access point. When specifying
/// CreationInfo, you must include values for all properties.
/// 
/// 
/// Amazon EFS creates a root directory only if you have provided the CreationInfo:
/// OwnUid, OwnGID, and permissions for the directory. If you do not provide
/// this information, Amazon EFS does not create the root directory. If the root
/// directory does not exist, attempts to mount using the access point will fail.
/// 
/// 
/// If you do not provide CreationInfo and the specified RootDirectory does not
/// exist, attempts to mount the file system using the access point will fail.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AccessPointRootDirectoryCreationInfo {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ownerGID")]
    pub owner_gid: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ownerUID")]
    pub owner_uid: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<String>,
}

/// A tag is a key-value pair. Allowed characters are letters, white space, and
/// numbers that can be represented in UTF-8, and the following characters:+
/// - = . _ : /.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AccessPointTags {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// AccessPointStatus defines the observed state of AccessPoint
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AccessPointStatus {
    /// The ID of the access point, assigned by Amazon EFS.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "accessPointID")]
    pub access_point_id: Option<String>,
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
    /// that is used to contain resource sync state, account ownership,
    /// constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<AccessPointStatusAckResourceMetadata>,
    /// All CRS managed by ACK have a common `Status.Conditions` member that
    /// contains a collection of `ackv1alpha1.Condition` objects that describe
    /// the various terminal states of the CR and its backend AWS service API
    /// resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// Identifies the lifecycle phase of the access point.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lifeCycleState")]
    pub life_cycle_state: Option<String>,
    /// The name of the access point. This is the value of the Name tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Identifies the Amazon Web Services account that owns the access point resource.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ownerID")]
    pub owner_id: Option<String>,
}

/// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
/// that is used to contain resource sync state, account ownership,
/// constructed ARN for the resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AccessPointStatusAckResourceMetadata {
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

