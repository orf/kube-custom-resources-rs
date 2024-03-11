// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/memorydb-controller/memorydb.services.k8s.aws/v1alpha1/clusters.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// ClusterSpec defines the desired state of Cluster. 
///  Contains all of the attributes of a specific cluster.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "memorydb.services.k8s.aws", version = "v1alpha1", kind = "Cluster", plural = "clusters")]
#[kube(namespaced)]
#[kube(status = "ClusterStatus")]
#[kube(schema = "disabled")]
pub struct ClusterSpec {
    /// The name of the Access Control List to associate with the cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "aclName")]
    pub acl_name: Option<String>,
    /// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference type to provide more user friendly syntax for references using 'from' field Ex: APIIDRef: 
    ///  from: name: my-api
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "aclRef")]
    pub acl_ref: Option<ClusterAclRef>,
    /// When set to true, the cluster will automatically receive minor engine version upgrades after launch.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "autoMinorVersionUpgrade")]
    pub auto_minor_version_upgrade: Option<bool>,
    /// An optional description of the cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The version number of the Redis engine to be used for the cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "engineVersion")]
    pub engine_version: Option<String>,
    /// The ID of the KMS key used to encrypt the cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "kmsKeyID")]
    pub kms_key_id: Option<String>,
    /// Specifies the weekly time range during which maintenance on the cluster is performed. It is specified as a range in the format ddd:hh24:mi-ddd:hh24:mi (24H Clock UTC). The minimum maintenance window is a 60 minute period.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maintenanceWindow")]
    pub maintenance_window: Option<String>,
    /// The name of the cluster. This value must be unique as it also serves as the cluster identifier.
    pub name: String,
    /// The compute and memory capacity of the nodes in the cluster.
    #[serde(rename = "nodeType")]
    pub node_type: String,
    /// The number of replicas to apply to each shard. The default value is 1. The maximum is 5.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "numReplicasPerShard")]
    pub num_replicas_per_shard: Option<i64>,
    /// The number of shards the cluster will contain. The default value is 1.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "numShards")]
    pub num_shards: Option<i64>,
    /// The name of the parameter group associated with the cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "parameterGroupName")]
    pub parameter_group_name: Option<String>,
    /// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference type to provide more user friendly syntax for references using 'from' field Ex: APIIDRef: 
    ///  from: name: my-api
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "parameterGroupRef")]
    pub parameter_group_ref: Option<ClusterParameterGroupRef>,
    /// The port number on which each of the nodes accepts connections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<i64>,
    /// A list of security group names to associate with this cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "securityGroupIDs")]
    pub security_group_i_ds: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "securityGroupRefs")]
    pub security_group_refs: Option<Vec<ClusterSecurityGroupRefs>>,
    /// A list of Amazon Resource Names (ARN) that uniquely identify the RDB snapshot files stored in Amazon S3. The snapshot files are used to populate the new cluster. The Amazon S3 object name in the ARN cannot contain any commas.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "snapshotARNs")]
    pub snapshot_ar_ns: Option<Vec<String>>,
    /// The name of a snapshot from which to restore data into the new cluster. The snapshot status changes to restoring while the new cluster is being created.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "snapshotName")]
    pub snapshot_name: Option<String>,
    /// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference type to provide more user friendly syntax for references using 'from' field Ex: APIIDRef: 
    ///  from: name: my-api
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "snapshotRef")]
    pub snapshot_ref: Option<ClusterSnapshotRef>,
    /// The number of days for which MemoryDB retains automatic snapshots before deleting them. For example, if you set SnapshotRetentionLimit to 5, a snapshot that was taken today is retained for 5 days before being deleted.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "snapshotRetentionLimit")]
    pub snapshot_retention_limit: Option<i64>,
    /// The daily time range (in UTC) during which MemoryDB begins taking a daily snapshot of your shard. 
    ///  Example: 05:00-09:00 
    ///  If you do not specify this parameter, MemoryDB automatically chooses an appropriate time range.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "snapshotWindow")]
    pub snapshot_window: Option<String>,
    /// The Amazon Resource Name (ARN) of the Amazon Simple Notification Service (SNS) topic to which notifications are sent.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "snsTopicARN")]
    pub sns_topic_arn: Option<String>,
    /// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference type to provide more user friendly syntax for references using 'from' field Ex: APIIDRef: 
    ///  from: name: my-api
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "snsTopicRef")]
    pub sns_topic_ref: Option<ClusterSnsTopicRef>,
    /// The name of the subnet group to be used for the cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "subnetGroupName")]
    pub subnet_group_name: Option<String>,
    /// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference type to provide more user friendly syntax for references using 'from' field Ex: APIIDRef: 
    ///  from: name: my-api
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "subnetGroupRef")]
    pub subnet_group_ref: Option<ClusterSubnetGroupRef>,
    /// A list of tags to be added to this resource. Tags are comma-separated key,value pairs (e.g. Key=myKey, Value=myKeyValue. You can include multiple tags as shown following: Key=myKey, Value=myKeyValue Key=mySecondKey, Value=mySecondKeyValue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<ClusterTags>>,
    /// A flag to enable in-transit encryption on the cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "tlsEnabled")]
    pub tls_enabled: Option<bool>,
}

/// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference type to provide more user friendly syntax for references using 'from' field Ex: APIIDRef: 
///  from: name: my-api
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterAclRef {
    /// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<ClusterAclRefFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterAclRefFrom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference type to provide more user friendly syntax for references using 'from' field Ex: APIIDRef: 
///  from: name: my-api
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterParameterGroupRef {
    /// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<ClusterParameterGroupRefFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterParameterGroupRefFrom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference type to provide more user friendly syntax for references using 'from' field Ex: APIIDRef: 
///  from: name: my-api
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterSecurityGroupRefs {
    /// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<ClusterSecurityGroupRefsFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterSecurityGroupRefsFrom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference type to provide more user friendly syntax for references using 'from' field Ex: APIIDRef: 
///  from: name: my-api
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterSnapshotRef {
    /// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<ClusterSnapshotRefFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterSnapshotRefFrom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference type to provide more user friendly syntax for references using 'from' field Ex: APIIDRef: 
///  from: name: my-api
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterSnsTopicRef {
    /// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<ClusterSnsTopicRefFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterSnsTopicRefFrom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference type to provide more user friendly syntax for references using 'from' field Ex: APIIDRef: 
///  from: name: my-api
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterSubnetGroupRef {
    /// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<ClusterSubnetGroupRefFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterSubnetGroupRefFrom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// A tag that can be added to an MemoryDB resource. Tags are composed of a Key/Value pair. You can use tags to categorize and track all your MemoryDB resources. When you add or remove tags on clusters, those actions will be replicated to all nodes in the cluster. A tag with a null Value is permitted. For more information, see Tagging your MemoryDB resources (https://docs.aws.amazon.com/MemoryDB/latest/devguide/tagging-resources.html)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterTags {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// ClusterStatus defines the observed state of Cluster
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterStatus {
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member that is used to contain resource sync state, account ownership, constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<ClusterStatusAckResourceMetadata>,
    /// A list node types which you can use to scale down your cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "allowedScaleDownNodeTypes")]
    pub allowed_scale_down_node_types: Option<Vec<String>>,
    /// A list node types which you can use to scale up your cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "allowedScaleUpNodeTypes")]
    pub allowed_scale_up_node_types: Option<Vec<String>>,
    /// Indicates if the cluster has a Multi-AZ configuration (multiaz) or not (singleaz).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "availabilityMode")]
    pub availability_mode: Option<String>,
    /// The cluster's configuration endpoint
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clusterEndpoint")]
    pub cluster_endpoint: Option<ClusterStatusClusterEndpoint>,
    /// All CRS managed by ACK have a common `Status.Conditions` member that contains a collection of `ackv1alpha1.Condition` objects that describe the various terminal states of the CR and its backend AWS service API resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// The Redis engine patch version used by the cluster
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "enginePatchVersion")]
    pub engine_patch_version: Option<String>,
    /// A list of events. Each element in the list contains detailed information about one event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<ClusterStatusEvents>>,
    /// The number of shards in the cluster
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "numberOfShards")]
    pub number_of_shards: Option<i64>,
    /// The status of the parameter group used by the cluster, for example 'active' or 'applying'.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "parameterGroupStatus")]
    pub parameter_group_status: Option<String>,
    /// A group of settings that are currently being applied.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "pendingUpdates")]
    pub pending_updates: Option<ClusterStatusPendingUpdates>,
    /// A list of security groups used by the cluster
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "securityGroups")]
    pub security_groups: Option<Vec<ClusterStatusSecurityGroups>>,
    /// A list of shards that are members of the cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shards: Option<Vec<ClusterStatusShards>>,
    /// The SNS topic must be in Active status to receive notifications
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "snsTopicStatus")]
    pub sns_topic_status: Option<String>,
    /// The status of the cluster. For example, Available, Updating, Creating.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member that is used to contain resource sync state, account ownership, constructed ARN for the resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterStatusAckResourceMetadata {
    /// ARN is the Amazon Resource Name for the resource. This is a globally-unique identifier and is set only by the ACK service controller once the controller has orchestrated the creation of the resource OR when it has verified that an "adopted" resource (a resource where the ARN annotation was set by the Kubernetes user on the CR) exists and matches the supplied CR's Spec field values. TODO(vijat@): Find a better strategy for resources that do not have ARN in CreateOutputResponse https://github.com/aws/aws-controllers-k8s/issues/270
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arn: Option<String>,
    /// OwnerAccountID is the AWS Account ID of the account that owns the backend AWS service API resource.
    #[serde(rename = "ownerAccountID")]
    pub owner_account_id: String,
    /// Region is the AWS region in which the resource exists or will exist.
    pub region: String,
}

/// The cluster's configuration endpoint
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterStatusClusterEndpoint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<i64>,
}

/// Represents a single occurrence of something interesting within the system. Some examples of events are creating a cluster or adding or removing a node.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterStatusEvents {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sourceName")]
    pub source_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sourceType")]
    pub source_type: Option<String>,
}

/// A group of settings that are currently being applied.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterStatusPendingUpdates {
    /// The status of the ACL update
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acls: Option<ClusterStatusPendingUpdatesAcls>,
    /// The status of the online resharding
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resharding: Option<ClusterStatusPendingUpdatesResharding>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "serviceUpdates")]
    pub service_updates: Option<Vec<ClusterStatusPendingUpdatesServiceUpdates>>,
}

/// The status of the ACL update
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterStatusPendingUpdatesAcls {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "aclToApply")]
    pub acl_to_apply: Option<String>,
}

/// The status of the online resharding
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterStatusPendingUpdatesResharding {
    /// Represents the progress of an online resharding operation.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "slotMigration")]
    pub slot_migration: Option<ClusterStatusPendingUpdatesReshardingSlotMigration>,
}

/// Represents the progress of an online resharding operation.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterStatusPendingUpdatesReshardingSlotMigration {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "progressPercentage")]
    pub progress_percentage: Option<f64>,
}

/// Update action that has yet to be processed for the corresponding apply/stop request
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterStatusPendingUpdatesServiceUpdates {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "serviceUpdateName")]
    pub service_update_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Represents a single security group and its status.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterStatusSecurityGroups {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "securityGroupID")]
    pub security_group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Represents a collection of nodes in a cluster. One node in the node group is the read/write primary node. All the other nodes are read-only Replica nodes.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterStatusShards {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodes: Option<Vec<ClusterStatusShardsNodes>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "numberOfNodes")]
    pub number_of_nodes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slots: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Represents an individual node within a cluster. Each node runs its own instance of the cluster's protocol-compliant caching software.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterStatusShardsNodes {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "availabilityZone")]
    pub availability_zone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "createTime")]
    pub create_time: Option<String>,
    /// Represents the information required for client programs to connect to the cluster and its nodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<ClusterStatusShardsNodesEndpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Represents the information required for client programs to connect to the cluster and its nodes.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterStatusShardsNodesEndpoint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<i64>,
}

