// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/elasticache-controller/elasticache.services.k8s.aws/v1alpha1/cacheparametergroups.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// CacheParameterGroupSpec defines the desired state of CacheParameterGroup. 
///  Represents the output of a CreateCacheParameterGroup operation.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "elasticache.services.k8s.aws", version = "v1alpha1", kind = "CacheParameterGroup", plural = "cacheparametergroups")]
#[kube(namespaced)]
#[kube(status = "CacheParameterGroupStatus")]
#[kube(schema = "disabled")]
pub struct CacheParameterGroupSpec {
    /// The name of the cache parameter group family that the cache parameter group can be used with. 
    ///  Valid values are: memcached1.4 | memcached1.5 | memcached1.6 | redis2.6 | redis2.8 | redis3.2 | redis4.0 | redis5.0 | redis6.x
    #[serde(rename = "cacheParameterGroupFamily")]
    pub cache_parameter_group_family: String,
    /// A user-specified name for the cache parameter group.
    #[serde(rename = "cacheParameterGroupName")]
    pub cache_parameter_group_name: String,
    /// A user-specified description for the cache parameter group.
    pub description: String,
    /// An array of parameter names and values for the parameter update. You must supply at least one parameter name and value; subsequent arguments are optional. A maximum of 20 parameters may be modified per request.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "parameterNameValues")]
    pub parameter_name_values: Option<Vec<CacheParameterGroupParameterNameValues>>,
    /// A list of tags to be added to this resource. A tag is a key-value pair. A tag key must be accompanied by a tag value, although null is accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<CacheParameterGroupTags>>,
}

/// Describes a name-value pair that is used to update the value of a parameter.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CacheParameterGroupParameterNameValues {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "parameterName")]
    pub parameter_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "parameterValue")]
    pub parameter_value: Option<String>,
}

/// A tag that can be added to an ElastiCache cluster or replication group. Tags are composed of a Key/Value pair. You can use tags to categorize and track all your ElastiCache resources, with the exception of global replication group. When you add or remove tags on replication groups, those actions will be replicated to all nodes in the replication group. A tag with a null Value is permitted.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CacheParameterGroupTags {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// CacheParameterGroupStatus defines the observed state of CacheParameterGroup
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CacheParameterGroupStatus {
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member that is used to contain resource sync state, account ownership, constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<CacheParameterGroupStatusAckResourceMetadata>,
    /// All CRS managed by ACK have a common `Status.Conditions` member that contains a collection of `ackv1alpha1.Condition` objects that describe the various terminal states of the CR and its backend AWS service API resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// A list of events. Each element in the list contains detailed information about one event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<CacheParameterGroupStatusEvents>>,
    /// Indicates whether the parameter group is associated with a Global datastore
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "isGlobal")]
    pub is_global: Option<bool>,
    /// A list of Parameter instances.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Vec<CacheParameterGroupStatusParameters>>,
}

/// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member that is used to contain resource sync state, account ownership, constructed ARN for the resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CacheParameterGroupStatusAckResourceMetadata {
    /// ARN is the Amazon Resource Name for the resource. This is a globally-unique identifier and is set only by the ACK service controller once the controller has orchestrated the creation of the resource OR when it has verified that an "adopted" resource (a resource where the ARN annotation was set by the Kubernetes user on the CR) exists and matches the supplied CR's Spec field values. TODO(vijat@): Find a better strategy for resources that do not have ARN in CreateOutputResponse https://github.com/aws/aws-controllers-k8s/issues/270
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arn: Option<String>,
    /// OwnerAccountID is the AWS Account ID of the account that owns the backend AWS service API resource.
    #[serde(rename = "ownerAccountID")]
    pub owner_account_id: String,
    /// Region is the AWS region in which the resource exists or will exist.
    pub region: String,
}

/// Represents a single occurrence of something interesting within the system. Some examples of events are creating a cluster, adding or removing a cache node, or rebooting a node.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CacheParameterGroupStatusEvents {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sourceIdentifier")]
    pub source_identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sourceType")]
    pub source_type: Option<String>,
}

/// Describes an individual setting that controls some aspect of ElastiCache behavior.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CacheParameterGroupStatusParameters {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "allowedValues")]
    pub allowed_values: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "changeType")]
    pub change_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dataType")]
    pub data_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "isModifiable")]
    pub is_modifiable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "minimumEngineVersion")]
    pub minimum_engine_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "parameterName")]
    pub parameter_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "parameterValue")]
    pub parameter_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

