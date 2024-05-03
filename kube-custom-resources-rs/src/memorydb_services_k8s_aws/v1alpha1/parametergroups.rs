// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/memorydb-controller/memorydb.services.k8s.aws/v1alpha1/parametergroups.yaml --derive=Default --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
}
use self::prelude::*;

/// ParameterGroupSpec defines the desired state of ParameterGroup. 
///  Represents the output of a CreateParameterGroup operation. A parameter group represents a combination of specific values for the parameters that are passed to the engine software during startup.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "memorydb.services.k8s.aws", version = "v1alpha1", kind = "ParameterGroup", plural = "parametergroups")]
#[kube(namespaced)]
#[kube(status = "ParameterGroupStatus")]
#[kube(schema = "disabled")]
#[kube(derive="Default")]
#[kube(derive="PartialEq")]
pub struct ParameterGroupSpec {
    /// An optional description of the parameter group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The name of the parameter group family that the parameter group can be used with.
    pub family: String,
    /// The name of the parameter group.
    pub name: String,
    /// An array of parameter names and values for the parameter update. You must supply at least one parameter name and value; subsequent arguments are optional. A maximum of 20 parameters may be updated per request.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "parameterNameValues")]
    pub parameter_name_values: Option<Vec<ParameterGroupParameterNameValues>>,
    /// A list of tags to be added to this resource. A tag is a key-value pair. A tag key must be accompanied by a tag value, although null is accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<ParameterGroupTags>>,
}

/// Describes a name-value pair that is used to update the value of a parameter.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ParameterGroupParameterNameValues {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "parameterName")]
    pub parameter_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "parameterValue")]
    pub parameter_value: Option<String>,
}

/// A tag that can be added to an MemoryDB resource. Tags are composed of a Key/Value pair. You can use tags to categorize and track all your MemoryDB resources. When you add or remove tags on clusters, those actions will be replicated to all nodes in the cluster. A tag with a null Value is permitted. For more information, see Tagging your MemoryDB resources (https://docs.aws.amazon.com/MemoryDB/latest/devguide/tagging-resources.html)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ParameterGroupTags {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// ParameterGroupStatus defines the observed state of ParameterGroup
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ParameterGroupStatus {
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member that is used to contain resource sync state, account ownership, constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<ParameterGroupStatusAckResourceMetadata>,
    /// All CRS managed by ACK have a common `Status.Conditions` member that contains a collection of `ackv1alpha1.Condition` objects that describe the various terminal states of the CR and its backend AWS service API resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// A list of parameters specific to a particular parameter group. Each element in the list contains detailed information about one parameter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Vec<ParameterGroupStatusParameters>>,
}

/// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member that is used to contain resource sync state, account ownership, constructed ARN for the resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ParameterGroupStatusAckResourceMetadata {
    /// ARN is the Amazon Resource Name for the resource. This is a globally-unique identifier and is set only by the ACK service controller once the controller has orchestrated the creation of the resource OR when it has verified that an "adopted" resource (a resource where the ARN annotation was set by the Kubernetes user on the CR) exists and matches the supplied CR's Spec field values. TODO(vijat@): Find a better strategy for resources that do not have ARN in CreateOutputResponse https://github.com/aws/aws-controllers-k8s/issues/270
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arn: Option<String>,
    /// OwnerAccountID is the AWS Account ID of the account that owns the backend AWS service API resource.
    #[serde(rename = "ownerAccountID")]
    pub owner_account_id: String,
    /// Region is the AWS region in which the resource exists or will exist.
    pub region: String,
}

/// Describes an individual setting that controls some aspect of MemoryDB behavior.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ParameterGroupStatusParameters {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "allowedValues")]
    pub allowed_values: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dataType")]
    pub data_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "minimumEngineVersion")]
    pub minimum_engine_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

