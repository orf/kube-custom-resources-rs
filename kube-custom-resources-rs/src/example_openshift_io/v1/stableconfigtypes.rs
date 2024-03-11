// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/openshift/api/example.openshift.io/v1/stableconfigtypes.yaml --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// spec is the specification of the desired behavior of the StableConfigType.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "example.openshift.io", version = "v1", kind = "StableConfigType", plural = "stableconfigtypes")]
#[kube(status = "StableConfigTypeStatus")]
#[kube(schema = "disabled")]
pub struct StableConfigTypeSpec {
    /// celUnion demonstrates how to validate a discrminated union using CEL
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "celUnion")]
    pub cel_union: Option<StableConfigTypeCelUnion>,
    /// evolvingUnion demonstrates how to phase in new values into discriminated union
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "evolvingUnion")]
    pub evolving_union: Option<StableConfigTypeEvolvingUnion>,
    /// immutableField is a field that is immutable once the object has been created. It is required at all times.
    #[serde(rename = "immutableField")]
    pub immutable_field: String,
    /// optionalImmutableField is a field that is immutable once set. It is optional but may not be changed once set.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "optionalImmutableField")]
    pub optional_immutable_field: Option<String>,
    /// stableField is a field that is present on default clusters and on tech preview clusters 
    ///  If empty, the platform will choose a good default, which may change over time without notice.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "stableField")]
    pub stable_field: Option<String>,
}

/// celUnion demonstrates how to validate a discrminated union using CEL
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct StableConfigTypeCelUnion {
    /// optionalMember is a union member that is optional.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "optionalMember")]
    pub optional_member: Option<String>,
    /// requiredMember is a union member that is required.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "requiredMember")]
    pub required_member: Option<String>,
    /// type determines which of the union members should be populated.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<StableConfigTypeCelUnionType>,
}

/// celUnion demonstrates how to validate a discrminated union using CEL
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum StableConfigTypeCelUnionType {
    RequiredMember,
    OptionalMember,
    EmptyMember,
}

/// evolvingUnion demonstrates how to phase in new values into discriminated union
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct StableConfigTypeEvolvingUnion {
    /// type is the discriminator. It has different values for Default and for TechPreviewNoUpgrade
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<StableConfigTypeEvolvingUnionType>,
}

/// evolvingUnion demonstrates how to phase in new values into discriminated union
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum StableConfigTypeEvolvingUnionType {
    #[serde(rename = "")]
    KopiumEmpty,
    StableValue,
}

/// status is the most recently observed status of the StableConfigType.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct StableConfigTypeStatus {
    /// Represents the observations of a foo's current state. Known .status.conditions.type are: "Available", "Progressing", and "Degraded"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// immutableField is a field that is immutable once the object has been created. It is required at all times.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "immutableField")]
    pub immutable_field: Option<String>,
}

