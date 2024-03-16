// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/openshift/api/config.openshift.io/v1/clusterversions.yaml --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// spec is the desired state of the cluster version - the operator will work to ensure that the desired version is applied to the cluster.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "config.openshift.io", version = "v1", kind = "ClusterVersion", plural = "clusterversions")]
#[kube(status = "ClusterVersionStatus")]
#[kube(schema = "disabled")]
pub struct ClusterVersionSpec {
    /// capabilities configures the installation of optional, core cluster components.  A null value here is identical to an empty object; see the child properties for default semantics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<ClusterVersionCapabilities>,
    /// channel is an identifier for explicitly requesting that a non-default set of updates be applied to this cluster. The default channel will be contain stable updates that are appropriate for production clusters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// clusterID uniquely identifies this cluster. This is expected to be an RFC4122 UUID value (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx in hexadecimal values). This is a required field.
    #[serde(rename = "clusterID")]
    pub cluster_id: String,
    /// desiredUpdate is an optional field that indicates the desired value of the cluster version. Setting this value will trigger an upgrade (if the current version does not match the desired version). The set of recommended update values is listed as part of available updates in status, and setting values outside that range may cause the upgrade to fail. 
    ///  Some of the fields are inter-related with restrictions and meanings described here. 1. image is specified, version is specified, architecture is specified. API validation error. 2. image is specified, version is specified, architecture is not specified. You should not do this. version is silently ignored and image is used. 3. image is specified, version is not specified, architecture is specified. API validation error. 4. image is specified, version is not specified, architecture is not specified. image is used. 5. image is not specified, version is specified, architecture is specified. version and desired architecture are used to select an image. 6. image is not specified, version is specified, architecture is not specified. version and current architecture are used to select an image. 7. image is not specified, version is not specified, architecture is specified. API validation error. 8. image is not specified, version is not specified, architecture is not specified. API validation error. 
    ///  If an upgrade fails the operator will halt and report status about the failing component. Setting the desired update value back to the previous version will cause a rollback to be attempted. Not all rollbacks will succeed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "desiredUpdate")]
    pub desired_update: Option<ClusterVersionDesiredUpdate>,
    /// overrides is list of overides for components that are managed by cluster version operator. Marking a component unmanaged will prevent the operator from creating or updating the object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overrides: Option<Vec<ClusterVersionOverrides>>,
    /// upstream may be used to specify the preferred update server. By default it will use the appropriate update server for the cluster and region.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
}

/// capabilities configures the installation of optional, core cluster components.  A null value here is identical to an empty object; see the child properties for default semantics.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterVersionCapabilities {
    /// additionalEnabledCapabilities extends the set of managed capabilities beyond the baseline defined in baselineCapabilitySet.  The default is an empty set.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "additionalEnabledCapabilities")]
    pub additional_enabled_capabilities: Option<Vec<String>>,
    /// baselineCapabilitySet selects an initial set of optional capabilities to enable, which can be extended via additionalEnabledCapabilities.  If unset, the cluster will choose a default, and the default may change over time. The current default is vCurrent.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "baselineCapabilitySet")]
    pub baseline_capability_set: Option<ClusterVersionCapabilitiesBaselineCapabilitySet>,
}

/// capabilities configures the installation of optional, core cluster components.  A null value here is identical to an empty object; see the child properties for default semantics.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ClusterVersionCapabilitiesBaselineCapabilitySet {
    None,
    #[serde(rename = "v4.11")]
    V411,
    #[serde(rename = "v4.12")]
    V412,
    #[serde(rename = "v4.13")]
    V413,
    #[serde(rename = "v4.14")]
    V414,
    #[serde(rename = "v4.15")]
    V415,
    #[serde(rename = "vCurrent")]
    VCurrent,
}

/// desiredUpdate is an optional field that indicates the desired value of the cluster version. Setting this value will trigger an upgrade (if the current version does not match the desired version). The set of recommended update values is listed as part of available updates in status, and setting values outside that range may cause the upgrade to fail. 
///  Some of the fields are inter-related with restrictions and meanings described here. 1. image is specified, version is specified, architecture is specified. API validation error. 2. image is specified, version is specified, architecture is not specified. You should not do this. version is silently ignored and image is used. 3. image is specified, version is not specified, architecture is specified. API validation error. 4. image is specified, version is not specified, architecture is not specified. image is used. 5. image is not specified, version is specified, architecture is specified. version and desired architecture are used to select an image. 6. image is not specified, version is specified, architecture is not specified. version and current architecture are used to select an image. 7. image is not specified, version is not specified, architecture is specified. API validation error. 8. image is not specified, version is not specified, architecture is not specified. API validation error. 
///  If an upgrade fails the operator will halt and report status about the failing component. Setting the desired update value back to the previous version will cause a rollback to be attempted. Not all rollbacks will succeed.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterVersionDesiredUpdate {
    /// architecture is an optional field that indicates the desired value of the cluster architecture. In this context cluster architecture means either a single architecture or a multi architecture. architecture can only be set to Multi thereby only allowing updates from single to multi architecture. If architecture is set, image cannot be set and version must be set. Valid values are 'Multi' and empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architecture: Option<ClusterVersionDesiredUpdateArchitecture>,
    /// force allows an administrator to update to an image that has failed verification or upgradeable checks. This option should only be used when the authenticity of the provided image has been verified out of band because the provided image will run with full administrative access to the cluster. Do not use this flag with images that comes from unknown or potentially malicious sources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force: Option<bool>,
    /// image is a container image location that contains the update. image should be used when the desired version does not exist in availableUpdates or history. When image is set, version is ignored. When image is set, version should be empty. When image is set, architecture cannot be specified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// version is a semantic version identifying the update version. version is ignored if image is specified and required if architecture is specified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// desiredUpdate is an optional field that indicates the desired value of the cluster version. Setting this value will trigger an upgrade (if the current version does not match the desired version). The set of recommended update values is listed as part of available updates in status, and setting values outside that range may cause the upgrade to fail. 
///  Some of the fields are inter-related with restrictions and meanings described here. 1. image is specified, version is specified, architecture is specified. API validation error. 2. image is specified, version is specified, architecture is not specified. You should not do this. version is silently ignored and image is used. 3. image is specified, version is not specified, architecture is specified. API validation error. 4. image is specified, version is not specified, architecture is not specified. image is used. 5. image is not specified, version is specified, architecture is specified. version and desired architecture are used to select an image. 6. image is not specified, version is specified, architecture is not specified. version and current architecture are used to select an image. 7. image is not specified, version is not specified, architecture is specified. API validation error. 8. image is not specified, version is not specified, architecture is not specified. API validation error. 
///  If an upgrade fails the operator will halt and report status about the failing component. Setting the desired update value back to the previous version will cause a rollback to be attempted. Not all rollbacks will succeed.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ClusterVersionDesiredUpdateArchitecture {
    Multi,
    #[serde(rename = "")]
    KopiumEmpty,
}

/// ComponentOverride allows overriding cluster version operator's behavior for a component.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterVersionOverrides {
    /// group identifies the API group that the kind is in.
    pub group: String,
    /// kind indentifies which object to override.
    pub kind: String,
    /// name is the component's name.
    pub name: String,
    /// namespace is the component's namespace. If the resource is cluster scoped, the namespace should be empty.
    pub namespace: String,
    /// unmanaged controls if cluster version operator should stop managing the resources in this cluster. Default: false
    pub unmanaged: bool,
}

/// status contains information about the available updates and any in-progress updates.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterVersionStatus {
    /// availableUpdates contains updates recommended for this cluster. Updates which appear in conditionalUpdates but not in availableUpdates may expose this cluster to known issues. This list may be empty if no updates are recommended, if the update service is unavailable, or if an invalid channel has been specified.
    #[serde(rename = "availableUpdates")]
    pub available_updates: Vec<ClusterVersionStatusAvailableUpdates>,
    /// capabilities describes the state of optional, core cluster components.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<ClusterVersionStatusCapabilities>,
    /// conditionalUpdates contains the list of updates that may be recommended for this cluster if it meets specific required conditions. Consumers interested in the set of updates that are actually recommended for this cluster should use availableUpdates. This list may be empty if no updates are recommended, if the update service is unavailable, or if an empty or invalid channel has been specified.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "conditionalUpdates")]
    pub conditional_updates: Option<Vec<ClusterVersionStatusConditionalUpdates>>,
    /// conditions provides information about the cluster version. The condition "Available" is set to true if the desiredUpdate has been reached. The condition "Progressing" is set to true if an update is being applied. The condition "Degraded" is set to true if an update is currently blocked by a temporary or permanent error. Conditions are only valid for the current desiredUpdate when metadata.generation is equal to status.generation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// desired is the version that the cluster is reconciling towards. If the cluster is not yet fully initialized desired will be set with the information available, which may be an image or a tag.
    pub desired: ClusterVersionStatusDesired,
    /// history contains a list of the most recent versions applied to the cluster. This value may be empty during cluster startup, and then will be updated when a new update is being applied. The newest update is first in the list and it is ordered by recency. Updates in the history have state Completed if the rollout completed - if an update was failing or halfway applied the state will be Partial. Only a limited amount of update history is preserved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<Vec<ClusterVersionStatusHistory>>,
    /// observedGeneration reports which version of the spec is being synced. If this value is not equal to metadata.generation, then the desired and conditions fields may represent a previous version.
    #[serde(rename = "observedGeneration")]
    pub observed_generation: i64,
    /// versionHash is a fingerprint of the content that the cluster will be updated with. It is used by the operator to avoid unnecessary work and is for internal use only.
    #[serde(rename = "versionHash")]
    pub version_hash: String,
}

/// Release represents an OpenShift release image and associated metadata.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterVersionStatusAvailableUpdates {
    /// channels is the set of Cincinnati channels to which the release currently belongs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channels: Option<Vec<String>>,
    /// image is a container image location that contains the update. When this field is part of spec, image is optional if version is specified and the availableUpdates field contains a matching version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// url contains information about this release. This URL is set by the 'url' metadata property on a release or the metadata returned by the update API and should be displayed as a link in user interfaces. The URL field may not be set for test or nightly releases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// version is a semantic version identifying the update version. When this field is part of spec, version is optional if image is specified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// capabilities describes the state of optional, core cluster components.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterVersionStatusCapabilities {
    /// enabledCapabilities lists all the capabilities that are currently managed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "enabledCapabilities")]
    pub enabled_capabilities: Option<Vec<String>>,
    /// knownCapabilities lists all the capabilities known to the current cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "knownCapabilities")]
    pub known_capabilities: Option<Vec<String>>,
}

/// ConditionalUpdate represents an update which is recommended to some clusters on the version the current cluster is reconciling, but which may not be recommended for the current cluster.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterVersionStatusConditionalUpdates {
    /// conditions represents the observations of the conditional update's current status. Known types are: * Evaluating, for whether the cluster-version operator will attempt to evaluate any risks[].matchingRules. * Recommended, for whether the update is recommended for the current cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// release is the target of the update.
    pub release: ClusterVersionStatusConditionalUpdatesRelease,
    /// risks represents the range of issues associated with updating to the target release. The cluster-version operator will evaluate all entries, and only recommend the update if there is at least one entry and all entries recommend the update.
    pub risks: Vec<ClusterVersionStatusConditionalUpdatesRisks>,
}

/// release is the target of the update.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterVersionStatusConditionalUpdatesRelease {
    /// channels is the set of Cincinnati channels to which the release currently belongs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channels: Option<Vec<String>>,
    /// image is a container image location that contains the update. When this field is part of spec, image is optional if version is specified and the availableUpdates field contains a matching version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// url contains information about this release. This URL is set by the 'url' metadata property on a release or the metadata returned by the update API and should be displayed as a link in user interfaces. The URL field may not be set for test or nightly releases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// version is a semantic version identifying the update version. When this field is part of spec, version is optional if image is specified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// ConditionalUpdateRisk represents a reason and cluster-state for not recommending a conditional update.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterVersionStatusConditionalUpdatesRisks {
    /// matchingRules is a slice of conditions for deciding which clusters match the risk and which do not. The slice is ordered by decreasing precedence. The cluster-version operator will walk the slice in order, and stop after the first it can successfully evaluate. If no condition can be successfully evaluated, the update will not be recommended.
    #[serde(rename = "matchingRules")]
    pub matching_rules: Vec<ClusterVersionStatusConditionalUpdatesRisksMatchingRules>,
    /// message provides additional information about the risk of updating, in the event that matchingRules match the cluster state. This is only to be consumed by humans. It may contain Line Feed characters (U+000A), which should be rendered as new lines.
    pub message: String,
    /// name is the CamelCase reason for not recommending a conditional update, in the event that matchingRules match the cluster state.
    pub name: String,
    /// url contains information about this risk.
    pub url: String,
}

/// ClusterCondition is a union of typed cluster conditions.  The 'type' property determines which of the type-specific properties are relevant. When evaluated on a cluster, the condition may match, not match, or fail to evaluate.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterVersionStatusConditionalUpdatesRisksMatchingRules {
    /// promQL represents a cluster condition based on PromQL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promql: Option<ClusterVersionStatusConditionalUpdatesRisksMatchingRulesPromql>,
    /// type represents the cluster-condition type. This defines the members and semantics of any additional properties.
    #[serde(rename = "type")]
    pub r#type: ClusterVersionStatusConditionalUpdatesRisksMatchingRulesType,
}

/// promQL represents a cluster condition based on PromQL.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterVersionStatusConditionalUpdatesRisksMatchingRulesPromql {
    /// PromQL is a PromQL query classifying clusters. This query query should return a 1 in the match case and a 0 in the does-not-match case. Queries which return no time series, or which return values besides 0 or 1, are evaluation failures.
    pub promql: String,
}

/// ClusterCondition is a union of typed cluster conditions.  The 'type' property determines which of the type-specific properties are relevant. When evaluated on a cluster, the condition may match, not match, or fail to evaluate.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ClusterVersionStatusConditionalUpdatesRisksMatchingRulesType {
    Always,
    #[serde(rename = "PromQL")]
    PromQl,
}

/// desired is the version that the cluster is reconciling towards. If the cluster is not yet fully initialized desired will be set with the information available, which may be an image or a tag.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterVersionStatusDesired {
    /// channels is the set of Cincinnati channels to which the release currently belongs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channels: Option<Vec<String>>,
    /// image is a container image location that contains the update. When this field is part of spec, image is optional if version is specified and the availableUpdates field contains a matching version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// url contains information about this release. This URL is set by the 'url' metadata property on a release or the metadata returned by the update API and should be displayed as a link in user interfaces. The URL field may not be set for test or nightly releases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// version is a semantic version identifying the update version. When this field is part of spec, version is optional if image is specified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// UpdateHistory is a single attempted update to the cluster.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterVersionStatusHistory {
    /// acceptedRisks records risks which were accepted to initiate the update. For example, it may menition an Upgradeable=False or missing signature that was overriden via desiredUpdate.force, or an update that was initiated despite not being in the availableUpdates set of recommended update targets.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "acceptedRisks")]
    pub accepted_risks: Option<String>,
    /// completionTime, if set, is when the update was fully applied. The update that is currently being applied will have a null completion time. Completion time will always be set for entries that are not the current update (usually to the started time of the next update).
    #[serde(rename = "completionTime")]
    pub completion_time: String,
    /// image is a container image location that contains the update. This value is always populated.
    pub image: String,
    /// startedTime is the time at which the update was started.
    #[serde(rename = "startedTime")]
    pub started_time: String,
    /// state reflects whether the update was fully applied. The Partial state indicates the update is not fully applied, while the Completed state indicates the update was successfully rolled out at least once (all parts of the update successfully applied).
    pub state: String,
    /// verified indicates whether the provided update was properly verified before it was installed. If this is false the cluster may not be trusted. Verified does not cover upgradeable checks that depend on the cluster state at the time when the update target was accepted.
    pub verified: bool,
    /// version is a semantic version identifying the update version. If the requested image does not define a version, or if a failure occurs retrieving the image, this value may be empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

