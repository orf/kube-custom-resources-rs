// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/open-feature/open-feature-operator/core.openfeature.dev/v1alpha2/featureflagconfigurations.yaml --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

/// FeatureFlagConfigurationSpec defines the desired state of FeatureFlagConfiguration
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "core.openfeature.dev", version = "v1alpha2", kind = "FeatureFlagConfiguration", plural = "featureflagconfigurations")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct FeatureFlagConfigurationSpec {
    /// FeatureFlagSpec is the structured representation of the feature flag specification
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "featureFlagSpec")]
    pub feature_flag_spec: Option<FeatureFlagConfigurationFeatureFlagSpec>,
    /// FlagDSpec [DEPRECATED]: superseded by FlagSourceConfiguration
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "flagDSpec")]
    pub flag_d_spec: Option<FeatureFlagConfigurationFlagDSpec>,
    /// Resources defines flagd sidecar resources. Default to operator sidecar-cpu-* and sidecar-ram-* flags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<FeatureFlagConfigurationResources>,
    /// ServiceProvider [DEPRECATED]: superseded by FlagSourceConfiguration
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "serviceProvider")]
    pub service_provider: Option<FeatureFlagConfigurationServiceProvider>,
    /// SyncProvider [DEPRECATED]: superseded by FlagSourceConfiguration
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "syncProvider")]
    pub sync_provider: Option<FeatureFlagConfigurationSyncProvider>,
}

/// FeatureFlagSpec is the structured representation of the feature flag specification
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FeatureFlagConfigurationFeatureFlagSpec {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "$evaluators")]
    pub evaluators: Option<BTreeMap<String, serde_json::Value>>,
    pub flags: BTreeMap<String, FeatureFlagConfigurationFeatureFlagSpecFlags>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FeatureFlagConfigurationFeatureFlagSpecFlags {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "defaultVariant")]
    pub default_variant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<FeatureFlagConfigurationFeatureFlagSpecFlagsState>,
    /// Targeting is the json targeting rule
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub targeting: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variants: Option<BTreeMap<String, serde_json::Value>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum FeatureFlagConfigurationFeatureFlagSpecFlagsState {
    #[serde(rename = "ENABLED")]
    Enabled,
    #[serde(rename = "DISABLED")]
    Disabled,
}

/// FlagDSpec [DEPRECATED]: superseded by FlagSourceConfiguration
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FeatureFlagConfigurationFlagDSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envs: Option<Vec<FeatureFlagConfigurationFlagDSpecEnvs>>,
}

/// EnvVar represents an environment variable present in a Container.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FeatureFlagConfigurationFlagDSpecEnvs {
    /// Name of the environment variable. Must be a C_IDENTIFIER.
    pub name: String,
    /// Variable references $(VAR_NAME) are expanded using the previously defined environment variables in the container and any service environment variables. If a variable cannot be resolved, the reference in the input string will be unchanged. Double $$ are reduced to a single $, which allows for escaping the $(VAR_NAME) syntax: i.e. "$$(VAR_NAME)" will produce the string literal "$(VAR_NAME)". Escaped references will never be expanded, regardless of whether the variable exists or not. Defaults to "".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Source for the environment variable's value. Cannot be used if value is not empty.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "valueFrom")]
    pub value_from: Option<FeatureFlagConfigurationFlagDSpecEnvsValueFrom>,
}

/// Source for the environment variable's value. Cannot be used if value is not empty.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FeatureFlagConfigurationFlagDSpecEnvsValueFrom {
    /// Selects a key of a ConfigMap.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "configMapKeyRef")]
    pub config_map_key_ref: Option<FeatureFlagConfigurationFlagDSpecEnvsValueFromConfigMapKeyRef>,
    /// Selects a field of the pod: supports metadata.name, metadata.namespace, `metadata.labels['<KEY>']`, `metadata.annotations['<KEY>']`, spec.nodeName, spec.serviceAccountName, status.hostIP, status.podIP, status.podIPs.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "fieldRef")]
    pub field_ref: Option<FeatureFlagConfigurationFlagDSpecEnvsValueFromFieldRef>,
    /// Selects a resource of the container: only resources limits and requests (limits.cpu, limits.memory, limits.ephemeral-storage, requests.cpu, requests.memory and requests.ephemeral-storage) are currently supported.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "resourceFieldRef")]
    pub resource_field_ref: Option<FeatureFlagConfigurationFlagDSpecEnvsValueFromResourceFieldRef>,
    /// Selects a key of a secret in the pod's namespace
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretKeyRef")]
    pub secret_key_ref: Option<FeatureFlagConfigurationFlagDSpecEnvsValueFromSecretKeyRef>,
}

/// Selects a key of a ConfigMap.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FeatureFlagConfigurationFlagDSpecEnvsValueFromConfigMapKeyRef {
    /// The key to select.
    pub key: String,
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Specify whether the ConfigMap or its key must be defined
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// Selects a field of the pod: supports metadata.name, metadata.namespace, `metadata.labels['<KEY>']`, `metadata.annotations['<KEY>']`, spec.nodeName, spec.serviceAccountName, status.hostIP, status.podIP, status.podIPs.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FeatureFlagConfigurationFlagDSpecEnvsValueFromFieldRef {
    /// Version of the schema the FieldPath is written in terms of, defaults to "v1".
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiVersion")]
    pub api_version: Option<String>,
    /// Path of the field to select in the specified API version.
    #[serde(rename = "fieldPath")]
    pub field_path: String,
}

/// Selects a resource of the container: only resources limits and requests (limits.cpu, limits.memory, limits.ephemeral-storage, requests.cpu, requests.memory and requests.ephemeral-storage) are currently supported.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FeatureFlagConfigurationFlagDSpecEnvsValueFromResourceFieldRef {
    /// Container name: required for volumes, optional for env vars
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "containerName")]
    pub container_name: Option<String>,
    /// Specifies the output format of the exposed resources, defaults to "1"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub divisor: Option<IntOrString>,
    /// Required: resource to select
    pub resource: String,
}

/// Selects a key of a secret in the pod's namespace
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FeatureFlagConfigurationFlagDSpecEnvsValueFromSecretKeyRef {
    /// The key of the secret to select from.  Must be a valid secret key.
    pub key: String,
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Specify whether the Secret or its key must be defined
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// Resources defines flagd sidecar resources. Default to operator sidecar-cpu-* and sidecar-ram-* flags.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FeatureFlagConfigurationResources {
    /// Claims lists the names of resources, defined in spec.resourceClaims, that are used by this container. 
    ///  This is an alpha field and requires enabling the DynamicResourceAllocation feature gate. 
    ///  This field is immutable. It can only be set for containers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<FeatureFlagConfigurationResourcesClaims>>,
    /// Limits describes the maximum amount of compute resources allowed. More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<BTreeMap<String, IntOrString>>,
    /// Requests describes the minimum amount of compute resources required. If Requests is omitted for a container, it defaults to Limits if that is explicitly specified, otherwise to an implementation-defined value. More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<BTreeMap<String, IntOrString>>,
}

/// ResourceClaim references one entry in PodSpec.ResourceClaims.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FeatureFlagConfigurationResourcesClaims {
    /// Name must match the name of one entry in pod.spec.resourceClaims of the Pod where this field is used. It makes that resource available inside a container.
    pub name: String,
}

/// ServiceProvider [DEPRECATED]: superseded by FlagSourceConfiguration
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FeatureFlagConfigurationServiceProvider {
    /// ObjectReference contains enough information to let you inspect or modify the referred object. --- New uses of this type are discouraged because of difficulty describing its usage when embedded in APIs. 1. Ignored fields.  It includes many fields which are not generally honored.  For instance, ResourceVersion and FieldPath are both very rarely valid in actual usage. 2. Invalid usage help.  It is impossible to add specific help for individual usage.  In most embedded usages, there are particular restrictions like, "must refer only to types A and B" or "UID not honored" or "name must be restricted". Those cannot be well described when embedded. 3. Inconsistent validation.  Because the usages are different, the validation rules are different by usage, which makes it hard for users to predict what will happen. 4. The fields are both imprecise and overly precise.  Kind is not a precise mapping to a URL. This can produce ambiguity during interpretation and require a REST mapping.  In most cases, the dependency is on the group,resource tuple and the version of the actual struct is irrelevant. 5. We cannot easily change it.  Because this type is embedded in many locations, updates to this type will affect numerous schemas.  Don't make new APIs embed an underspecified API type they do not control. 
    ///  Instead of using this type, create a locally provided and used type that is well-focused on your reference. For example, ServiceReferences for admission registration: https://github.com/kubernetes/api/blob/release-1.17/admissionregistration/v1/types.go#L533 .
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<FeatureFlagConfigurationServiceProviderCredentials>,
    pub name: FeatureFlagConfigurationServiceProviderName,
}

/// ObjectReference contains enough information to let you inspect or modify the referred object. --- New uses of this type are discouraged because of difficulty describing its usage when embedded in APIs. 1. Ignored fields.  It includes many fields which are not generally honored.  For instance, ResourceVersion and FieldPath are both very rarely valid in actual usage. 2. Invalid usage help.  It is impossible to add specific help for individual usage.  In most embedded usages, there are particular restrictions like, "must refer only to types A and B" or "UID not honored" or "name must be restricted". Those cannot be well described when embedded. 3. Inconsistent validation.  Because the usages are different, the validation rules are different by usage, which makes it hard for users to predict what will happen. 4. The fields are both imprecise and overly precise.  Kind is not a precise mapping to a URL. This can produce ambiguity during interpretation and require a REST mapping.  In most cases, the dependency is on the group,resource tuple and the version of the actual struct is irrelevant. 5. We cannot easily change it.  Because this type is embedded in many locations, updates to this type will affect numerous schemas.  Don't make new APIs embed an underspecified API type they do not control. 
///  Instead of using this type, create a locally provided and used type that is well-focused on your reference. For example, ServiceReferences for admission registration: https://github.com/kubernetes/api/blob/release-1.17/admissionregistration/v1/types.go#L533 .
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FeatureFlagConfigurationServiceProviderCredentials {
    /// API version of the referent.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiVersion")]
    pub api_version: Option<String>,
    /// If referring to a piece of an object instead of an entire object, this string should contain a valid JSON/Go field access statement, such as desiredState.manifest.containers[2]. For example, if the object reference is to a container within a pod, this would take on a value like: "spec.containers{name}" (where "name" refers to the name of the container that triggered the event) or if no container name is specified "spec.containers[2]" (container with index 2 in this pod). This syntax is chosen only to have some well-defined way of referencing a part of an object. TODO: this design is not final and this field is subject to change in the future.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "fieldPath")]
    pub field_path: Option<String>,
    /// Kind of the referent. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Namespace of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Specific resourceVersion to which this reference is made, if any. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#concurrency-control-and-consistency
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "resourceVersion")]
    pub resource_version: Option<String>,
    /// UID of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#uids
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
}

/// ServiceProvider [DEPRECATED]: superseded by FlagSourceConfiguration
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum FeatureFlagConfigurationServiceProviderName {
    #[serde(rename = "flagd")]
    Flagd,
}

/// SyncProvider [DEPRECATED]: superseded by FlagSourceConfiguration
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FeatureFlagConfigurationSyncProvider {
    /// HttpSyncConfiguration defines the desired configuration for a http sync
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "httpSyncConfiguration")]
    pub http_sync_configuration: Option<FeatureFlagConfigurationSyncProviderHttpSyncConfiguration>,
    pub name: String,
}

/// HttpSyncConfiguration defines the desired configuration for a http sync
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FeatureFlagConfigurationSyncProviderHttpSyncConfiguration {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "bearerToken")]
    pub bearer_token: Option<String>,
    /// Target is the target url for flagd to poll
    pub target: String,
}

/// FeatureFlagConfigurationStatus defines the observed state of FeatureFlagConfiguration
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FeatureFlagConfigurationStatus {
}

