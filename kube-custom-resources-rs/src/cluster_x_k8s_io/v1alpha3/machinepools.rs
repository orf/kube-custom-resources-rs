// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kubernetes-sigs/cluster-api/cluster.x-k8s.io/v1alpha3/machinepools.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// MachinePoolSpec defines the desired state of MachinePool.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "cluster.x-k8s.io", version = "v1alpha3", kind = "MachinePool", plural = "machinepools")]
#[kube(namespaced)]
#[kube(status = "MachinePoolStatus")]
#[kube(schema = "disabled")]
pub struct MachinePoolSpec {
    /// ClusterName is the name of the Cluster this object belongs to.
    #[serde(rename = "clusterName")]
    pub cluster_name: String,
    /// FailureDomains is the list of failure domains this MachinePool should be attached to.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "failureDomains")]
    pub failure_domains: Option<Vec<String>>,
    /// Minimum number of seconds for which a newly created machine instances should
    /// be ready.
    /// Defaults to 0 (machine instance will be considered available as soon as it
    /// is ready)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "minReadySeconds")]
    pub min_ready_seconds: Option<i32>,
    /// ProviderIDList are the identification IDs of machine instances provided by the provider.
    /// This field must match the provider IDs as seen on the node objects corresponding to a machine pool's machine instances.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "providerIDList")]
    pub provider_id_list: Option<Vec<String>>,
    /// Number of desired machines. Defaults to 1.
    /// This is a pointer to distinguish between explicit zero and not specified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<i32>,
    /// The deployment strategy to use to replace existing machine instances with
    /// new ones.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<MachinePoolStrategy>,
    /// Template describes the machines that will be created.
    pub template: MachinePoolTemplate,
}

/// The deployment strategy to use to replace existing machine instances with
/// new ones.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MachinePoolStrategy {
    /// Rolling update config params. Present only if
    /// MachineDeploymentStrategyType = RollingUpdate.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "rollingUpdate")]
    pub rolling_update: Option<MachinePoolStrategyRollingUpdate>,
    /// Type of deployment. Currently the only supported strategy is
    /// "RollingUpdate".
    /// Default is RollingUpdate.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
}

/// Rolling update config params. Present only if
/// MachineDeploymentStrategyType = RollingUpdate.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MachinePoolStrategyRollingUpdate {
    /// The maximum number of machines that can be scheduled above the
    /// desired number of machines.
    /// Value can be an absolute number (ex: 5) or a percentage of
    /// desired machines (ex: 10%).
    /// This can not be 0 if MaxUnavailable is 0.
    /// Absolute number is calculated from percentage by rounding up.
    /// Defaults to 1.
    /// Example: when this is set to 30%, the new MachineSet can be scaled
    /// up immediately when the rolling update starts, such that the total
    /// number of old and new machines do not exceed 130% of desired
    /// machines. Once old machines have been killed, new MachineSet can
    /// be scaled up further, ensuring that total number of machines running
    /// at any time during the update is at most 130% of desired machines.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxSurge")]
    pub max_surge: Option<IntOrString>,
    /// The maximum number of machines that can be unavailable during the update.
    /// Value can be an absolute number (ex: 5) or a percentage of desired
    /// machines (ex: 10%).
    /// Absolute number is calculated from percentage by rounding down.
    /// This can not be 0 if MaxSurge is 0.
    /// Defaults to 0.
    /// Example: when this is set to 30%, the old MachineSet can be scaled
    /// down to 70% of desired machines immediately when the rolling update
    /// starts. Once new machines are ready, old MachineSet can be scaled
    /// down further, followed by scaling up the new MachineSet, ensuring
    /// that the total number of machines available at all times
    /// during the update is at least 70% of desired machines.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxUnavailable")]
    pub max_unavailable: Option<IntOrString>,
}

/// Template describes the machines that will be created.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MachinePoolTemplate {
    /// Standard object's metadata.
    /// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<MachinePoolTemplateMetadata>,
    /// Specification of the desired behavior of the machine.
    /// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<MachinePoolTemplateSpec>,
}

/// Standard object's metadata.
/// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MachinePoolTemplateMetadata {
    /// Annotations is an unstructured key value map stored with a resource that may be
    /// set by external tools to store and retrieve arbitrary metadata. They are not
    /// queryable and should be preserved when modifying objects.
    /// More info: http://kubernetes.io/docs/user-guide/annotations
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
    /// GenerateName is an optional prefix, used by the server, to generate a unique
    /// name ONLY IF the Name field has not been provided.
    /// If this field is used, the name returned to the client will be different
    /// than the name passed. This value will also be combined with a unique suffix.
    /// The provided value has the same validation rules as the Name field,
    /// and may be truncated by the length of the suffix required to make the value
    /// unique on the server.
    /// 
    /// 
    /// If this field is specified and the generated name exists, the server will
    /// NOT return a 409 - instead, it will either return 201 Created or 500 with Reason
    /// ServerTimeout indicating a unique name could not be found in the time allotted, and the client
    /// should retry (optionally after the time indicated in the Retry-After header).
    /// 
    /// 
    /// Applied only if Name is not specified.
    /// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#idempotency
    /// 
    /// 
    /// Deprecated: This field has no function and is going to be removed in a next release.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "generateName")]
    pub generate_name: Option<String>,
    /// Map of string keys and values that can be used to organize and categorize
    /// (scope and select) objects. May match selectors of replication controllers
    /// and services.
    /// More info: http://kubernetes.io/docs/user-guide/labels
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    /// Name must be unique within a namespace. Is required when creating resources, although
    /// some resources may allow a client to request the generation of an appropriate name
    /// automatically. Name is primarily intended for creation idempotence and configuration
    /// definition.
    /// Cannot be updated.
    /// More info: http://kubernetes.io/docs/user-guide/identifiers#names
    /// 
    /// 
    /// Deprecated: This field has no function and is going to be removed in a next release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Namespace defines the space within each name must be unique. An empty namespace is
    /// equivalent to the "default" namespace, but "default" is the canonical representation.
    /// Not all objects are required to be scoped to a namespace - the value of this field for
    /// those objects will be empty.
    /// 
    /// 
    /// Must be a DNS_LABEL.
    /// Cannot be updated.
    /// More info: http://kubernetes.io/docs/user-guide/namespaces
    /// 
    /// 
    /// Deprecated: This field has no function and is going to be removed in a next release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// List of objects depended by this object. If ALL objects in the list have
    /// been deleted, this object will be garbage collected. If this object is managed by a controller,
    /// then an entry in this list will point to this controller, with the controller field set to true.
    /// There cannot be more than one managing controller.
    /// 
    /// 
    /// Deprecated: This field has no function and is going to be removed in a next release.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ownerReferences")]
    pub owner_references: Option<Vec<MachinePoolTemplateMetadataOwnerReferences>>,
}

/// OwnerReference contains enough information to let you identify an owning
/// object. An owning object must be in the same namespace as the dependent, or
/// be cluster-scoped, so there is no namespace field.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MachinePoolTemplateMetadataOwnerReferences {
    /// API version of the referent.
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    /// If true, AND if the owner has the "foregroundDeletion" finalizer, then
    /// the owner cannot be deleted from the key-value store until this
    /// reference is removed.
    /// See https://kubernetes.io/docs/concepts/architecture/garbage-collection/#foreground-deletion
    /// for how the garbage collector interacts with this field and enforces the foreground deletion.
    /// Defaults to false.
    /// To set this field, a user needs "delete" permission of the owner,
    /// otherwise 422 (Unprocessable Entity) will be returned.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "blockOwnerDeletion")]
    pub block_owner_deletion: Option<bool>,
    /// If true, this reference points to the managing controller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller: Option<bool>,
    /// Kind of the referent.
    /// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
    pub kind: String,
    /// Name of the referent.
    /// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names#names
    pub name: String,
    /// UID of the referent.
    /// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names#uids
    pub uid: String,
}

/// Specification of the desired behavior of the machine.
/// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MachinePoolTemplateSpec {
    /// Bootstrap is a reference to a local struct which encapsulates
    /// fields to configure the Machine’s bootstrapping mechanism.
    pub bootstrap: MachinePoolTemplateSpecBootstrap,
    /// ClusterName is the name of the Cluster this object belongs to.
    #[serde(rename = "clusterName")]
    pub cluster_name: String,
    /// FailureDomain is the failure domain the machine will be created in.
    /// Must match a key in the FailureDomains map stored on the cluster object.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "failureDomain")]
    pub failure_domain: Option<String>,
    /// InfrastructureRef is a required reference to a custom resource
    /// offered by an infrastructure provider.
    #[serde(rename = "infrastructureRef")]
    pub infrastructure_ref: MachinePoolTemplateSpecInfrastructureRef,
    /// NodeDrainTimeout is the total amount of time that the controller will spend on draining a node.
    /// The default value is 0, meaning that the node can be drained without any time limitations.
    /// NOTE: NodeDrainTimeout is different from `kubectl drain --timeout`
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nodeDrainTimeout")]
    pub node_drain_timeout: Option<String>,
    /// ProviderID is the identification ID of the machine provided by the provider.
    /// This field must match the provider ID as seen on the node object corresponding to this machine.
    /// This field is required by higher level consumers of cluster-api. Example use case is cluster autoscaler
    /// with cluster-api as provider. Clean-up logic in the autoscaler compares machines to nodes to find out
    /// machines at provider which could not get registered as Kubernetes nodes. With cluster-api as a
    /// generic out-of-tree provider for autoscaler, this field is required by autoscaler to be
    /// able to have a provider view of the list of machines. Another list of nodes is queried from the k8s apiserver
    /// and then a comparison is done to find out unregistered machines and are marked for delete.
    /// This field will be set by the actuators and consumed by higher level entities like autoscaler that will
    /// be interfacing with cluster-api as generic provider.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "providerID")]
    pub provider_id: Option<String>,
    /// Version defines the desired Kubernetes version.
    /// This field is meant to be optionally used by bootstrap providers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Bootstrap is a reference to a local struct which encapsulates
/// fields to configure the Machine’s bootstrapping mechanism.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MachinePoolTemplateSpecBootstrap {
    /// ConfigRef is a reference to a bootstrap provider-specific resource
    /// that holds configuration details. The reference is optional to
    /// allow users/operators to specify Bootstrap.Data without
    /// the need of a controller.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "configRef")]
    pub config_ref: Option<MachinePoolTemplateSpecBootstrapConfigRef>,
    /// Data contains the bootstrap data, such as cloud-init details scripts.
    /// If nil, the Machine should remain in the Pending state.
    /// 
    /// 
    /// Deprecated: Switch to DataSecretName.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// DataSecretName is the name of the secret that stores the bootstrap data script.
    /// If nil, the Machine should remain in the Pending state.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dataSecretName")]
    pub data_secret_name: Option<String>,
}

/// ConfigRef is a reference to a bootstrap provider-specific resource
/// that holds configuration details. The reference is optional to
/// allow users/operators to specify Bootstrap.Data without
/// the need of a controller.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MachinePoolTemplateSpecBootstrapConfigRef {
    /// API version of the referent.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiVersion")]
    pub api_version: Option<String>,
    /// If referring to a piece of an object instead of an entire object, this string
    /// should contain a valid JSON/Go field access statement, such as desiredState.manifest.containers[2].
    /// For example, if the object reference is to a container within a pod, this would take on a value like:
    /// "spec.containers{name}" (where "name" refers to the name of the container that triggered
    /// the event) or if no container name is specified "spec.containers[2]" (container with
    /// index 2 in this pod). This syntax is chosen only to have some well-defined way of
    /// referencing a part of an object.
    /// TODO: this design is not final and this field is subject to change in the future.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "fieldPath")]
    pub field_path: Option<String>,
    /// Kind of the referent.
    /// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Name of the referent.
    /// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Namespace of the referent.
    /// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Specific resourceVersion to which this reference is made, if any.
    /// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#concurrency-control-and-consistency
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "resourceVersion")]
    pub resource_version: Option<String>,
    /// UID of the referent.
    /// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#uids
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
}

/// InfrastructureRef is a required reference to a custom resource
/// offered by an infrastructure provider.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MachinePoolTemplateSpecInfrastructureRef {
    /// API version of the referent.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiVersion")]
    pub api_version: Option<String>,
    /// If referring to a piece of an object instead of an entire object, this string
    /// should contain a valid JSON/Go field access statement, such as desiredState.manifest.containers[2].
    /// For example, if the object reference is to a container within a pod, this would take on a value like:
    /// "spec.containers{name}" (where "name" refers to the name of the container that triggered
    /// the event) or if no container name is specified "spec.containers[2]" (container with
    /// index 2 in this pod). This syntax is chosen only to have some well-defined way of
    /// referencing a part of an object.
    /// TODO: this design is not final and this field is subject to change in the future.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "fieldPath")]
    pub field_path: Option<String>,
    /// Kind of the referent.
    /// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Name of the referent.
    /// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Namespace of the referent.
    /// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Specific resourceVersion to which this reference is made, if any.
    /// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#concurrency-control-and-consistency
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "resourceVersion")]
    pub resource_version: Option<String>,
    /// UID of the referent.
    /// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#uids
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
}

/// MachinePoolStatus defines the observed state of MachinePool.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MachinePoolStatus {
    /// The number of available replicas (ready for at least minReadySeconds) for this MachinePool.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "availableReplicas")]
    pub available_replicas: Option<i32>,
    /// BootstrapReady is the state of the bootstrap provider.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "bootstrapReady")]
    pub bootstrap_ready: Option<bool>,
    /// Conditions define the current service state of the MachinePool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// FailureMessage indicates that there is a problem reconciling the state,
    /// and will be set to a descriptive error message.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "failureMessage")]
    pub failure_message: Option<String>,
    /// FailureReason indicates that there is a problem reconciling the state, and
    /// will be set to a token value suitable for programmatic interpretation.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "failureReason")]
    pub failure_reason: Option<String>,
    /// InfrastructureReady is the state of the infrastructure provider.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "infrastructureReady")]
    pub infrastructure_ready: Option<bool>,
    /// NodeRefs will point to the corresponding Nodes if it they exist.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nodeRefs")]
    pub node_refs: Option<Vec<MachinePoolStatusNodeRefs>>,
    /// ObservedGeneration is the latest generation observed by the controller.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
    /// Phase represents the current phase of cluster actuation.
    /// E.g. Pending, Running, Terminating, Failed etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    /// The number of ready replicas for this MachinePool. A machine is considered ready when the node has been created and is "Ready".
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "readyReplicas")]
    pub ready_replicas: Option<i32>,
    /// Replicas is the most recently observed number of replicas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<i32>,
    /// Total number of unavailable machine instances targeted by this machine pool.
    /// This is the total number of machine instances that are still required for
    /// the machine pool to have 100% available capacity. They may either
    /// be machine instances that are running but not yet available or machine instances
    /// that still have not been created.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "unavailableReplicas")]
    pub unavailable_replicas: Option<i32>,
}

/// ObjectReference contains enough information to let you inspect or modify the referred object.
/// ---
/// New uses of this type are discouraged because of difficulty describing its usage when embedded in APIs.
///  1. Ignored fields.  It includes many fields which are not generally honored.  For instance, ResourceVersion and FieldPath are both very rarely valid in actual usage.
///  2. Invalid usage help.  It is impossible to add specific help for individual usage.  In most embedded usages, there are particular
///     restrictions like, "must refer only to types A and B" or "UID not honored" or "name must be restricted".
///     Those cannot be well described when embedded.
///  3. Inconsistent validation.  Because the usages are different, the validation rules are different by usage, which makes it hard for users to predict what will happen.
///  4. The fields are both imprecise and overly precise.  Kind is not a precise mapping to a URL. This can produce ambiguity
///     during interpretation and require a REST mapping.  In most cases, the dependency is on the group,resource tuple
///     and the version of the actual struct is irrelevant.
///  5. We cannot easily change it.  Because this type is embedded in many locations, updates to this type
///     will affect numerous schemas.  Don't make new APIs embed an underspecified API type they do not control.
/// 
/// 
/// Instead of using this type, create a locally provided and used type that is well-focused on your reference.
/// For example, ServiceReferences for admission registration: https://github.com/kubernetes/api/blob/release-1.17/admissionregistration/v1/types.go#L533 .
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MachinePoolStatusNodeRefs {
    /// API version of the referent.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiVersion")]
    pub api_version: Option<String>,
    /// If referring to a piece of an object instead of an entire object, this string
    /// should contain a valid JSON/Go field access statement, such as desiredState.manifest.containers[2].
    /// For example, if the object reference is to a container within a pod, this would take on a value like:
    /// "spec.containers{name}" (where "name" refers to the name of the container that triggered
    /// the event) or if no container name is specified "spec.containers[2]" (container with
    /// index 2 in this pod). This syntax is chosen only to have some well-defined way of
    /// referencing a part of an object.
    /// TODO: this design is not final and this field is subject to change in the future.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "fieldPath")]
    pub field_path: Option<String>,
    /// Kind of the referent.
    /// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Name of the referent.
    /// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Namespace of the referent.
    /// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Specific resourceVersion to which this reference is made, if any.
    /// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#concurrency-control-and-consistency
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "resourceVersion")]
    pub resource_version: Option<String>,
    /// UID of the referent.
    /// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#uids
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
}

