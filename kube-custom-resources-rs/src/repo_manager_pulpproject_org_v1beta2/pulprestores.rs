// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename ./crd-catalog/pulp/pulp-operator/repo-manager.pulpproject.org/v1beta2/pulprestores.yaml
// kopium version: 0.16.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// PulpRestoreSpec defines the desired state of PulpRestore
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug)]
#[kube(group = "repo-manager.pulpproject.org", version = "v1beta2", kind = "PulpRestore", plural = "pulprestores")]
#[kube(namespaced)]
#[kube(status = "PulpRestoreStatus")]
#[kube(schema = "disabled")]
pub struct PulpRestoreSpec {
    /// Backup directory name, set as a status found on the backup object (backupDirectory)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_dir: Option<String>,
    /// Name of the backup custom resource
    pub backup_name: String,
    /// Name of the PVC to be restored from, set as a status found on the backup object (backupClaim)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_pvc: Option<String>,
    /// Name of the deployment to be restored to
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_name: Option<String>,
    /// Name of the deployment type. Can be one of {galaxy,pulp}.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_type: Option<PulpRestoreDeploymentType>,
    /// KeepBackupReplicasCount allows to define if the restore controller should restore the components with the same number of replicas from backup or restore only a single replica each.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_replicas: Option<bool>,
}

/// PulpRestoreSpec defines the desired state of PulpRestore
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum PulpRestoreDeploymentType {
    #[serde(rename = "galaxy")]
    Galaxy,
    #[serde(rename = "pulp")]
    Pulp,
}

/// PulpRestoreStatus defines the observed state of PulpRestore
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PulpRestoreStatus {
    pub conditions: Vec<PulpRestoreStatusConditions>,
    pub postgres_secret: String,
}

/// Condition contains details for one aspect of the current state of this API Resource. --- This struct is intended for direct use as an array at the field path .status.conditions.  For example, 
///  type FooStatus struct{ // Represents the observations of a foo's current state. // Known .status.conditions.type are: "Available", "Progressing", and "Degraded" // +patchMergeKey=type // +patchStrategy=merge // +listType=map // +listMapKey=type Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"` 
///  // other fields }
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PulpRestoreStatusConditions {
    /// lastTransitionTime is the last time the condition transitioned from one status to another. This should be when the underlying condition changed.  If that is not known, then using the time when the API field changed is acceptable.
    #[serde(rename = "lastTransitionTime")]
    pub last_transition_time: String,
    /// message is a human readable message indicating details about the transition. This may be an empty string.
    pub message: String,
    /// observedGeneration represents the .metadata.generation that the condition was set based upon. For instance, if .metadata.generation is currently 12, but the .status.conditions[x].observedGeneration is 9, the condition is out of date with respect to the current state of the instance.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
    /// reason contains a programmatic identifier indicating the reason for the condition's last transition. Producers of specific condition types may define expected values and meanings for this field, and whether the values are considered a guaranteed API. The value should be a CamelCase string. This field may not be empty.
    pub reason: String,
    /// status of the condition, one of True, False, Unknown.
    pub status: PulpRestoreStatusConditionsStatus,
    /// type of condition in CamelCase or in foo.example.com/CamelCase. --- Many .condition.type values are consistent across resources like Available, but because arbitrary conditions can be useful (see .node.status.conditions), the ability to deconflict is important. The regex it matches is (dns1123SubdomainFmt/)?(qualifiedNameFmt)
    #[serde(rename = "type")]
    pub r#type: String,
}

/// Condition contains details for one aspect of the current state of this API Resource. --- This struct is intended for direct use as an array at the field path .status.conditions.  For example, 
///  type FooStatus struct{ // Represents the observations of a foo's current state. // Known .status.conditions.type are: "Available", "Progressing", and "Degraded" // +patchMergeKey=type // +patchStrategy=merge // +listType=map // +listMapKey=type Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"` 
///  // other fields }
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum PulpRestoreStatusConditionsStatus {
    True,
    False,
    Unknown,
}

