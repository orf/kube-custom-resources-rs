// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/vmware-tanzu/velero/velero.io/v1/volumesnapshotlocations.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// VolumeSnapshotLocationSpec defines the specification for a Velero VolumeSnapshotLocation.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "velero.io", version = "v1", kind = "VolumeSnapshotLocation", plural = "volumesnapshotlocations")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct VolumeSnapshotLocationSpec {
    /// Config is for provider-specific configuration fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<BTreeMap<String, String>>,
    /// Credential contains the credential information intended to be used with this location
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<VolumeSnapshotLocationCredential>,
    /// Provider is the provider of the volume storage.
    pub provider: String,
}

/// Credential contains the credential information intended to be used with this location
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct VolumeSnapshotLocationCredential {
    /// The key of the secret to select from.  Must be a valid secret key.
    pub key: String,
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Specify whether the Secret or its key must be defined
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// VolumeSnapshotLocationStatus describes the current status of a Velero VolumeSnapshotLocation.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct VolumeSnapshotLocationStatus {
    /// VolumeSnapshotLocationPhase is the lifecycle phase of a Velero VolumeSnapshotLocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<VolumeSnapshotLocationStatusPhase>,
}

/// VolumeSnapshotLocationStatus describes the current status of a Velero VolumeSnapshotLocation.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum VolumeSnapshotLocationStatusPhase {
    Available,
    Unavailable,
}

