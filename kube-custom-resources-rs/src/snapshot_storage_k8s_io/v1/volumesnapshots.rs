// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kubernetes-csi/external-snapshotter/snapshot.storage.k8s.io/v1/volumesnapshots.yaml --derive=Default --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
}
use self::prelude::*;

/// spec defines the desired characteristics of a snapshot requested by a user.
/// More info: https://kubernetes.io/docs/concepts/storage/volume-snapshots#volumesnapshots
/// Required.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "snapshot.storage.k8s.io", version = "v1", kind = "VolumeSnapshot", plural = "volumesnapshots")]
#[kube(namespaced)]
#[kube(status = "VolumeSnapshotStatus")]
#[kube(schema = "disabled")]
#[kube(derive="Default")]
#[kube(derive="PartialEq")]
pub struct VolumeSnapshotSpec {
    /// source specifies where a snapshot will be created from.
    /// This field is immutable after creation.
    /// Required.
    pub source: VolumeSnapshotSource,
    /// VolumeSnapshotClassName is the name of the VolumeSnapshotClass
    /// requested by the VolumeSnapshot.
    /// VolumeSnapshotClassName may be left nil to indicate that the default
    /// SnapshotClass should be used.
    /// A given cluster may have multiple default Volume SnapshotClasses: one
    /// default per CSI Driver. If a VolumeSnapshot does not specify a SnapshotClass,
    /// VolumeSnapshotSource will be checked to figure out what the associated
    /// CSI Driver is, and the default VolumeSnapshotClass associated with that
    /// CSI Driver will be used. If more than one VolumeSnapshotClass exist for
    /// a given CSI Driver and more than one have been marked as default,
    /// CreateSnapshot will fail and generate an event.
    /// Empty string is not allowed for this field.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "volumeSnapshotClassName")]
    pub volume_snapshot_class_name: Option<String>,
}

/// source specifies where a snapshot will be created from.
/// This field is immutable after creation.
/// Required.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct VolumeSnapshotSource {
    /// persistentVolumeClaimName specifies the name of the PersistentVolumeClaim
    /// object representing the volume from which a snapshot should be created.
    /// This PVC is assumed to be in the same namespace as the VolumeSnapshot
    /// object.
    /// This field should be set if the snapshot does not exists, and needs to be
    /// created.
    /// This field is immutable.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "persistentVolumeClaimName")]
    pub persistent_volume_claim_name: Option<String>,
    /// volumeSnapshotContentName specifies the name of a pre-existing VolumeSnapshotContent
    /// object representing an existing volume snapshot.
    /// This field should be set if the snapshot already exists and only needs a representation in Kubernetes.
    /// This field is immutable.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "volumeSnapshotContentName")]
    pub volume_snapshot_content_name: Option<String>,
}

/// status represents the current information of a snapshot.
/// Consumers must verify binding between VolumeSnapshot and
/// VolumeSnapshotContent objects is successful (by validating that both
/// VolumeSnapshot and VolumeSnapshotContent point at each other) before
/// using this object.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct VolumeSnapshotStatus {
    /// boundVolumeSnapshotContentName is the name of the VolumeSnapshotContent
    /// object to which this VolumeSnapshot object intends to bind to.
    /// If not specified, it indicates that the VolumeSnapshot object has not been
    /// successfully bound to a VolumeSnapshotContent object yet.
    /// NOTE: To avoid possible security issues, consumers must verify binding between
    /// VolumeSnapshot and VolumeSnapshotContent objects is successful (by validating that
    /// both VolumeSnapshot and VolumeSnapshotContent point at each other) before using
    /// this object.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "boundVolumeSnapshotContentName")]
    pub bound_volume_snapshot_content_name: Option<String>,
    /// creationTime is the timestamp when the point-in-time snapshot is taken
    /// by the underlying storage system.
    /// In dynamic snapshot creation case, this field will be filled in by the
    /// snapshot controller with the "creation_time" value returned from CSI
    /// "CreateSnapshot" gRPC call.
    /// For a pre-existing snapshot, this field will be filled with the "creation_time"
    /// value returned from the CSI "ListSnapshots" gRPC call if the driver supports it.
    /// If not specified, it may indicate that the creation time of the snapshot is unknown.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "creationTime")]
    pub creation_time: Option<String>,
    /// error is the last observed error during snapshot creation, if any.
    /// This field could be helpful to upper level controllers(i.e., application controller)
    /// to decide whether they should continue on waiting for the snapshot to be created
    /// based on the type of error reported.
    /// The snapshot controller will keep retrying when an error occurs during the
    /// snapshot creation. Upon success, this error field will be cleared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<VolumeSnapshotStatusError>,
    /// readyToUse indicates if the snapshot is ready to be used to restore a volume.
    /// In dynamic snapshot creation case, this field will be filled in by the
    /// snapshot controller with the "ready_to_use" value returned from CSI
    /// "CreateSnapshot" gRPC call.
    /// For a pre-existing snapshot, this field will be filled with the "ready_to_use"
    /// value returned from the CSI "ListSnapshots" gRPC call if the driver supports it,
    /// otherwise, this field will be set to "True".
    /// If not specified, it means the readiness of a snapshot is unknown.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "readyToUse")]
    pub ready_to_use: Option<bool>,
    /// restoreSize represents the minimum size of volume required to create a volume
    /// from this snapshot.
    /// In dynamic snapshot creation case, this field will be filled in by the
    /// snapshot controller with the "size_bytes" value returned from CSI
    /// "CreateSnapshot" gRPC call.
    /// For a pre-existing snapshot, this field will be filled with the "size_bytes"
    /// value returned from the CSI "ListSnapshots" gRPC call if the driver supports it.
    /// When restoring a volume from this snapshot, the size of the volume MUST NOT
    /// be smaller than the restoreSize if it is specified, otherwise the restoration will fail.
    /// If not specified, it indicates that the size is unknown.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "restoreSize")]
    pub restore_size: Option<String>,
    /// VolumeGroupSnapshotName is the name of the VolumeGroupSnapshot of which this
    /// VolumeSnapshot is a part of.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "volumeGroupSnapshotName")]
    pub volume_group_snapshot_name: Option<String>,
}

/// error is the last observed error during snapshot creation, if any.
/// This field could be helpful to upper level controllers(i.e., application controller)
/// to decide whether they should continue on waiting for the snapshot to be created
/// based on the type of error reported.
/// The snapshot controller will keep retrying when an error occurs during the
/// snapshot creation. Upon success, this error field will be cleared.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct VolumeSnapshotStatusError {
    /// message is a string detailing the encountered error during snapshot
    /// creation if specified.
    /// NOTE: message may be logged, and it should not contain sensitive
    /// information.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// time is the timestamp when the error was encountered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
}

