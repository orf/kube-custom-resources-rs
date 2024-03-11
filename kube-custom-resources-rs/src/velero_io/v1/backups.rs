// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/vmware-tanzu/velero/velero.io/v1/backups.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// BackupSpec defines the specification for a Velero backup.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "velero.io", version = "v1", kind = "Backup", plural = "backups")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct BackupSpec {
    /// CSISnapshotTimeout specifies the time used to wait for CSI VolumeSnapshot status turns to ReadyToUse during creation, before returning error as timeout. The default value is 10 minute.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "csiSnapshotTimeout")]
    pub csi_snapshot_timeout: Option<String>,
    /// DataMover specifies the data mover to be used by the backup. If DataMover is "" or "velero", the built-in data mover will be used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub datamover: Option<String>,
    /// DefaultVolumesToFsBackup specifies whether pod volume file system backup should be used for all volumes by default.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "defaultVolumesToFsBackup")]
    pub default_volumes_to_fs_backup: Option<bool>,
    /// DefaultVolumesToRestic specifies whether restic should be used to take a backup of all pod volumes by default. 
    ///  Deprecated: this field is no longer used and will be removed entirely in future. Use DefaultVolumesToFsBackup instead.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "defaultVolumesToRestic")]
    pub default_volumes_to_restic: Option<bool>,
    /// ExcludedClusterScopedResources is a slice of cluster-scoped resource type names to exclude from the backup. If set to "*", all cluster-scoped resource types are excluded. The default value is empty.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "excludedClusterScopedResources")]
    pub excluded_cluster_scoped_resources: Option<Vec<String>>,
    /// ExcludedNamespaceScopedResources is a slice of namespace-scoped resource type names to exclude from the backup. If set to "*", all namespace-scoped resource types are excluded. The default value is empty.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "excludedNamespaceScopedResources")]
    pub excluded_namespace_scoped_resources: Option<Vec<String>>,
    /// ExcludedNamespaces contains a list of namespaces that are not included in the backup.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "excludedNamespaces")]
    pub excluded_namespaces: Option<Vec<String>>,
    /// ExcludedResources is a slice of resource names that are not included in the backup.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "excludedResources")]
    pub excluded_resources: Option<Vec<String>>,
    /// Hooks represent custom behaviors that should be executed at different phases of the backup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hooks: Option<BackupHooks>,
    /// IncludeClusterResources specifies whether cluster-scoped resources should be included for consideration in the backup.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "includeClusterResources")]
    pub include_cluster_resources: Option<bool>,
    /// IncludedClusterScopedResources is a slice of cluster-scoped resource type names to include in the backup. If set to "*", all cluster-scoped resource types are included. The default value is empty, which means only related cluster-scoped resources are included.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "includedClusterScopedResources")]
    pub included_cluster_scoped_resources: Option<Vec<String>>,
    /// IncludedNamespaceScopedResources is a slice of namespace-scoped resource type names to include in the backup. The default value is "*".
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "includedNamespaceScopedResources")]
    pub included_namespace_scoped_resources: Option<Vec<String>>,
    /// IncludedNamespaces is a slice of namespace names to include objects from. If empty, all namespaces are included.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "includedNamespaces")]
    pub included_namespaces: Option<Vec<String>>,
    /// IncludedResources is a slice of resource names to include in the backup. If empty, all resources are included.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "includedResources")]
    pub included_resources: Option<Vec<String>>,
    /// ItemOperationTimeout specifies the time used to wait for asynchronous BackupItemAction operations The default value is 4 hour.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "itemOperationTimeout")]
    pub item_operation_timeout: Option<String>,
    /// LabelSelector is a metav1.LabelSelector to filter with when adding individual objects to the backup. If empty or nil, all objects are included. Optional.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "labelSelector")]
    pub label_selector: Option<BackupLabelSelector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BackupMetadata>,
    /// OrLabelSelectors is list of metav1.LabelSelector to filter with when adding individual objects to the backup. If multiple provided they will be joined by the OR operator. LabelSelector as well as OrLabelSelectors cannot co-exist in backup request, only one of them can be used.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "orLabelSelectors")]
    pub or_label_selectors: Option<Vec<BackupOrLabelSelectors>>,
    /// OrderedResources specifies the backup order of resources of specific Kind. The map key is the resource name and value is a list of object names separated by commas. Each resource name has format "namespace/objectname".  For cluster resources, simply use "objectname".
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "orderedResources")]
    pub ordered_resources: Option<BTreeMap<String, String>>,
    /// ResourcePolicy specifies the referenced resource policies that backup should follow
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "resourcePolicy")]
    pub resource_policy: Option<BackupResourcePolicy>,
    /// SnapshotMoveData specifies whether snapshot data should be moved
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "snapshotMoveData")]
    pub snapshot_move_data: Option<bool>,
    /// SnapshotVolumes specifies whether to take snapshots of any PV's referenced in the set of objects included in the Backup.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "snapshotVolumes")]
    pub snapshot_volumes: Option<bool>,
    /// StorageLocation is a string containing the name of a BackupStorageLocation where the backup should be stored.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "storageLocation")]
    pub storage_location: Option<String>,
    /// TTL is a time.Duration-parseable string describing how long the Backup should be retained for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    /// UploaderConfig specifies the configuration for the uploader.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "uploaderConfig")]
    pub uploader_config: Option<BackupUploaderConfig>,
    /// VolumeSnapshotLocations is a list containing names of VolumeSnapshotLocations associated with this backup.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "volumeSnapshotLocations")]
    pub volume_snapshot_locations: Option<Vec<String>>,
}

/// Hooks represent custom behaviors that should be executed at different phases of the backup.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackupHooks {
    /// Resources are hooks that should be executed when backing up individual instances of a resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<BackupHooksResources>>,
}

/// BackupResourceHookSpec defines one or more BackupResourceHooks that should be executed based on the rules defined for namespaces, resources, and label selector.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackupHooksResources {
    /// ExcludedNamespaces specifies the namespaces to which this hook spec does not apply.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "excludedNamespaces")]
    pub excluded_namespaces: Option<Vec<String>>,
    /// ExcludedResources specifies the resources to which this hook spec does not apply.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "excludedResources")]
    pub excluded_resources: Option<Vec<String>>,
    /// IncludedNamespaces specifies the namespaces to which this hook spec applies. If empty, it applies to all namespaces.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "includedNamespaces")]
    pub included_namespaces: Option<Vec<String>>,
    /// IncludedResources specifies the resources to which this hook spec applies. If empty, it applies to all resources.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "includedResources")]
    pub included_resources: Option<Vec<String>>,
    /// LabelSelector, if specified, filters the resources to which this hook spec applies.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "labelSelector")]
    pub label_selector: Option<BackupHooksResourcesLabelSelector>,
    /// Name is the name of this hook.
    pub name: String,
    /// PostHooks is a list of BackupResourceHooks to execute after storing the item in the backup. These are executed after all "additional items" from item actions are processed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post: Option<Vec<BackupHooksResourcesPost>>,
    /// PreHooks is a list of BackupResourceHooks to execute prior to storing the item in the backup. These are executed before any "additional items" from item actions are processed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre: Option<Vec<BackupHooksResourcesPre>>,
}

/// LabelSelector, if specified, filters the resources to which this hook spec applies.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackupHooksResourcesLabelSelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<BackupHooksResourcesLabelSelectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackupHooksResourcesLabelSelectorMatchExpressions {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// BackupResourceHook defines a hook for a resource.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackupHooksResourcesPost {
    /// Exec defines an exec hook.
    pub exec: BackupHooksResourcesPostExec,
}

/// Exec defines an exec hook.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackupHooksResourcesPostExec {
    /// Command is the command and arguments to execute.
    pub command: Vec<String>,
    /// Container is the container in the pod where the command should be executed. If not specified, the pod's first container is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// OnError specifies how Velero should behave if it encounters an error executing this hook.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "onError")]
    pub on_error: Option<BackupHooksResourcesPostExecOnError>,
    /// Timeout defines the maximum amount of time Velero should wait for the hook to complete before considering the execution a failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
}

/// Exec defines an exec hook.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum BackupHooksResourcesPostExecOnError {
    Continue,
    Fail,
}

/// BackupResourceHook defines a hook for a resource.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackupHooksResourcesPre {
    /// Exec defines an exec hook.
    pub exec: BackupHooksResourcesPreExec,
}

/// Exec defines an exec hook.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackupHooksResourcesPreExec {
    /// Command is the command and arguments to execute.
    pub command: Vec<String>,
    /// Container is the container in the pod where the command should be executed. If not specified, the pod's first container is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// OnError specifies how Velero should behave if it encounters an error executing this hook.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "onError")]
    pub on_error: Option<BackupHooksResourcesPreExecOnError>,
    /// Timeout defines the maximum amount of time Velero should wait for the hook to complete before considering the execution a failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
}

/// Exec defines an exec hook.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum BackupHooksResourcesPreExecOnError {
    Continue,
    Fail,
}

/// LabelSelector is a metav1.LabelSelector to filter with when adding individual objects to the backup. If empty or nil, all objects are included. Optional.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackupLabelSelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<BackupLabelSelectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackupLabelSelectorMatchExpressions {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackupMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
}

/// A label selector is a label query over a set of resources. The result of matchLabels and matchExpressions are ANDed. An empty label selector matches all objects. A null label selector matches no objects.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackupOrLabelSelectors {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<BackupOrLabelSelectorsMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackupOrLabelSelectorsMatchExpressions {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// ResourcePolicy specifies the referenced resource policies that backup should follow
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackupResourcePolicy {
    /// APIGroup is the group for the resource being referenced. If APIGroup is not specified, the specified Kind must be in the core API group. For any other third-party types, APIGroup is required.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiGroup")]
    pub api_group: Option<String>,
    /// Kind is the type of resource being referenced
    pub kind: String,
    /// Name is the name of resource being referenced
    pub name: String,
}

/// UploaderConfig specifies the configuration for the uploader.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackupUploaderConfig {
    /// ParallelFilesUpload is the number of files parallel uploads to perform when using the uploader.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "parallelFilesUpload")]
    pub parallel_files_upload: Option<i64>,
}

/// BackupStatus captures the current status of a Velero backup.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackupStatus {
    /// BackupItemOperationsAttempted is the total number of attempted async BackupItemAction operations for this backup.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "backupItemOperationsAttempted")]
    pub backup_item_operations_attempted: Option<i64>,
    /// BackupItemOperationsCompleted is the total number of successfully completed async BackupItemAction operations for this backup.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "backupItemOperationsCompleted")]
    pub backup_item_operations_completed: Option<i64>,
    /// BackupItemOperationsFailed is the total number of async BackupItemAction operations for this backup which ended with an error.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "backupItemOperationsFailed")]
    pub backup_item_operations_failed: Option<i64>,
    /// CompletionTimestamp records the time a backup was completed. Completion time is recorded even on failed backups. Completion time is recorded before uploading the backup object. The server's time is used for CompletionTimestamps
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "completionTimestamp")]
    pub completion_timestamp: Option<String>,
    /// CSIVolumeSnapshotsAttempted is the total number of attempted CSI VolumeSnapshots for this backup.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "csiVolumeSnapshotsAttempted")]
    pub csi_volume_snapshots_attempted: Option<i64>,
    /// CSIVolumeSnapshotsCompleted is the total number of successfully completed CSI VolumeSnapshots for this backup.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "csiVolumeSnapshotsCompleted")]
    pub csi_volume_snapshots_completed: Option<i64>,
    /// Errors is a count of all error messages that were generated during execution of the backup.  The actual errors are in the backup's log file in object storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<i64>,
    /// Expiration is when this Backup is eligible for garbage-collection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration: Option<String>,
    /// FailureReason is an error that caused the entire backup to fail.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "failureReason")]
    pub failure_reason: Option<String>,
    /// FormatVersion is the backup format version, including major, minor, and patch version.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "formatVersion")]
    pub format_version: Option<String>,
    /// HookStatus contains information about the status of the hooks.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "hookStatus")]
    pub hook_status: Option<BackupStatusHookStatus>,
    /// Phase is the current state of the Backup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<BackupStatusPhase>,
    /// Progress contains information about the backup's execution progress. Note that this information is best-effort only -- if Velero fails to update it during a backup for any reason, it may be inaccurate/stale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<BackupStatusProgress>,
    /// StartTimestamp records the time a backup was started. Separate from CreationTimestamp, since that value changes on restores. The server's time is used for StartTimestamps
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "startTimestamp")]
    pub start_timestamp: Option<String>,
    /// ValidationErrors is a slice of all validation errors (if applicable).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "validationErrors")]
    pub validation_errors: Option<Vec<String>>,
    /// Version is the backup format major version. Deprecated: Please see FormatVersion
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
    /// VolumeSnapshotsAttempted is the total number of attempted volume snapshots for this backup.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "volumeSnapshotsAttempted")]
    pub volume_snapshots_attempted: Option<i64>,
    /// VolumeSnapshotsCompleted is the total number of successfully completed volume snapshots for this backup.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "volumeSnapshotsCompleted")]
    pub volume_snapshots_completed: Option<i64>,
    /// Warnings is a count of all warning messages that were generated during execution of the backup. The actual warnings are in the backup's log file in object storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warnings: Option<i64>,
}

/// HookStatus contains information about the status of the hooks.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackupStatusHookStatus {
    /// HooksAttempted is the total number of attempted hooks Specifically, HooksAttempted represents the number of hooks that failed to execute and the number of hooks that executed successfully.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "hooksAttempted")]
    pub hooks_attempted: Option<i64>,
    /// HooksFailed is the total number of hooks which ended with an error
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "hooksFailed")]
    pub hooks_failed: Option<i64>,
}

/// BackupStatus captures the current status of a Velero backup.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum BackupStatusPhase {
    New,
    FailedValidation,
    InProgress,
    WaitingForPluginOperations,
    WaitingForPluginOperationsPartiallyFailed,
    Finalizing,
    FinalizingPartiallyFailed,
    Completed,
    PartiallyFailed,
    Failed,
    Deleting,
}

/// Progress contains information about the backup's execution progress. Note that this information is best-effort only -- if Velero fails to update it during a backup for any reason, it may be inaccurate/stale.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BackupStatusProgress {
    /// ItemsBackedUp is the number of items that have actually been written to the backup tarball so far.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "itemsBackedUp")]
    pub items_backed_up: Option<i64>,
    /// TotalItems is the total number of items to be backed up. This number may change throughout the execution of the backup due to plugins that return additional related items to back up, the velero.io/exclude-from-backup label, and various other filters that happen as items are processed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "totalItems")]
    pub total_items: Option<i64>,
}

