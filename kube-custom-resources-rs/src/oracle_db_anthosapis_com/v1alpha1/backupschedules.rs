// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/GoogleCloudPlatform/elcarro-oracle-operator/oracle.db.anthosapis.com/v1alpha1/backupschedules.yaml --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "oracle.db.anthosapis.com", version = "v1alpha1", kind = "BackupSchedule", plural = "backupschedules")]
#[kube(namespaced)]
#[kube(status = "BackupScheduleStatus")]
#[kube(schema = "disabled")]
pub struct BackupScheduleSpec {
    /// BackupLabels define the desired labels that scheduled backups will be created with.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "backupLabels")]
    pub backup_labels: Option<BTreeMap<String, String>>,
    /// BackupRetentionPolicy is the policy used to trigger automatic deletion of backups produced from this BackupSchedule.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "backupRetentionPolicy")]
    pub backup_retention_policy: Option<BackupScheduleBackupRetentionPolicy>,
    /// BackupSpec defines the Backup that will be created on the provided schedule.
    #[serde(rename = "backupSpec")]
    pub backup_spec: BackupScheduleBackupSpec,
    /// Schedule is a cron-style expression of the schedule on which Backup will be created. For allowed syntax, see en.wikipedia.org/wiki/Cron and godoc.org/github.com/robfig/cron.
    pub schedule: String,
    /// StartingDeadlineSeconds is an optional deadline in seconds for starting the backup creation if it misses scheduled time for any reason. The default is 30 seconds.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "startingDeadlineSeconds")]
    pub starting_deadline_seconds: Option<i64>,
    /// Suspend tells the controller to suspend operations - both creation of new Backup and retention actions. This will not have any effect on backups currently in progress. Default is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspend: Option<bool>,
}

/// BackupRetentionPolicy is the policy used to trigger automatic deletion of backups produced from this BackupSchedule.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BackupScheduleBackupRetentionPolicy {
    /// BackupRetention is the number of successful backups to keep around. The default is 7. A value of 0 means "do not delete backups based on count". Max of 512 allows for ~21 days of hourly backups or ~1.4 years of daily backups.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "backupRetention")]
    pub backup_retention: Option<i32>,
}

/// BackupSpec defines the Backup that will be created on the provided schedule.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BackupScheduleBackupSpec {
    /// For a Physical backup this slice can be used to indicate what PDBs, schemas, tablespaces or tables to back up.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "backupItems")]
    pub backup_items: Option<Vec<String>>,
    /// For a Physical backup the choices are Backupset and Image Copies. Backupset is the default, but if Image Copies are required, flip this flag to false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backupset: Option<bool>,
    /// For a Physical backup, optionally turn on an additional "check logical" option. The default is off.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "checkLogical")]
    pub check_logical: Option<bool>,
    /// For a Physical backup, optionally turn on compression, by flipping this flag to true. The default is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compressed: Option<bool>,
    /// For a Physical backup, optionally indicate a degree of parallelism also known as DOP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dop: Option<i32>,
    /// For a Physical backup, optionally specify filesperset. The default depends on a type of backup, generally 64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesperset: Option<i32>,
    /// Similar to GcsPath but specify a Gcs directory. The backup sets of physical backup will be transferred to this GcsDir under a folder named .backup.Spec.Name. This field is usually set in .backupSchedule.Spec.backSpec to specify a GcsDir which all scheduled backups will be uploaded to. A user is to ensure proper write access to the bucket from within the Oracle Operator.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "gcsDir")]
    pub gcs_dir: Option<String>,
    /// If set up ahead of time, the backup sets of a physical backup can be optionally transferred to a GCS bucket. A user is to ensure proper write access to the bucket from within the Oracle Operator.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "gcsPath")]
    pub gcs_path: Option<String>,
    /// Instance is a name of an instance to take a backup for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// KeepDataOnDeletion defines whether to keep backup data when backup resource is removed. The default value is false.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "keepDataOnDeletion")]
    pub keep_data_on_deletion: Option<bool>,
    /// For a Physical backup, optionally specify an incremental level. The default is 0 (the whole database).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<i32>,
    /// For a Physical backup, optionally specify a local backup dir. If omitted, /u03/app/oracle/rman is assumed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "localPath")]
    pub local_path: Option<String>,
    /// Mode specifies how this backup will be managed by the operator. if it is not set, the operator tries to create a backup based on the specifications. if it is set to VerifyExists, the operator verifies the existence of a backup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<BackupScheduleBackupSpecMode>,
    /// For a Physical backup, optionally specify a section size in various units (K M G).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sectionSize")]
    pub section_size: Option<IntOrString>,
    /// Backup sub-type, which is only relevant for a Physical backup type (e.g. RMAN). If omitted, the default of Instance(Level) is assumed. Supported options at this point are: Instance or Database level backups.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "subType")]
    pub sub_type: Option<BackupScheduleBackupSpecSubType>,
    /// For a Physical backup, optionally specify the time threshold. If a threshold is reached, the backup request would time out and error out. The threshold is expressed in minutes. Don't include the unit (minutes), just the integer.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "timeLimitMinutes")]
    pub time_limit_minutes: Option<i32>,
    /// Type describes a type of a backup to take. Immutable. Available options are: - Snapshot: storage level disk snapshot. - Physical: database engine specific backup that relies on a redo stream / continuous archiving (WAL) and may allow a PITR. Examples include pg_backup, pgBackRest, mysqlbackup. A Physical backup may be file based or database block based (e.g. Oracle RMAN). - Logical: database engine specific backup that relies on running SQL statements, e.g. mysqldump, pg_dump, expdp. If not specified, the default of Snapshot is assumed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<BackupScheduleBackupSpecType>,
    /// VolumeSnapshotClass points to a particular CSI driver and is used for taking a volume snapshot. If requested here at the Backup level, this setting overrides the platform default as well as the default set via the Config (global user preferences).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "volumeSnapshotClass")]
    pub volume_snapshot_class: Option<String>,
}

/// BackupSpec defines the Backup that will be created on the provided schedule.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum BackupScheduleBackupSpecMode {
    VerifyExists,
}

/// BackupSpec defines the Backup that will be created on the provided schedule.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum BackupScheduleBackupSpecSubType {
    Instance,
    Database,
    Tablespace,
    Datafile,
}

/// BackupSpec defines the Backup that will be created on the provided schedule.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum BackupScheduleBackupSpecType {
    Snapshot,
    Physical,
    Logical,
}

/// BackupScheduleStatus defines the observed state of BackupSchedule.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BackupScheduleStatus {
    /// BackupHistory stores the records for up to 7 of the latest backups.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "backupHistory")]
    pub backup_history: Option<Vec<BackupScheduleStatusBackupHistory>>,
    /// BackupTotal stores the total number of current existing backups created by this backupSchedule.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "backupTotal")]
    pub backup_total: Option<i32>,
    /// Conditions of the BackupSchedule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// LastBackupTime is the time the last Backup was created for this BackupSchedule.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastBackupTime")]
    pub last_backup_time: Option<String>,
}

/// BackupHistoryRecord is a historical record of a Backup.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BackupScheduleStatusBackupHistory {
    /// BackupName is the name of the Backup that gets created.
    #[serde(rename = "backupName")]
    pub backup_name: String,
    /// CreationTime is the time that the Backup gets created.
    #[serde(rename = "creationTime")]
    pub creation_time: String,
    /// Phase tells the state of the Backup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
}

