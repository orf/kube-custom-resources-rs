// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/openshift/api/security.openshift.io/v1/securitycontextconstraints.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// AllowedFlexVolume represents a single Flexvolume that is allowed to be used.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SecurityContextConstraintsAllowedFlexVolumes {
    /// Driver is the name of the Flexvolume driver.
    pub driver: String,
}

/// FSGroup is the strategy that will dictate what fs group is used by the SecurityContext.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SecurityContextConstraintsFsGroup {
    /// Ranges are the allowed ranges of fs groups.  If you would like to force a single fs group then supply a single range with the same start and end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ranges: Option<Vec<SecurityContextConstraintsFsGroupRanges>>,
    /// Type is the strategy that will dictate what FSGroup is used in the SecurityContext.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
}

/// IDRange provides a min/max of an allowed range of IDs. TODO: this could be reused for UIDs.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SecurityContextConstraintsFsGroupRanges {
    /// Max is the end of the range, inclusive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
    /// Min is the start of the range, inclusive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<i64>,
}

/// RunAsUser is the strategy that will dictate what RunAsUser is used in the SecurityContext.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SecurityContextConstraintsRunAsUser {
    /// Type is the strategy that will dictate what RunAsUser is used in the SecurityContext.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
    /// UID is the user id that containers must run as.  Required for the MustRunAs strategy if not using namespace/service account allocated uids.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<i64>,
    /// UIDRangeMax defines the max value for a strategy that allocates by range.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "uidRangeMax")]
    pub uid_range_max: Option<i64>,
    /// UIDRangeMin defines the min value for a strategy that allocates by range.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "uidRangeMin")]
    pub uid_range_min: Option<i64>,
}

/// SELinuxContext is the strategy that will dictate what labels will be set in the SecurityContext.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SecurityContextConstraintsSeLinuxContext {
    /// seLinuxOptions required to run as; required for MustRunAs
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "seLinuxOptions")]
    pub se_linux_options: Option<SecurityContextConstraintsSeLinuxContextSeLinuxOptions>,
    /// Type is the strategy that will dictate what SELinux context is used in the SecurityContext.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
}

/// seLinuxOptions required to run as; required for MustRunAs
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SecurityContextConstraintsSeLinuxContextSeLinuxOptions {
    /// Level is SELinux level label that applies to the container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    /// Role is a SELinux role label that applies to the container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Type is a SELinux type label that applies to the container.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
    /// User is a SELinux user label that applies to the container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

/// SupplementalGroups is the strategy that will dictate what supplemental groups are used by the SecurityContext.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SecurityContextConstraintsSupplementalGroups {
    /// Ranges are the allowed ranges of supplemental groups.  If you would like to force a single supplemental group then supply a single range with the same start and end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ranges: Option<Vec<SecurityContextConstraintsSupplementalGroupsRanges>>,
    /// Type is the strategy that will dictate what supplemental groups is used in the SecurityContext.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
}

/// IDRange provides a min/max of an allowed range of IDs. TODO: this could be reused for UIDs.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SecurityContextConstraintsSupplementalGroupsRanges {
    /// Max is the end of the range, inclusive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
    /// Min is the start of the range, inclusive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<i64>,
}

