// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/snapp-incubator/ceph-s3-operator/s3.snappcloud.io/v1alpha1/s3userclaims.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

/// S3UserClaimSpec defines the desired state of S3UserClaim
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "s3.snappcloud.io", version = "v1alpha1", kind = "S3UserClaim", plural = "s3userclaims")]
#[kube(namespaced)]
#[kube(status = "S3UserClaimStatus")]
#[kube(schema = "disabled")]
pub struct S3UserClaimSpec {
    #[serde(rename = "adminSecret")]
    pub admin_secret: String,
    /// UserQuota specifies the quota for a user in Ceph
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<S3UserClaimQuota>,
    #[serde(rename = "readonlySecret")]
    pub readonly_secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "s3UserClass")]
    pub s3_user_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subusers: Option<Vec<String>>,
}

/// UserQuota specifies the quota for a user in Ceph
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct S3UserClaimQuota {
    /// max number of buckets the user can create
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxBuckets")]
    pub max_buckets: Option<i64>,
    /// max number of objects the user can store
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxObjects")]
    pub max_objects: Option<IntOrString>,
    /// max number of bytes the user can store
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxSize")]
    pub max_size: Option<IntOrString>,
}

/// S3UserClaimStatus defines the observed state of S3UserClaim
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct S3UserClaimStatus {
    /// UserQuota specifies the quota for a user in Ceph
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<S3UserClaimStatusQuota>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "s3UserName")]
    pub s3_user_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subusers: Option<Vec<String>>,
}

/// UserQuota specifies the quota for a user in Ceph
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct S3UserClaimStatusQuota {
    /// max number of buckets the user can create
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxBuckets")]
    pub max_buckets: Option<i64>,
    /// max number of objects the user can store
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxObjects")]
    pub max_objects: Option<IntOrString>,
    /// max number of bytes the user can store
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxSize")]
    pub max_size: Option<IntOrString>,
}

