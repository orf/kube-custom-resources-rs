// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/rook/rook/objectbucket.io/v1alpha1/objectbuckets.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "objectbucket.io", version = "v1alpha1", kind = "ObjectBucket", plural = "objectbuckets")]
#[kube(schema = "disabled")]
pub struct ObjectBucketSpec {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "additionalState")]
    pub additional_state: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<ObjectBucketAuthentication>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "claimRef")]
    pub claim_ref: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<ObjectBucketEndpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "reclaimPolicy")]
    pub reclaim_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "storageClassName")]
    pub storage_class_name: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ObjectBucketAuthentication {
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ObjectBucketEndpoint {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "additionalConfig")]
    pub additional_config: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "bucketHost")]
    pub bucket_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "bucketName")]
    pub bucket_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "bucketPort")]
    pub bucket_port: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "subRegion")]
    pub sub_region: Option<String>,
}

