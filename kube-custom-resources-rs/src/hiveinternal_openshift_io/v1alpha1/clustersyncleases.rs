// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/openshift/hive/hiveinternal.openshift.io/v1alpha1/clustersyncleases.yaml --derive=Default --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
}
use self::prelude::*;

/// ClusterSyncLeaseSpec is the specification of a ClusterSyncLease.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "hiveinternal.openshift.io", version = "v1alpha1", kind = "ClusterSyncLease", plural = "clustersyncleases")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
#[kube(derive="Default")]
#[kube(derive="PartialEq")]
pub struct ClusterSyncLeaseSpec {
    /// RenewTime is the time when SyncSets and SelectorSyncSets were last applied to the cluster.
    #[serde(rename = "renewTime")]
    pub renew_time: String,
}

