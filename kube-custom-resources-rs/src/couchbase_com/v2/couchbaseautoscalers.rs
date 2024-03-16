// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/couchbase-partners/helm-charts/couchbase.com/v2/couchbaseautoscalers.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// CouchbaseAutoscalerSpec allows control over an autoscaling group.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "couchbase.com", version = "v2", kind = "CouchbaseAutoscaler", plural = "couchbaseautoscalers")]
#[kube(namespaced)]
#[kube(status = "CouchbaseAutoscalerStatus")]
#[kube(schema = "disabled")]
pub struct CouchbaseAutoscalerSpec {
    /// Servers specifies the server group that this autoscaler belongs to.
    pub servers: String,
    /// Size allows the server group to be dynamically scaled.
    pub size: i64,
}

/// CouchbaseAutoscalerStatus provides information to the HPA to assist with scaling server groups.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CouchbaseAutoscalerStatus {
    /// LabelSelector allows the HPA to select resources to monitor for resource utilization in order to trigger scaling.
    #[serde(rename = "labelSelector")]
    pub label_selector: String,
    /// Size is the current size of the server group.
    pub size: i64,
}

