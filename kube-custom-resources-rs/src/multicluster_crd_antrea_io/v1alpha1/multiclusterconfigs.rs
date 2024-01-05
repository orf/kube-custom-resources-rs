// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/antrea-io/antrea/multicluster.crd.antrea.io/v1alpha1/multiclusterconfigs.yaml --derive=Default --derive=PartialEq
// kopium version: 0.16.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// MultiClusterConfigSpec defines the desired state of MultiClusterConfig
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "multicluster.crd.antrea.io", version = "v1alpha1", kind = "MultiClusterConfig", plural = "multiclusterconfigs")]
#[kube(namespaced)]
#[kube(status = "MultiClusterConfigStatus")]
#[kube(schema = "disabled")]
pub struct MultiClusterConfigSpec {
    /// Foo is an example field of MultiClusterConfig. Edit multiclusterconfig_types.go to remove/update
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub foo: Option<String>,
}

/// MultiClusterConfigStatus defines the observed state of MultiClusterConfig
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MultiClusterConfigStatus {
}
