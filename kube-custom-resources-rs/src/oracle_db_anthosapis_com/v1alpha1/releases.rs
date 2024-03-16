// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/GoogleCloudPlatform/elcarro-oracle-operator/oracle.db.anthosapis.com/v1alpha1/releases.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// ReleaseSpec defines the desired state of Release.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "oracle.db.anthosapis.com", version = "v1alpha1", kind = "Release", plural = "releases")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct ReleaseSpec {
    pub version: String,
}

/// ReleaseStatus defines the observed state of Release.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ReleaseStatus {
}

