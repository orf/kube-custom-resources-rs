// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/tigera/operator/operator.tigera.io/v1/tigerastatuses.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// TigeraStatusSpec defines the desired state of TigeraStatus
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "operator.tigera.io", version = "v1", kind = "TigeraStatus", plural = "tigerastatuses")]
#[kube(status = "TigeraStatusStatus")]
#[kube(schema = "disabled")]
pub struct TigeraStatusSpec {
}

/// TigeraStatusStatus defines the observed state of TigeraStatus
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TigeraStatusStatus {
    /// Conditions represents the latest observed set of conditions for this component. A component may be one or more of Available, Progressing, or Degraded.
    pub conditions: Vec<Condition>,
}

