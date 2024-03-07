// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --derive=Default --derive=PartialEq --derive=Copy --filename=./crd-catalog/tigera/operator/operator.tigera.io/v1/tigerastatuses.yaml
// kopium version: 0.16.5

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// TigeraStatusSpec defines the desired state of TigeraStatus
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq, Copy)]
#[kube(group = "operator.tigera.io", version = "v1", kind = "TigeraStatus", plural = "tigerastatuses")]
#[kube(status = "TigeraStatusStatus")]
#[kube(schema = "disabled")]
pub struct TigeraStatusSpec {
}

/// TigeraStatusStatus defines the observed state of TigeraStatus
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Copy)]
pub struct TigeraStatusStatus {
    /// Conditions represents the latest observed set of conditions for this component. A component may be one or more of Available, Progressing, or Degraded.
    pub conditions: Vec<TigeraStatusStatusConditions>,
}

/// TigeraStatusCondition represents a condition attached to a particular component.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Copy)]
pub struct TigeraStatusStatusConditions {
    /// The timestamp representing the start time for the current status.
    #[serde(rename = "lastTransitionTime")]
    pub last_transition_time: String,
    /// Optionally, a detailed message providing additional context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// observedGeneration represents the generation that the condition was set based upon. For instance, if generation is currently 12, but the .status.conditions[x].observedGeneration is 9, the condition is out of date with respect to the current state of the instance.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
    /// A brief reason explaining the condition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The status of the condition. May be True, False, or Unknown.
    pub status: String,
    /// The type of condition. May be Available, Progressing, or Degraded.
    #[serde(rename = "type")]
    pub r#type: String,
}

