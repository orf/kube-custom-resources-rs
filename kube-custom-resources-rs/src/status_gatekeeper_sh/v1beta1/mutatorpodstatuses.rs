// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/open-policy-agent/gatekeeper/status.gatekeeper.sh/v1beta1/mutatorpodstatuses.yaml --derive=Default --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
}
use self::prelude::*;

/// MutatorPodStatusStatus defines the observed state of MutatorPodStatus.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MutatorPodStatusStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<MutatorPodStatusStatusErrors>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Storing the mutator UID allows us to detect drift, such as
    /// when a mutator has been recreated after its CRD was deleted
    /// out from under it, interrupting the watch
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "mutatorUID")]
    pub mutator_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operations: Option<Vec<String>>,
}

/// MutatorError represents a single error caught while adding a mutator to a system.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MutatorPodStatusStatusErrors {
    pub message: String,
    /// Type indicates a specific class of error for use by controller code.
    /// If not present, the error should be treated as not matching any known type.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
}

