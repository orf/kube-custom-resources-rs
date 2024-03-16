// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws/eks-anywhere/anywhere.eks.amazonaws.com/v1alpha1/vspheredatacenterconfigs.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// VSphereDatacenterConfigSpec defines the desired state of VSphereDatacenterConfig.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "anywhere.eks.amazonaws.com", version = "v1alpha1", kind = "VSphereDatacenterConfig", plural = "vspheredatacenterconfigs")]
#[kube(namespaced)]
#[kube(status = "VSphereDatacenterConfigStatus")]
#[kube(schema = "disabled")]
pub struct VSphereDatacenterConfigSpec {
    pub datacenter: String,
    pub insecure: bool,
    pub network: String,
    pub server: String,
    pub thumbprint: String,
}

/// VSphereDatacenterConfigStatus defines the observed state of VSphereDatacenterConfig.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct VSphereDatacenterConfigStatus {
    /// FailureMessage indicates that there is a fatal problem reconciling the state, and will be set to a descriptive error message.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "failureMessage")]
    pub failure_message: Option<String>,
    /// ObservedGeneration is the latest generation observed by the controller.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
    /// SpecValid is set to true if vspheredatacenterconfig is validated.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "specValid")]
    pub spec_valid: Option<bool>,
}

