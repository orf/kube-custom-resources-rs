// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/bpfd-dev/bpfd/bpfd.dev/v1alpha1/bpfprograms.yaml --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// BpfProgramSpec defines the desired state of BpfProgram
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "bpfd.dev", version = "v1alpha1", kind = "BpfProgram", plural = "bpfprograms")]
#[kube(status = "BpfProgramStatus")]
#[kube(schema = "disabled")]
pub struct BpfProgramSpec {
    /// Type specifies the bpf program type
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
}

/// BpfProgramStatus defines the observed state of BpfProgram TODO Make these a fixed set of metav1.Condition.types and metav1.Condition.reasons
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BpfProgramStatus {
    /// Conditions houses the updates regarding the actual implementation of the bpf program on the node Known .status.conditions.type are: "Available", "Progressing", and "Degraded"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
}

