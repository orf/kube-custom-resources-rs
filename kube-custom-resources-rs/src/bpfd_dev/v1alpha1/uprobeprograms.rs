// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/bpfd-dev/bpfd/bpfd.dev/v1alpha1/uprobeprograms.yaml --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// UprobeProgramSpec defines the desired state of UprobeProgram
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "bpfd.dev", version = "v1alpha1", kind = "UprobeProgram", plural = "uprobeprograms")]
#[kube(status = "UprobeProgramStatus")]
#[kube(schema = "disabled")]
pub struct UprobeProgramSpec {
    /// BpfFunctionName is the name of the function that is the entry point for the BPF program
    pub bpffunctionname: String,
    /// Bytecode configures where the bpf program's bytecode should be loaded from.
    pub bytecode: UprobeProgramBytecode,
    /// Function to attach the uprobe to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub func_name: Option<String>,
    /// GlobalData allows the user to to set global variables when the program is loaded with an array of raw bytes. This is a very low level primitive. The caller is responsible for formatting the byte string appropriately considering such things as size, endianness, alignment and packing of data structures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub globaldata: Option<BTreeMap<String, String>>,
    /// MapOwnerSelector is used to select the loaded eBPF program this eBPF program will share a map with. The value is a label applied to the BpfProgram to select. The selector must resolve to exactly one instance of a BpfProgram on a given node or the eBPF program will not load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapownerselector: Option<UprobeProgramMapownerselector>,
    /// NodeSelector allows the user to specify which nodes to deploy the bpf program to.  This field must be specified, to select all nodes use standard metav1.LabelSelector semantics and make it empty.
    pub nodeselector: UprobeProgramNodeselector,
    /// Offset added to the address of the function for uprobe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    /// Only execute uprobe for given process identification number (PID). If PID is not provided, uprobe executes for all PIDs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<i32>,
    /// Whether the program is a uretprobe.  Default is false
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retprobe: Option<bool>,
    /// Library name or the absolute path to a binary or library.
    pub target: Vec<String>,
}

/// Bytecode configures where the bpf program's bytecode should be loaded from.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct UprobeProgramBytecode {
    /// Image used to specify a bytecode container image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<UprobeProgramBytecodeImage>,
    /// Path is used to specify a bytecode object via filepath.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// Image used to specify a bytecode container image.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct UprobeProgramBytecodeImage {
    /// PullPolicy describes a policy for if/when to pull a bytecode image. Defaults to IfNotPresent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imagepullpolicy: Option<UprobeProgramBytecodeImageImagepullpolicy>,
    /// ImagePullSecret is the name of the secret bpfd should use to get remote image repository secrets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imagepullsecret: Option<UprobeProgramBytecodeImageImagepullsecret>,
    /// Valid container image URL used to reference a remote bytecode image.
    pub url: String,
}

/// Image used to specify a bytecode container image.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum UprobeProgramBytecodeImageImagepullpolicy {
    Always,
    Never,
    IfNotPresent,
}

/// ImagePullSecret is the name of the secret bpfd should use to get remote image repository secrets.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct UprobeProgramBytecodeImageImagepullsecret {
    /// Name of the secret which contains the credentials to access the image repository.
    pub name: String,
    /// Namespace of the secret which contains the credentials to access the image repository.
    pub namespace: String,
}

/// MapOwnerSelector is used to select the loaded eBPF program this eBPF program will share a map with. The value is a label applied to the BpfProgram to select. The selector must resolve to exactly one instance of a BpfProgram on a given node or the eBPF program will not load.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct UprobeProgramMapownerselector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<UprobeProgramMapownerselectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct UprobeProgramMapownerselectorMatchExpressions {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// NodeSelector allows the user to specify which nodes to deploy the bpf program to.  This field must be specified, to select all nodes use standard metav1.LabelSelector semantics and make it empty.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct UprobeProgramNodeselector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<UprobeProgramNodeselectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct UprobeProgramNodeselectorMatchExpressions {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// UprobeProgramStatus defines the observed state of UprobeProgram
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct UprobeProgramStatus {
    /// Conditions houses the global cluster state for the UprobeProgram. The explicit condition types are defined internally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
}

