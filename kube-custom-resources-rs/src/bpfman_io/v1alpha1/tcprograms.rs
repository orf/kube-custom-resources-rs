// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/bpfman/bpfman/bpfman.io/v1alpha1/tcprograms.yaml --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use std::collections::BTreeMap;
    pub use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
}
use self::prelude::*;

/// TcProgramSpec defines the desired state of TcProgram
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "bpfman.io", version = "v1alpha1", kind = "TcProgram", plural = "tcprograms")]
#[kube(status = "TcProgramStatus")]
#[kube(schema = "disabled")]
#[kube(derive="PartialEq")]
pub struct TcProgramSpec {
    /// BpfFunctionName is the name of the function that is the entry point for the BPF program
    pub bpffunctionname: String,
    /// Bytecode configures where the bpf program's bytecode should be loaded from.
    pub bytecode: TcProgramBytecode,
    /// Direction specifies the direction of traffic the tc program should attach to for a given network device.
    pub direction: TcProgramDirection,
    /// GlobalData allows the user to to set global variables when the program is loaded with an array of raw bytes. This is a very low level primitive. The caller is responsible for formatting the byte string appropriately considering such things as size, endianness, alignment and packing of data structures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub globaldata: Option<BTreeMap<String, String>>,
    /// Selector to determine the network interface (or interfaces)
    pub interfaceselector: TcProgramInterfaceselector,
    /// MapOwnerSelector is used to select the loaded eBPF program this eBPF program will share a map with. The value is a label applied to the BpfProgram to select. The selector must resolve to exactly one instance of a BpfProgram on a given node or the eBPF program will not load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapownerselector: Option<TcProgramMapownerselector>,
    /// NodeSelector allows the user to specify which nodes to deploy the bpf program to.  This field must be specified, to select all nodes use standard metav1.LabelSelector semantics and make it empty.
    pub nodeselector: TcProgramNodeselector,
    /// Priority specifies the priority of the tc program in relation to other programs of the same type with the same attach point. It is a value from 0 to 1000 where lower values have higher precedence.
    pub priority: i32,
    /// ProceedOn allows the user to call other tc programs in chain on this exit code. Multiple values are supported by repeating the parameter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proceedon: Option<Vec<String>>,
}

/// Bytecode configures where the bpf program's bytecode should be loaded from.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TcProgramBytecode {
    /// Image used to specify a bytecode container image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<TcProgramBytecodeImage>,
    /// Path is used to specify a bytecode object via filepath.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// Image used to specify a bytecode container image.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TcProgramBytecodeImage {
    /// PullPolicy describes a policy for if/when to pull a bytecode image. Defaults to IfNotPresent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imagepullpolicy: Option<TcProgramBytecodeImageImagepullpolicy>,
    /// ImagePullSecret is the name of the secret bpfman should use to get remote image repository secrets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imagepullsecret: Option<TcProgramBytecodeImageImagepullsecret>,
    /// Valid container image URL used to reference a remote bytecode image.
    pub url: String,
}

/// Image used to specify a bytecode container image.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum TcProgramBytecodeImageImagepullpolicy {
    Always,
    Never,
    IfNotPresent,
}

/// ImagePullSecret is the name of the secret bpfman should use to get remote image repository secrets.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TcProgramBytecodeImageImagepullsecret {
    /// Name of the secret which contains the credentials to access the image repository.
    pub name: String,
    /// Namespace of the secret which contains the credentials to access the image repository.
    pub namespace: String,
}

/// TcProgramSpec defines the desired state of TcProgram
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum TcProgramDirection {
    #[serde(rename = "ingress")]
    Ingress,
    #[serde(rename = "egress")]
    Egress,
}

/// Selector to determine the network interface (or interfaces)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TcProgramInterfaceselector {
    /// Interfaces refers to a list of network interfaces to attach the BPF program to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interfaces: Option<Vec<String>>,
    /// Attach BPF program to the primary interface on the node. Only 'true' accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primarynodeinterface: Option<bool>,
}

/// MapOwnerSelector is used to select the loaded eBPF program this eBPF program will share a map with. The value is a label applied to the BpfProgram to select. The selector must resolve to exactly one instance of a BpfProgram on a given node or the eBPF program will not load.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TcProgramMapownerselector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<TcProgramMapownerselectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TcProgramMapownerselectorMatchExpressions {
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
pub struct TcProgramNodeselector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<TcProgramNodeselectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TcProgramNodeselectorMatchExpressions {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// TcProgramStatus defines the observed state of TcProgram
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TcProgramStatus {
    /// Conditions houses the global cluster state for the TcProgram. The explicit condition types are defined internally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
}

