// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/projectcalico/calico/crd.projectcalico.org/v1/blockaffinities.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// BlockAffinitySpec contains the specification for a BlockAffinity resource.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "crd.projectcalico.org", version = "v1", kind = "BlockAffinity", plural = "blockaffinities")]
#[kube(schema = "disabled")]
pub struct BlockAffinitySpec {
    pub cidr: String,
    /// Deleted indicates that this block affinity is being deleted. This field is a string for compatibility with older releases that mistakenly treat this field as a string.
    pub deleted: String,
    pub node: String,
    pub state: String,
}

