// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/projectcalico/calico/crd.projectcalico.org/v1/ipamblocks.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// IPAMBlockSpec contains the specification for an IPAMBlock resource.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "crd.projectcalico.org", version = "v1", kind = "IPAMBlock", plural = "ipamblocks")]
#[kube(schema = "disabled")]
pub struct IPAMBlockSpec {
    /// Affinity of the block, if this block has one. If set, it will be of the form "host:<hostname>". If not set, this block is not affine to a host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affinity: Option<String>,
    /// Array of allocations in-use within this block. nil entries mean the allocation is free. For non-nil entries at index i, the index is the ordinal of the allocation within this block and the value is the index of the associated attributes in the Attributes array.
    pub allocations: Vec<i64>,
    /// Attributes is an array of arbitrary metadata associated with allocations in the block. To find attributes for a given allocation, use the value of the allocation's entry in the Allocations array as the index of the element in this array.
    pub attributes: Vec<IPAMBlockAttributes>,
    /// The block's CIDR.
    pub cidr: String,
    /// Deleted is an internal boolean used to workaround a limitation in the Kubernetes API whereby deletion will not return a conflict error if the block has been updated. It should not be set manually.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted: Option<bool>,
    /// We store a sequence number that is updated each time the block is written. Each allocation will also store the sequence number of the block at the time of its creation. When releasing an IP, passing the sequence number associated with the allocation allows us to protect against a race condition and ensure the IP hasn't been released and re-allocated since the release request.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sequenceNumber")]
    pub sequence_number: Option<i64>,
    /// Map of allocated ordinal within the block to sequence number of the block at the time of allocation. Kubernetes does not allow numerical keys for maps, so the key is cast to a string.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sequenceNumberForAllocation")]
    pub sequence_number_for_allocation: Option<BTreeMap<String, i64>>,
    /// StrictAffinity on the IPAMBlock is deprecated and no longer used by the code. Use IPAMConfig StrictAffinity instead.
    #[serde(rename = "strictAffinity")]
    pub strict_affinity: bool,
    /// Unallocated is an ordered list of allocations which are free in the block.
    pub unallocated: Vec<i64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct IPAMBlockAttributes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary: Option<BTreeMap<String, String>>,
}

