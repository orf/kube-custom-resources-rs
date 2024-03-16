// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/projectcalico/calico/crd.projectcalico.org/v1/ipamconfigs.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// IPAMConfigSpec contains the specification for an IPAMConfig resource.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "crd.projectcalico.org", version = "v1", kind = "IPAMConfig", plural = "ipamconfigs")]
#[kube(schema = "disabled")]
pub struct IPAMConfigSpec {
    #[serde(rename = "autoAllocateBlocks")]
    pub auto_allocate_blocks: bool,
    /// MaxBlocksPerHost, if non-zero, is the max number of blocks that can be affine to each host.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxBlocksPerHost")]
    pub max_blocks_per_host: Option<i64>,
    #[serde(rename = "strictAffinity")]
    pub strict_affinity: bool,
}

