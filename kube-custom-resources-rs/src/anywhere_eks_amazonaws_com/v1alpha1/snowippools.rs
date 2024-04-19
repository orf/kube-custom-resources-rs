// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws/eks-anywhere/anywhere.eks.amazonaws.com/v1alpha1/snowippools.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// SnowIPPoolSpec defines the desired state of SnowIPPool.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "anywhere.eks.amazonaws.com", version = "v1alpha1", kind = "SnowIPPool", plural = "snowippools")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct SnowIPPoolSpec {
    /// IPPools defines a list of ip pool for the DNI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pools: Option<Vec<SnowIPPoolPools>>,
}

/// IPPool defines an ip pool with ip range, subnet and gateway.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SnowIPPoolPools {
    /// Gateway is the gateway of the subnet for routing purpose.
    pub gateway: String,
    /// IPEnd is the end address of an ip range.
    #[serde(rename = "ipEnd")]
    pub ip_end: String,
    /// IPStart is the start address of an ip range.
    #[serde(rename = "ipStart")]
    pub ip_start: String,
    /// Subnet is used to determine whether an ip is within subnet.
    pub subnet: String,
}

/// SnowIPPoolStatus defines the observed state of SnowIPPool.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SnowIPPoolStatus {
}

