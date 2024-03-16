// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/cilium/cilium/cilium.io/v2/ciliumexternalworkloads.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// Spec is the desired configuration of the external Cilium workload.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "cilium.io", version = "v2", kind = "CiliumExternalWorkload", plural = "ciliumexternalworkloads")]
#[kube(status = "CiliumExternalWorkloadStatus")]
#[kube(schema = "disabled")]
pub struct CiliumExternalWorkloadSpec {
    /// IPv4AllocCIDR is the range of IPv4 addresses in the CIDR format that the external workload can use to allocate IP addresses for the tunnel device and the health endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ipv4-alloc-cidr")]
    pub ipv4_alloc_cidr: Option<String>,
    /// IPv6AllocCIDR is the range of IPv6 addresses in the CIDR format that the external workload can use to allocate IP addresses for the tunnel device and the health endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ipv6-alloc-cidr")]
    pub ipv6_alloc_cidr: Option<String>,
}

/// Status is the most recent status of the external Cilium workload. It is a read-only field.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumExternalWorkloadStatus {
    /// ID is the numeric identity allocated for the external workload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    /// IP is the IP address of the workload. Empty if the workload has not registered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
}

