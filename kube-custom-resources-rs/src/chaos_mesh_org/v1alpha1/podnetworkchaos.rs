// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/chaos-mesh/chaos-mesh/chaos-mesh.org/v1alpha1/podnetworkchaos.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// Spec defines the behavior of a pod chaos experiment
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "chaos-mesh.org", version = "v1alpha1", kind = "PodNetworkChaos", plural = "podnetworkchaos")]
#[kube(namespaced)]
#[kube(status = "PodNetworkChaosStatus")]
#[kube(schema = "disabled")]
pub struct PodNetworkChaosSpec {
    /// The ipset on the pod
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipsets: Option<Vec<PodNetworkChaosIpsets>>,
    /// The iptables rules on the pod
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iptables: Option<Vec<PodNetworkChaosIptables>>,
    /// The tc rules on the pod
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcs: Option<Vec<PodNetworkChaosTcs>>,
}

/// RawIPSet represents an ipset on specific pod
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodNetworkChaosIpsets {
    /// The contents of ipset. Only available when IPSetType is NetPortIPSet.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "cidrAndPorts")]
    pub cidr_and_ports: Option<Vec<PodNetworkChaosIpsetsCidrAndPorts>>,
    /// The contents of ipset. Only available when IPSetType is NetIPSet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidrs: Option<Vec<String>>,
    /// IPSetType represents the type of IP set
    #[serde(rename = "ipsetType")]
    pub ipset_type: String,
    /// The name of ipset
    pub name: String,
    /// The contents of ipset. Only available when IPSetType is SetIPSet.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "setNames")]
    pub set_names: Option<Vec<String>>,
    pub source: String,
}

/// CidrAndPort represents CIDR and port pair
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodNetworkChaosIpsetsCidrAndPorts {
    pub cidr: String,
    pub port: i64,
}

/// RawIptables represents the iptables rules on specific pod
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodNetworkChaosIptables {
    /// Device represents the network device to be affected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// The block direction of this iptables rule
    pub direction: String,
    /// The name of related ipset
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipsets: Option<Vec<String>>,
    /// The name of iptables chain
    pub name: String,
    pub source: String,
}

/// RawTrafficControl represents the traffic control chaos on specific pod
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodNetworkChaosTcs {
    /// Bandwidth represents the detail about bandwidth control action
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bandwidth: Option<PodNetworkChaosTcsBandwidth>,
    /// Corrupt represents the detail about corrupt action
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corrupt: Option<PodNetworkChaosTcsCorrupt>,
    /// Delay represents the detail about delay action
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay: Option<PodNetworkChaosTcsDelay>,
    /// Device represents the network device to be affected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// DuplicateSpec represents the detail about loss action
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duplicate: Option<PodNetworkChaosTcsDuplicate>,
    /// The name of target ipset
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipset: Option<String>,
    /// Loss represents the detail about loss action
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss: Option<PodNetworkChaosTcsLoss>,
    /// Rate represents the detail about rate control action
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<PodNetworkChaosTcsRate>,
    /// The name and namespace of the source network chaos
    pub source: String,
    /// The type of traffic control
    #[serde(rename = "type")]
    pub r#type: String,
}

/// Bandwidth represents the detail about bandwidth control action
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodNetworkChaosTcsBandwidth {
    /// Buffer is the maximum amount of bytes that tokens can be available for instantaneously.
    pub buffer: i32,
    /// Limit is the number of bytes that can be queued waiting for tokens to become available.
    pub limit: i32,
    /// Minburst specifies the size of the peakrate bucket. For perfect accuracy, should be set to the MTU of the interface.  If a peakrate is needed, but some burstiness is acceptable, this size can be raised. A 3000 byte minburst allows around 3mbit/s of peakrate, given 1000 byte packets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minburst: Option<i32>,
    /// Peakrate is the maximum depletion rate of the bucket. The peakrate does not need to be set, it is only necessary if perfect millisecond timescale shaping is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peakrate: Option<i64>,
    /// Rate is the speed knob. Allows bit, kbit, mbit, gbit, tbit, bps, kbps, mbps, gbps, tbps unit. bps means bytes per second.
    pub rate: String,
}

/// Corrupt represents the detail about corrupt action
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodNetworkChaosTcsCorrupt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation: Option<String>,
    pub corrupt: String,
}

/// Delay represents the detail about delay action
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodNetworkChaosTcsDelay {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jitter: Option<String>,
    pub latency: String,
    /// ReorderSpec defines details of packet reorder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reorder: Option<PodNetworkChaosTcsDelayReorder>,
}

/// ReorderSpec defines details of packet reorder.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodNetworkChaosTcsDelayReorder {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation: Option<String>,
    pub gap: i64,
    pub reorder: String,
}

/// DuplicateSpec represents the detail about loss action
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodNetworkChaosTcsDuplicate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation: Option<String>,
    pub duplicate: String,
}

/// Loss represents the detail about loss action
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodNetworkChaosTcsLoss {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation: Option<String>,
    pub loss: String,
}

/// Rate represents the detail about rate control action
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodNetworkChaosTcsRate {
    /// Rate is the speed knob. Allows bit, kbit, mbit, gbit, tbit, bps, kbps, mbps, gbps, tbps unit. bps means bytes per second.
    pub rate: String,
}

/// Most recently observed status of the chaos experiment about pods
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodNetworkChaosStatus {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "failedMessage")]
    pub failed_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
}

