// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/projectcalico/calico/crd.projectcalico.org/v1/ippools.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// IPPoolSpec contains the specification for an IPPool resource.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "crd.projectcalico.org", version = "v1", kind = "IPPool", plural = "ippools")]
#[kube(schema = "disabled")]
pub struct IPPoolSpec {
    /// AllowedUse controls what the IP pool will be used for.  If not specified or empty, defaults to ["Tunnel", "Workload"] for back-compatibility
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "allowedUses")]
    pub allowed_uses: Option<Vec<String>>,
    /// The block size to use for IP address assignments from this pool. Defaults to 26 for IPv4 and 122 for IPv6.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "blockSize")]
    pub block_size: Option<i64>,
    /// The pool CIDR.
    pub cidr: String,
    /// Disable exporting routes from this IP Pool's CIDR over BGP. [Default: false]
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "disableBGPExport")]
    pub disable_bgp_export: Option<bool>,
    /// When disabled is true, Calico IPAM will not assign addresses from this pool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    /// Deprecated: this field is only used for APIv1 backwards compatibility. Setting this field is not allowed, this field is for internal use only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipip: Option<IPPoolIpip>,
    /// Contains configuration for IPIP tunneling for this pool. If not specified, then this is defaulted to "Never" (i.e. IPIP tunneling is disabled).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ipipMode")]
    pub ipip_mode: Option<String>,
    /// Deprecated: this field is only used for APIv1 backwards compatibility. Setting this field is not allowed, this field is for internal use only.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nat-outgoing")]
    pub nat_outgoing: Option<bool>,
    /// When natOutgoing is true, packets sent from Calico networked containers in this pool to destinations outside of this pool will be masqueraded.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "natOutgoing")]
    pub nat_outgoing_x: Option<bool>,
    /// Allows IPPool to allocate for a specific node by label selector.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nodeSelector")]
    pub node_selector: Option<String>,
    /// Contains configuration for VXLAN tunneling for this pool. If not specified, then this is defaulted to "Never" (i.e. VXLAN tunneling is disabled).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vxlanMode")]
    pub vxlan_mode: Option<String>,
}

/// Deprecated: this field is only used for APIv1 backwards compatibility. Setting this field is not allowed, this field is for internal use only.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct IPPoolIpip {
    /// When enabled is true, ipip tunneling will be used to deliver packets to destinations within this pool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// The IPIP mode.  This can be one of "always" or "cross-subnet".  A mode of "always" will also use IPIP tunneling for routing to destination IP addresses within this pool.  A mode of "cross-subnet" will only use IPIP tunneling when the destination node is on a different subnet to the originating node.  The default value (if not specified) is "always".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

