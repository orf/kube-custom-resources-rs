// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/cilium/cilium/cilium.io/v2/ciliumnodes.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// Spec defines the desired specification/configuration of the node.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "cilium.io", version = "v2", kind = "CiliumNode", plural = "ciliumnodes")]
#[kube(status = "CiliumNodeStatus")]
#[kube(schema = "disabled")]
pub struct CiliumNodeSpec {
    /// Addresses is the list of all node addresses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addresses: Option<Vec<CiliumNodeAddresses>>,
    /// AlibabaCloud is the AlibabaCloud IPAM specific configuration.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "alibaba-cloud")]
    pub alibaba_cloud: Option<CiliumNodeAlibabaCloud>,
    /// Azure is the Azure IPAM specific configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure: Option<CiliumNodeAzure>,
    /// BootID is a unique node identifier generated on boot
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootid: Option<String>,
    /// Encryption is the encryption configuration of the node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<CiliumNodeEncryption>,
    /// ENI is the AWS ENI specific configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eni: Option<CiliumNodeEni>,
    /// HealthAddressing is the addressing information for health connectivity checking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<CiliumNodeHealth>,
    /// IngressAddressing is the addressing information for Ingress listener.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress: Option<CiliumNodeIngress>,
    /// InstanceID is the identifier of the node. This is different from the node name which is typically the FQDN of the node. The InstanceID typically refers to the identifier used by the cloud provider or some other means of identification.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "instance-id")]
    pub instance_id: Option<String>,
    /// IPAM is the address management specification. This section can be populated by a user or it can be automatically populated by an IPAM operator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipam: Option<CiliumNodeIpam>,
    /// NodeIdentity is the Cilium numeric identity allocated for the node, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodeidentity: Option<i64>,
}

/// NodeAddress is a node address.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeAddresses {
    /// IP is an IP of a node
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Type is the type of the node address
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
}

/// AlibabaCloud is the AlibabaCloud IPAM specific configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeAlibabaCloud {
    /// AvailabilityZone is the availability zone to use when allocating ENIs.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "availability-zone")]
    pub availability_zone: Option<String>,
    /// CIDRBlock is vpc ipv4 CIDR
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "cidr-block")]
    pub cidr_block: Option<String>,
    /// InstanceType is the ECS instance type, e.g. "ecs.g6.2xlarge"
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "instance-type")]
    pub instance_type: Option<String>,
    /// SecurityGroupTags is the list of tags to use when evaluating which security groups to use for the ENI.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "security-group-tags")]
    pub security_group_tags: Option<BTreeMap<String, String>>,
    /// SecurityGroups is the list of security groups to attach to any ENI that is created and attached to the instance.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "security-groups")]
    pub security_groups: Option<Vec<String>>,
    /// VPCID is the VPC ID to use when allocating ENIs.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vpc-id")]
    pub vpc_id: Option<String>,
    /// VSwitchTags is the list of tags to use when evaluating which vSwitch to use for the ENI.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vswitch-tags")]
    pub vswitch_tags: Option<BTreeMap<String, String>>,
    /// VSwitches is the ID of vSwitch available for ENI
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vswitches: Option<Vec<String>>,
}

/// Azure is the Azure IPAM specific configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeAzure {
    /// InterfaceName is the name of the interface the cilium-operator will use to allocate all the IPs on
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "interface-name")]
    pub interface_name: Option<String>,
}

/// Encryption is the encryption configuration of the node.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeEncryption {
    /// Key is the index to the key to use for encryption or 0 if encryption is disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<i64>,
}

/// ENI is the AWS ENI specific configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeEni {
    /// AvailabilityZone is the availability zone to use when allocating ENIs.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "availability-zone")]
    pub availability_zone: Option<String>,
    /// DeleteOnTermination defines that the ENI should be deleted when the associated instance is terminated. If the parameter is not set the default behavior is to delete the ENI on instance termination.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "delete-on-termination")]
    pub delete_on_termination: Option<bool>,
    /// DisablePrefixDelegation determines whether ENI prefix delegation should be disabled on this node.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "disable-prefix-delegation")]
    pub disable_prefix_delegation: Option<bool>,
    /// ExcludeInterfaceTags is the list of tags to use when excluding ENIs for Cilium IP allocation. Any interface matching this set of tags will not be managed by Cilium.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "exclude-interface-tags")]
    pub exclude_interface_tags: Option<BTreeMap<String, String>>,
    /// FirstInterfaceIndex is the index of the first ENI to use for IP allocation, e.g. if the node has eth0, eth1, eth2 and FirstInterfaceIndex is set to 1, then only eth1 and eth2 will be used for IP allocation, eth0 will be ignored for PodIP allocation.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "first-interface-index")]
    pub first_interface_index: Option<i64>,
    /// InstanceID is the AWS InstanceId of the node. The InstanceID is used to retrieve AWS metadata for the node. 
    ///  OBSOLETE: This field is obsolete, please use Spec.InstanceID
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "instance-id")]
    pub instance_id: Option<String>,
    /// InstanceType is the AWS EC2 instance type, e.g. "m5.large"
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "instance-type")]
    pub instance_type: Option<String>,
    /// MaxAboveWatermark is the maximum number of addresses to allocate beyond the addresses needed to reach the PreAllocate watermark. Going above the watermark can help reduce the number of API calls to allocate IPs, e.g. when a new ENI is allocated, as many secondary IPs as possible are allocated. Limiting the amount can help reduce waste of IPs. 
    ///  OBSOLETE: This field is obsolete, please use Spec.IPAM.MaxAboveWatermark
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "max-above-watermark")]
    pub max_above_watermark: Option<i64>,
    /// MinAllocate is the minimum number of IPs that must be allocated when the node is first bootstrapped. It defines the minimum base socket of addresses that must be available. After reaching this watermark, the PreAllocate and MaxAboveWatermark logic takes over to continue allocating IPs. 
    ///  OBSOLETE: This field is obsolete, please use Spec.IPAM.MinAllocate
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "min-allocate")]
    pub min_allocate: Option<i64>,
    /// NodeSubnetID is the subnet of the primary ENI the instance was brought up with. It is used as a sensible default subnet to create ENIs in.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "node-subnet-id")]
    pub node_subnet_id: Option<String>,
    /// PreAllocate defines the number of IP addresses that must be available for allocation in the IPAMspec. It defines the buffer of addresses available immediately without requiring cilium-operator to get involved. 
    ///  OBSOLETE: This field is obsolete, please use Spec.IPAM.PreAllocate
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "pre-allocate")]
    pub pre_allocate: Option<i64>,
    /// SecurityGroupTags is the list of tags to use when evaliating what AWS security groups to use for the ENI.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "security-group-tags")]
    pub security_group_tags: Option<BTreeMap<String, String>>,
    /// SecurityGroups is the list of security groups to attach to any ENI that is created and attached to the instance.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "security-groups")]
    pub security_groups: Option<Vec<String>>,
    /// SubnetIDs is the list of subnet ids to use when evaluating what AWS subnets to use for ENI and IP allocation.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "subnet-ids")]
    pub subnet_ids: Option<Vec<String>>,
    /// SubnetTags is the list of tags to use when evaluating what AWS subnets to use for ENI and IP allocation.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "subnet-tags")]
    pub subnet_tags: Option<BTreeMap<String, String>>,
    /// UsePrimaryAddress determines whether an ENI's primary address should be available for allocations on the node
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "use-primary-address")]
    pub use_primary_address: Option<bool>,
    /// VpcID is the VPC ID to use when allocating ENIs.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vpc-id")]
    pub vpc_id: Option<String>,
}

/// HealthAddressing is the addressing information for health connectivity checking.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeHealth {
    /// IPv4 is the IPv4 address of the IPv4 health endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<String>,
    /// IPv6 is the IPv6 address of the IPv4 health endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
}

/// IngressAddressing is the addressing information for Ingress listener.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeIngress {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
}

/// IPAM is the address management specification. This section can be populated by a user or it can be automatically populated by an IPAM operator.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeIpam {
    /// MaxAboveWatermark is the maximum number of addresses to allocate beyond the addresses needed to reach the PreAllocate watermark. Going above the watermark can help reduce the number of API calls to allocate IPs, e.g. when a new ENI is allocated, as many secondary IPs as possible are allocated. Limiting the amount can help reduce waste of IPs.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "max-above-watermark")]
    pub max_above_watermark: Option<i64>,
    /// MaxAllocate is the maximum number of IPs that can be allocated to the node. When the current amount of allocated IPs will approach this value, the considered value for PreAllocate will decrease down to 0 in order to not attempt to allocate more addresses than defined.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "max-allocate")]
    pub max_allocate: Option<i64>,
    /// MinAllocate is the minimum number of IPs that must be allocated when the node is first bootstrapped. It defines the minimum base socket of addresses that must be available. After reaching this watermark, the PreAllocate and MaxAboveWatermark logic takes over to continue allocating IPs.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "min-allocate")]
    pub min_allocate: Option<i64>,
    /// PodCIDRs is the list of CIDRs available to the node for allocation. When an IP is used, the IP will be added to Status.IPAM.Used
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "podCIDRs")]
    pub pod_cid_rs: Option<Vec<String>>,
    /// Pool is the list of IPs available to the node for allocation. When an IP is used, the IP will remain on this list but will be added to Status.IPAM.Used
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool: Option<BTreeMap<String, CiliumNodeIpamPool>>,
    /// Pools contains the list of assigned IPAM pools for this node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pools: Option<CiliumNodeIpamPools>,
    /// PreAllocate defines the number of IP addresses that must be available for allocation in the IPAMspec. It defines the buffer of addresses available immediately without requiring cilium-operator to get involved.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "pre-allocate")]
    pub pre_allocate: Option<i64>,
}

/// Pool is the list of IPs available to the node for allocation. When an IP is used, the IP will remain on this list but will be added to Status.IPAM.Used
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeIpamPool {
    /// Owner is the owner of the IP. This field is set if the IP has been allocated. It will be set to the pod name or another identifier representing the usage of the IP 
    ///  The owner field is left blank for an entry in Spec.IPAM.Pool and filled out as the IP is used and also added to Status.IPAM.Used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Resource is set for both available and allocated IPs, it represents what resource the IP is associated with, e.g. in combination with AWS ENI, this will refer to the ID of the ENI
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

/// Pools contains the list of assigned IPAM pools for this node.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeIpamPools {
    /// Allocated contains the list of pooled CIDR assigned to this node. The operator will add new pod CIDRs to this field, whereas the agent will remove CIDRs it has released.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocated: Option<Vec<CiliumNodeIpamPoolsAllocated>>,
    /// Requested contains a list of IPAM pool requests, i.e. indicates how many addresses this node requests out of each pool listed here. This field is owned and written to by cilium-agent and read by the operator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested: Option<Vec<CiliumNodeIpamPoolsRequested>>,
}

/// IPAMPoolAllocation describes an allocation of an IPAM pool from the operator to the node. It contains the assigned PodCIDRs allocated from this pool
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeIpamPoolsAllocated {
    /// CIDRs contains a list of pod CIDRs currently allocated from this pool
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidrs: Option<Vec<String>>,
    /// Pool is the name of the IPAM pool backing this allocation
    pub pool: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeIpamPoolsRequested {
    /// Needed indicates how many IPs out of the above Pool this node requests from the operator. The operator runs a reconciliation loop to ensure each node always has enough PodCIDRs allocated in each pool to fulfill the requested number of IPs here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needed: Option<CiliumNodeIpamPoolsRequestedNeeded>,
    /// Pool is the name of the IPAM pool backing this request
    pub pool: String,
}

/// Needed indicates how many IPs out of the above Pool this node requests from the operator. The operator runs a reconciliation loop to ensure each node always has enough PodCIDRs allocated in each pool to fulfill the requested number of IPs here.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeIpamPoolsRequestedNeeded {
    /// IPv4Addrs contains the number of requested IPv4 addresses out of a given pool
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ipv4-addrs")]
    pub ipv4_addrs: Option<i64>,
    /// IPv6Addrs contains the number of requested IPv6 addresses out of a given pool
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ipv6-addrs")]
    pub ipv6_addrs: Option<i64>,
}

/// Status defines the realized specification/configuration and status of the node.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeStatus {
    /// AlibabaCloud is the AlibabaCloud specific status of the node.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "alibaba-cloud")]
    pub alibaba_cloud: Option<CiliumNodeStatusAlibabaCloud>,
    /// Azure is the Azure specific status of the node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure: Option<CiliumNodeStatusAzure>,
    /// ENI is the AWS ENI specific status of the node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eni: Option<CiliumNodeStatusEni>,
    /// IPAM is the IPAM status of the node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipam: Option<CiliumNodeStatusIpam>,
}

/// AlibabaCloud is the AlibabaCloud specific status of the node.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeStatusAlibabaCloud {
    /// ENIs is the list of ENIs on the node
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enis: Option<BTreeMap<String, CiliumNodeStatusAlibabaCloudEnis>>,
}

/// ENIs is the list of ENIs on the node
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeStatusAlibabaCloudEnis {
    /// InstanceID is the InstanceID using this ENI
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "instance-id")]
    pub instance_id: Option<String>,
    /// MACAddress is the mac address of the ENI
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "mac-address")]
    pub mac_address: Option<String>,
    /// NetworkInterfaceID is the ENI id
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "network-interface-id")]
    pub network_interface_id: Option<String>,
    /// PrimaryIPAddress is the primary IP on ENI
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "primary-ip-address")]
    pub primary_ip_address: Option<String>,
    /// PrivateIPSets is the list of all IPs on the ENI, including PrimaryIPAddress
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "private-ipsets")]
    pub private_ipsets: Option<Vec<CiliumNodeStatusAlibabaCloudEnisPrivateIpsets>>,
    /// SecurityGroupIDs is the security group ids used by this ENI
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "security-groupids")]
    pub security_groupids: Option<Vec<String>>,
    /// Tags is the tags on this ENI
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,
    /// Type is the ENI type Primary or Secondary
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
    /// VPC is the vpc to which the ENI belongs
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpc: Option<CiliumNodeStatusAlibabaCloudEnisVpc>,
    /// VSwitch is the vSwitch the ENI is using
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vswitch: Option<CiliumNodeStatusAlibabaCloudEnisVswitch>,
    /// ZoneID is the zone to which the ENI belongs
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "zone-id")]
    pub zone_id: Option<String>,
}

/// PrivateIPSet is a nested struct in ecs response
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeStatusAlibabaCloudEnisPrivateIpsets {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "private-ip-address")]
    pub private_ip_address: Option<String>,
}

/// VPC is the vpc to which the ENI belongs
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeStatusAlibabaCloudEnisVpc {
    /// CIDRBlock is the VPC IPv4 CIDR
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    /// IPv6CIDRBlock is the VPC IPv6 CIDR
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ipv6-cidr")]
    pub ipv6_cidr: Option<String>,
    /// SecondaryCIDRs is the list of Secondary CIDRs associated with the VPC
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secondary-cidrs")]
    pub secondary_cidrs: Option<Vec<String>>,
    /// VPCID is the vpc to which the ENI belongs
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vpc-id")]
    pub vpc_id: Option<String>,
}

/// VSwitch is the vSwitch the ENI is using
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeStatusAlibabaCloudEnisVswitch {
    /// CIDRBlock is the vSwitch IPv4 CIDR
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    /// IPv6CIDRBlock is the vSwitch IPv6 CIDR
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ipv6-cidr")]
    pub ipv6_cidr: Option<String>,
    /// VSwitchID is the vSwitch to which the ENI belongs
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vswitch-id")]
    pub vswitch_id: Option<String>,
}

/// Azure is the Azure specific status of the node.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeStatusAzure {
    /// Interfaces is the list of interfaces on the node
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interfaces: Option<Vec<CiliumNodeStatusAzureInterfaces>>,
}

/// AzureInterface represents an Azure Interface
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeStatusAzureInterfaces {
    /// GatewayIP is the interface's subnet's default route 
    ///  OBSOLETE: This field is obsolete, please use Gateway field instead.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "GatewayIP")]
    pub gateway_ip: Option<String>,
    /// Addresses is the list of all IPs associated with the interface, including all secondary addresses
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addresses: Option<Vec<CiliumNodeStatusAzureInterfacesAddresses>>,
    /// CIDR is the range that the interface belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    /// Gateway is the interface's subnet's default route
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// ID is the identifier
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// MAC is the mac address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// Name is the name of the interface
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// SecurityGroup is the security group associated with the interface
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "security-group")]
    pub security_group: Option<String>,
    /// State is the provisioning state
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// AzureAddress is an IP address assigned to an AzureInterface
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeStatusAzureInterfacesAddresses {
    /// IP is the ip address of the address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// State is the provisioning state of the address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Subnet is the subnet the address belongs to
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subnet: Option<String>,
}

/// ENI is the AWS ENI specific status of the node.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeStatusEni {
    /// ENIs is the list of ENIs on the node
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enis: Option<BTreeMap<String, CiliumNodeStatusEniEnis>>,
}

/// ENIs is the list of ENIs on the node
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeStatusEniEnis {
    /// Addresses is the list of all secondary IPs associated with the ENI
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addresses: Option<Vec<String>>,
    /// AvailabilityZone is the availability zone of the ENI
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "availability-zone")]
    pub availability_zone: Option<String>,
    /// Description is the description field of the ENI
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// ID is the ENI ID
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// IP is the primary IP of the ENI
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// MAC is the mac address of the ENI
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// Number is the interface index, it used in combination with FirstInterfaceIndex
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number: Option<i64>,
    /// Prefixes is the list of all /28 prefixes associated with the ENI
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefixes: Option<Vec<String>>,
    /// SecurityGroups are the security groups associated with the ENI
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "security-groups")]
    pub security_groups: Option<Vec<String>>,
    /// Subnet is the subnet the ENI is associated with
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subnet: Option<CiliumNodeStatusEniEnisSubnet>,
    /// Tags is the set of tags of the ENI. Used to detect ENIs which should not be managed by Cilium
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,
    /// VPC is the VPC information to which the ENI is attached to
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpc: Option<CiliumNodeStatusEniEnisVpc>,
}

/// Subnet is the subnet the ENI is associated with
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeStatusEniEnisSubnet {
    /// CIDR is the CIDR range associated with the subnet
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    /// ID is the ID of the subnet
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// VPC is the VPC information to which the ENI is attached to
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeStatusEniEnisVpc {
    /// CIDRs is the list of CIDR ranges associated with the VPC
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidrs: Option<Vec<String>>,
    /// / ID is the ID of a VPC
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// PrimaryCIDR is the primary CIDR of the VPC
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "primary-cidr")]
    pub primary_cidr: Option<String>,
}

/// IPAM is the IPAM status of the node.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeStatusIpam {
    /// Operator is the Operator status of the node
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "operator-status")]
    pub operator_status: Option<CiliumNodeStatusIpamOperatorStatus>,
    /// PodCIDRs lists the status of each pod CIDR allocated to this node.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "pod-cidrs")]
    pub pod_cidrs: Option<BTreeMap<String, CiliumNodeStatusIpamPodCidrs>>,
    /// ReleaseIPs tracks the state for every IP considered for release. value can be one of the following string : * marked-for-release : Set by operator as possible candidate for IP * ready-for-release  : Acknowledged as safe to release by agent * do-not-release     : IP already in use / not owned by the node. Set by agent * released           : IP successfully released. Set by operator
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "release-ips")]
    pub release_ips: Option<BTreeMap<String, String>>,
    /// Used lists all IPs out of Spec.IPAM.Pool which have been allocated and are in use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used: Option<BTreeMap<String, CiliumNodeStatusIpamUsed>>,
}

/// Operator is the Operator status of the node
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeStatusIpamOperatorStatus {
    /// Error is the error message set by cilium-operator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// PodCIDRs lists the status of each pod CIDR allocated to this node.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeStatusIpamPodCidrs {
    /// Status describes the status of a pod CIDR
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<CiliumNodeStatusIpamPodCidrsStatus>,
}

/// PodCIDRs lists the status of each pod CIDR allocated to this node.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum CiliumNodeStatusIpamPodCidrsStatus {
    #[serde(rename = "released")]
    Released,
    #[serde(rename = "depleted")]
    Depleted,
    #[serde(rename = "in-use")]
    InUse,
}

/// Used lists all IPs out of Spec.IPAM.Pool which have been allocated and are in use.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumNodeStatusIpamUsed {
    /// Owner is the owner of the IP. This field is set if the IP has been allocated. It will be set to the pod name or another identifier representing the usage of the IP 
    ///  The owner field is left blank for an entry in Spec.IPAM.Pool and filled out as the IP is used and also added to Status.IPAM.Used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Resource is set for both available and allocated IPs, it represents what resource the IP is associated with, e.g. in combination with AWS ENI, this will refer to the ID of the ENI
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

