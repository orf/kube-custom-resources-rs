// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/cilium/cilium/cilium.io/v2/ciliumendpoints.yaml --derive=Default --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use std::collections::BTreeMap;
}
use self::prelude::*;

/// EndpointStatus is the status of a Cilium endpoint.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumEndpointStatus {
    /// Controllers is the list of failing controllers for this endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controllers: Option<Vec<CiliumEndpointStatusControllers>>,
    /// Encryption is the encryption configuration of the node
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<CiliumEndpointStatusEncryption>,
    /// ExternalIdentifiers is a set of identifiers to identify the endpoint apart from the pod name. This includes container runtime IDs.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "external-identifiers")]
    pub external_identifiers: Option<CiliumEndpointStatusExternalIdentifiers>,
    /// Health is the overall endpoint & subcomponent health.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<CiliumEndpointStatusHealth>,
    /// ID is the cilium-agent-local ID of the endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    /// Identity is the security identity associated with the endpoint
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<CiliumEndpointStatusIdentity>,
    /// Log is the list of the last few warning and error log entries
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<Vec<CiliumEndpointStatusLog>>,
    /// NamedPorts List of named Layer 4 port and protocol pairs which will be used in Network Policy specs. 
    ///  swagger:model NamedPorts
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "named-ports")]
    pub named_ports: Option<Vec<CiliumEndpointStatusNamedPorts>>,
    /// Networking is the networking properties of the endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub networking: Option<CiliumEndpointStatusNetworking>,
    /// EndpointPolicy represents the endpoint's policy by listing all allowed ingress and egress identities in combination with L4 port and protocol.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<CiliumEndpointStatusPolicy>,
    /// State is the state of the endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<CiliumEndpointStatusState>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "visibility-policy-status")]
    pub visibility_policy_status: Option<String>,
}

/// ControllerStatus is the status of a failing controller.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumEndpointStatusControllers {
    /// Configuration is the controller configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration: Option<CiliumEndpointStatusControllersConfiguration>,
    /// Name is the name of the controller
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Status is the status of the controller
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<CiliumEndpointStatusControllersStatus>,
    /// UUID is the UUID of the controller
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
}

/// Configuration is the controller configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumEndpointStatusControllersConfiguration {
    /// Retry on error
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "error-retry")]
    pub error_retry: Option<bool>,
    /// Base error retry back-off time Format: duration
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "error-retry-base")]
    pub error_retry_base: Option<i64>,
    /// Regular synchronization interval Format: duration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<i64>,
}

/// Status is the status of the controller
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumEndpointStatusControllersStatus {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "consecutive-failure-count")]
    pub consecutive_failure_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "failure-count")]
    pub failure_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "last-failure-msg")]
    pub last_failure_msg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "last-failure-timestamp")]
    pub last_failure_timestamp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "last-success-timestamp")]
    pub last_success_timestamp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "success-count")]
    pub success_count: Option<i64>,
}

/// Encryption is the encryption configuration of the node
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumEndpointStatusEncryption {
    /// Key is the index to the key to use for encryption or 0 if encryption is disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<i64>,
}

/// ExternalIdentifiers is a set of identifiers to identify the endpoint apart from the pod name. This includes container runtime IDs.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumEndpointStatusExternalIdentifiers {
    /// ID assigned to this attachment by container runtime
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "cni-attachment-id")]
    pub cni_attachment_id: Option<String>,
    /// ID assigned by container runtime (deprecated, may not be unique)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "container-id")]
    pub container_id: Option<String>,
    /// Name assigned to container (deprecated, may not be unique)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "container-name")]
    pub container_name: Option<String>,
    /// Docker endpoint ID
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "docker-endpoint-id")]
    pub docker_endpoint_id: Option<String>,
    /// Docker network ID
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "docker-network-id")]
    pub docker_network_id: Option<String>,
    /// K8s namespace for this endpoint (deprecated, may not be unique)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "k8s-namespace")]
    pub k8s_namespace: Option<String>,
    /// K8s pod name for this endpoint (deprecated, may not be unique)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "k8s-pod-name")]
    pub k8s_pod_name: Option<String>,
    /// K8s pod for this endpoint (deprecated, may not be unique)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "pod-name")]
    pub pod_name: Option<String>,
}

/// Health is the overall endpoint & subcomponent health.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumEndpointStatusHealth {
    /// bpf
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bpf: Option<String>,
    /// Is this endpoint reachable
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connected: Option<bool>,
    /// overall health
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "overallHealth")]
    pub overall_health: Option<String>,
    /// policy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
}

/// Identity is the security identity associated with the endpoint
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumEndpointStatusIdentity {
    /// ID is the numeric identity of the endpoint
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    /// Labels is the list of labels associated with the identity
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
}

/// EndpointStatusChange Indication of a change of status 
///  swagger:model EndpointStatusChange
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumEndpointStatusLog {
    /// Code indicate type of status change Enum: [ok failed]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Status message
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// state
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Timestamp when status change occurred
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

/// Port Layer 4 port / protocol pair 
///  swagger:model Port
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumEndpointStatusNamedPorts {
    /// Optional layer 4 port name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Layer 4 port number
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<i64>,
    /// Layer 4 protocol Enum: [TCP UDP SCTP ICMP ICMPV6 ANY]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

/// Networking is the networking properties of the endpoint.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumEndpointStatusNetworking {
    /// IP4/6 addresses assigned to this Endpoint
    pub addressing: Vec<CiliumEndpointStatusNetworkingAddressing>,
    /// NodeIP is the IP of the node the endpoint is running on. The IP must be reachable between nodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
}

/// AddressPair is a pair of IPv4 and/or IPv6 address.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumEndpointStatusNetworkingAddressing {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
}

/// EndpointPolicy represents the endpoint's policy by listing all allowed ingress and egress identities in combination with L4 port and protocol.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumEndpointStatusPolicy {
    /// EndpointPolicyDirection is the list of allowed identities per direction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<CiliumEndpointStatusPolicyEgress>,
    /// EndpointPolicyDirection is the list of allowed identities per direction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress: Option<CiliumEndpointStatusPolicyIngress>,
}

/// EndpointPolicyDirection is the list of allowed identities per direction.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumEndpointStatusPolicyEgress {
    /// Deprecated
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adding: Option<Vec<CiliumEndpointStatusPolicyEgressAdding>>,
    /// AllowedIdentityList is a list of IdentityTuples that species peers that are allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed: Option<Vec<CiliumEndpointStatusPolicyEgressAllowed>>,
    /// DenyIdentityList is a list of IdentityTuples that species peers that are denied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied: Option<Vec<CiliumEndpointStatusPolicyEgressDenied>>,
    pub enforcing: bool,
    /// Deprecated
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removing: Option<Vec<CiliumEndpointStatusPolicyEgressRemoving>>,
    /// EndpointPolicyState defines the state of the Policy mode: "enforcing", "non-enforcing", "disabled"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// IdentityTuple specifies a peer by identity, destination port and protocol.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumEndpointStatusPolicyEgressAdding {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dest-port")]
    pub dest_port: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "identity-labels")]
    pub identity_labels: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<i64>,
}

/// IdentityTuple specifies a peer by identity, destination port and protocol.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumEndpointStatusPolicyEgressAllowed {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dest-port")]
    pub dest_port: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "identity-labels")]
    pub identity_labels: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<i64>,
}

/// IdentityTuple specifies a peer by identity, destination port and protocol.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumEndpointStatusPolicyEgressDenied {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dest-port")]
    pub dest_port: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "identity-labels")]
    pub identity_labels: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<i64>,
}

/// IdentityTuple specifies a peer by identity, destination port and protocol.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumEndpointStatusPolicyEgressRemoving {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dest-port")]
    pub dest_port: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "identity-labels")]
    pub identity_labels: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<i64>,
}

/// EndpointPolicyDirection is the list of allowed identities per direction.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumEndpointStatusPolicyIngress {
    /// Deprecated
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adding: Option<Vec<CiliumEndpointStatusPolicyIngressAdding>>,
    /// AllowedIdentityList is a list of IdentityTuples that species peers that are allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed: Option<Vec<CiliumEndpointStatusPolicyIngressAllowed>>,
    /// DenyIdentityList is a list of IdentityTuples that species peers that are denied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied: Option<Vec<CiliumEndpointStatusPolicyIngressDenied>>,
    pub enforcing: bool,
    /// Deprecated
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removing: Option<Vec<CiliumEndpointStatusPolicyIngressRemoving>>,
    /// EndpointPolicyState defines the state of the Policy mode: "enforcing", "non-enforcing", "disabled"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// IdentityTuple specifies a peer by identity, destination port and protocol.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumEndpointStatusPolicyIngressAdding {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dest-port")]
    pub dest_port: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "identity-labels")]
    pub identity_labels: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<i64>,
}

/// IdentityTuple specifies a peer by identity, destination port and protocol.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumEndpointStatusPolicyIngressAllowed {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dest-port")]
    pub dest_port: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "identity-labels")]
    pub identity_labels: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<i64>,
}

/// IdentityTuple specifies a peer by identity, destination port and protocol.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumEndpointStatusPolicyIngressDenied {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dest-port")]
    pub dest_port: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "identity-labels")]
    pub identity_labels: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<i64>,
}

/// IdentityTuple specifies a peer by identity, destination port and protocol.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CiliumEndpointStatusPolicyIngressRemoving {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dest-port")]
    pub dest_port: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "identity-labels")]
    pub identity_labels: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<i64>,
}

/// EndpointStatus is the status of a Cilium endpoint.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum CiliumEndpointStatusState {
    #[serde(rename = "creating")]
    Creating,
    #[serde(rename = "waiting-for-identity")]
    WaitingForIdentity,
    #[serde(rename = "not-ready")]
    NotReady,
    #[serde(rename = "waiting-to-regenerate")]
    WaitingToRegenerate,
    #[serde(rename = "regenerating")]
    Regenerating,
    #[serde(rename = "restoring")]
    Restoring,
    #[serde(rename = "ready")]
    Ready,
    #[serde(rename = "disconnecting")]
    Disconnecting,
    #[serde(rename = "disconnected")]
    Disconnected,
    #[serde(rename = "invalid")]
    Invalid,
}

