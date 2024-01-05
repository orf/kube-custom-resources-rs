// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kumahq/kuma/kuma.io/v1alpha1/meshloadbalancingstrategies.yaml --derive=PartialEq
// kopium version: 0.16.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

/// Spec is the specification of the Kuma MeshLoadBalancingStrategy resource.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "kuma.io", version = "v1alpha1", kind = "MeshLoadBalancingStrategy", plural = "meshloadbalancingstrategies")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct MeshLoadBalancingStrategySpec {
    /// TargetRef is a reference to the resource the policy takes an effect on. The resource could be either a real store object or virtual resource defined inplace.
    #[serde(rename = "targetRef")]
    pub target_ref: MeshLoadBalancingStrategyTargetRef,
    /// To list makes a match between the consumed services and corresponding configurations
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<Vec<MeshLoadBalancingStrategyTo>>,
}

/// TargetRef is a reference to the resource the policy takes an effect on. The resource could be either a real store object or virtual resource defined inplace.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyTargetRef {
    /// Kind of the referenced resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<MeshLoadBalancingStrategyTargetRefKind>,
    /// Mesh is reserved for future use to identify cross mesh resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh: Option<String>,
    /// Name of the referenced resource. Can only be used with kinds: `MeshService`, `MeshServiceSubset` and `MeshGatewayRoute`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Tags used to select a subset of proxies by tags. Can only be used with kinds `MeshSubset` and `MeshServiceSubset`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,
}

/// TargetRef is a reference to the resource the policy takes an effect on. The resource could be either a real store object or virtual resource defined inplace.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum MeshLoadBalancingStrategyTargetRefKind {
    Mesh,
    MeshSubset,
    MeshGateway,
    MeshService,
    MeshServiceSubset,
    #[serde(rename = "MeshHTTPRoute")]
    MeshHttpRoute,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyTo {
    /// Default is a configuration specific to the group of destinations referenced in 'targetRef'
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<MeshLoadBalancingStrategyToDefault>,
    /// TargetRef is a reference to the resource that represents a group of destinations.
    #[serde(rename = "targetRef")]
    pub target_ref: MeshLoadBalancingStrategyToTargetRef,
}

/// Default is a configuration specific to the group of destinations referenced in 'targetRef'
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefault {
    /// LoadBalancer allows to specify load balancing algorithm.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "loadBalancer")]
    pub load_balancer: Option<MeshLoadBalancingStrategyToDefaultLoadBalancer>,
    /// LocalityAwareness contains configuration for locality aware load balancing.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "localityAwareness")]
    pub locality_awareness: Option<MeshLoadBalancingStrategyToDefaultLocalityAwareness>,
}

/// LoadBalancer allows to specify load balancing algorithm.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLoadBalancer {
    /// LeastRequest selects N random available hosts as specified in 'choiceCount' (2 by default) and picks the host which has the fewest active requests
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "leastRequest")]
    pub least_request: Option<MeshLoadBalancingStrategyToDefaultLoadBalancerLeastRequest>,
    /// Maglev implements consistent hashing to upstream hosts. Maglev can be used as a drop in replacement for the ring hash load balancer any place in which consistent hashing is desired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maglev: Option<MeshLoadBalancingStrategyToDefaultLoadBalancerMaglev>,
    /// Random selects a random available host. The random load balancer generally performs better than round-robin if no health checking policy is configured. Random selection avoids bias towards the host in the set that comes after a failed host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub random: Option<MeshLoadBalancingStrategyToDefaultLoadBalancerRandom>,
    /// RingHash  implements consistent hashing to upstream hosts. Each host is mapped onto a circle (the “ring”) by hashing its address; each request is then routed to a host by hashing some property of the request, and finding the nearest corresponding host clockwise around the ring.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ringHash")]
    pub ring_hash: Option<MeshLoadBalancingStrategyToDefaultLoadBalancerRingHash>,
    /// RoundRobin is a load balancing algorithm that distributes requests across available upstream hosts in round-robin order.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "roundRobin")]
    pub round_robin: Option<MeshLoadBalancingStrategyToDefaultLoadBalancerRoundRobin>,
    #[serde(rename = "type")]
    pub r#type: MeshLoadBalancingStrategyToDefaultLoadBalancerType,
}

/// LeastRequest selects N random available hosts as specified in 'choiceCount' (2 by default) and picks the host which has the fewest active requests
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLoadBalancerLeastRequest {
    /// ActiveRequestBias refers to dynamic weights applied when hosts have varying load balancing weights. A higher value here aggressively reduces the weight of endpoints that are currently handling active requests. In essence, the higher the ActiveRequestBias value, the more forcefully it reduces the load balancing weight of endpoints that are actively serving requests.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "activeRequestBias")]
    pub active_request_bias: Option<IntOrString>,
    /// ChoiceCount is the number of random healthy hosts from which the host with the fewest active requests will be chosen. Defaults to 2 so that Envoy performs two-choice selection if the field is not set.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "choiceCount")]
    pub choice_count: Option<i32>,
}

/// Maglev implements consistent hashing to upstream hosts. Maglev can be used as a drop in replacement for the ring hash load balancer any place in which consistent hashing is desired.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLoadBalancerMaglev {
    /// HashPolicies specify a list of request/connection properties that are used to calculate a hash. These hash policies are executed in the specified order. If a hash policy has the “terminal” attribute set to true, and there is already a hash generated, the hash is returned immediately, ignoring the rest of the hash policy list.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "hashPolicies")]
    pub hash_policies: Option<Vec<MeshLoadBalancingStrategyToDefaultLoadBalancerMaglevHashPolicies>>,
    /// The table size for Maglev hashing. Maglev aims for “minimal disruption” rather than an absolute guarantee. Minimal disruption means that when the set of upstream hosts change, a connection will likely be sent to the same upstream as it was before. Increasing the table size reduces the amount of disruption. The table size must be prime number limited to 5000011. If it is not specified, the default is 65537.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "tableSize")]
    pub table_size: Option<i32>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLoadBalancerMaglevHashPolicies {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<MeshLoadBalancingStrategyToDefaultLoadBalancerMaglevHashPoliciesConnection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie: Option<MeshLoadBalancingStrategyToDefaultLoadBalancerMaglevHashPoliciesCookie>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "filterState")]
    pub filter_state: Option<MeshLoadBalancingStrategyToDefaultLoadBalancerMaglevHashPoliciesFilterState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<MeshLoadBalancingStrategyToDefaultLoadBalancerMaglevHashPoliciesHeader>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "queryParameter")]
    pub query_parameter: Option<MeshLoadBalancingStrategyToDefaultLoadBalancerMaglevHashPoliciesQueryParameter>,
    /// Terminal is a flag that short-circuits the hash computing. This field provides a ‘fallback’ style of configuration: “if a terminal policy doesn’t work, fallback to rest of the policy list”, it saves time when the terminal policy works. If true, and there is already a hash computed, ignore rest of the list of hash polices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<bool>,
    #[serde(rename = "type")]
    pub r#type: MeshLoadBalancingStrategyToDefaultLoadBalancerMaglevHashPoliciesType,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLoadBalancerMaglevHashPoliciesConnection {
    /// Hash on source IP address.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sourceIP")]
    pub source_ip: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLoadBalancerMaglevHashPoliciesCookie {
    /// The name of the cookie that will be used to obtain the hash key.
    pub name: String,
    /// The name of the path for the cookie.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// If specified, a cookie with the TTL will be generated if the cookie is not present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLoadBalancerMaglevHashPoliciesFilterState {
    /// The name of the Object in the per-request filterState, which is an Envoy::Hashable object. If there is no data associated with the key, or the stored object is not Envoy::Hashable, no hash will be produced.
    pub key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLoadBalancerMaglevHashPoliciesHeader {
    /// The name of the request header that will be used to obtain the hash key.
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLoadBalancerMaglevHashPoliciesQueryParameter {
    /// The name of the URL query parameter that will be used to obtain the hash key. If the parameter is not present, no hash will be produced. Query parameter names are case-sensitive.
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum MeshLoadBalancingStrategyToDefaultLoadBalancerMaglevHashPoliciesType {
    Header,
    Cookie,
    #[serde(rename = "SourceIP")]
    SourceIp,
    QueryParameter,
    FilterState,
}

/// Random selects a random available host. The random load balancer generally performs better than round-robin if no health checking policy is configured. Random selection avoids bias towards the host in the set that comes after a failed host.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLoadBalancerRandom {
}

/// RingHash  implements consistent hashing to upstream hosts. Each host is mapped onto a circle (the “ring”) by hashing its address; each request is then routed to a host by hashing some property of the request, and finding the nearest corresponding host clockwise around the ring.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLoadBalancerRingHash {
    /// HashFunction is a function used to hash hosts onto the ketama ring. The value defaults to XX_HASH. Available values – XX_HASH, MURMUR_HASH_2.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "hashFunction")]
    pub hash_function: Option<MeshLoadBalancingStrategyToDefaultLoadBalancerRingHashHashFunction>,
    /// HashPolicies specify a list of request/connection properties that are used to calculate a hash. These hash policies are executed in the specified order. If a hash policy has the “terminal” attribute set to true, and there is already a hash generated, the hash is returned immediately, ignoring the rest of the hash policy list.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "hashPolicies")]
    pub hash_policies: Option<Vec<MeshLoadBalancingStrategyToDefaultLoadBalancerRingHashHashPolicies>>,
    /// Maximum hash ring size. Defaults to 8M entries, and limited to 8M entries, but can be lowered to further constrain resource use.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxRingSize")]
    pub max_ring_size: Option<i32>,
    /// Minimum hash ring size. The larger the ring is (that is, the more hashes there are for each provided host) the better the request distribution will reflect the desired weights. Defaults to 1024 entries, and limited to 8M entries.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "minRingSize")]
    pub min_ring_size: Option<i32>,
}

/// RingHash  implements consistent hashing to upstream hosts. Each host is mapped onto a circle (the “ring”) by hashing its address; each request is then routed to a host by hashing some property of the request, and finding the nearest corresponding host clockwise around the ring.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum MeshLoadBalancingStrategyToDefaultLoadBalancerRingHashHashFunction {
    #[serde(rename = "XXHash")]
    XxHash,
    MurmurHash2,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLoadBalancerRingHashHashPolicies {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<MeshLoadBalancingStrategyToDefaultLoadBalancerRingHashHashPoliciesConnection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie: Option<MeshLoadBalancingStrategyToDefaultLoadBalancerRingHashHashPoliciesCookie>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "filterState")]
    pub filter_state: Option<MeshLoadBalancingStrategyToDefaultLoadBalancerRingHashHashPoliciesFilterState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<MeshLoadBalancingStrategyToDefaultLoadBalancerRingHashHashPoliciesHeader>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "queryParameter")]
    pub query_parameter: Option<MeshLoadBalancingStrategyToDefaultLoadBalancerRingHashHashPoliciesQueryParameter>,
    /// Terminal is a flag that short-circuits the hash computing. This field provides a ‘fallback’ style of configuration: “if a terminal policy doesn’t work, fallback to rest of the policy list”, it saves time when the terminal policy works. If true, and there is already a hash computed, ignore rest of the list of hash polices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<bool>,
    #[serde(rename = "type")]
    pub r#type: MeshLoadBalancingStrategyToDefaultLoadBalancerRingHashHashPoliciesType,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLoadBalancerRingHashHashPoliciesConnection {
    /// Hash on source IP address.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sourceIP")]
    pub source_ip: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLoadBalancerRingHashHashPoliciesCookie {
    /// The name of the cookie that will be used to obtain the hash key.
    pub name: String,
    /// The name of the path for the cookie.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// If specified, a cookie with the TTL will be generated if the cookie is not present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLoadBalancerRingHashHashPoliciesFilterState {
    /// The name of the Object in the per-request filterState, which is an Envoy::Hashable object. If there is no data associated with the key, or the stored object is not Envoy::Hashable, no hash will be produced.
    pub key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLoadBalancerRingHashHashPoliciesHeader {
    /// The name of the request header that will be used to obtain the hash key.
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLoadBalancerRingHashHashPoliciesQueryParameter {
    /// The name of the URL query parameter that will be used to obtain the hash key. If the parameter is not present, no hash will be produced. Query parameter names are case-sensitive.
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum MeshLoadBalancingStrategyToDefaultLoadBalancerRingHashHashPoliciesType {
    Header,
    Cookie,
    #[serde(rename = "SourceIP")]
    SourceIp,
    QueryParameter,
    FilterState,
}

/// RoundRobin is a load balancing algorithm that distributes requests across available upstream hosts in round-robin order.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLoadBalancerRoundRobin {
}

/// LoadBalancer allows to specify load balancing algorithm.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum MeshLoadBalancingStrategyToDefaultLoadBalancerType {
    RoundRobin,
    LeastRequest,
    RingHash,
    Random,
    Maglev,
}

/// LocalityAwareness contains configuration for locality aware load balancing.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLocalityAwareness {
    /// CrossZone defines locality aware load balancing priorities when dataplane proxies inside local zone are unavailable
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "crossZone")]
    pub cross_zone: Option<MeshLoadBalancingStrategyToDefaultLocalityAwarenessCrossZone>,
    /// Disabled allows to disable locality-aware load balancing. When disabled requests are distributed across all endpoints regardless of locality.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    /// LocalZone defines locality aware load balancing priorities between dataplane proxies inside a zone
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "localZone")]
    pub local_zone: Option<MeshLoadBalancingStrategyToDefaultLocalityAwarenessLocalZone>,
}

/// CrossZone defines locality aware load balancing priorities when dataplane proxies inside local zone are unavailable
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLocalityAwarenessCrossZone {
    /// Failover defines list of load balancing rules in order of priority
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failover: Option<Vec<MeshLoadBalancingStrategyToDefaultLocalityAwarenessCrossZoneFailover>>,
    /// FailoverThreshold defines the percentage of live destination dataplane proxies below which load balancing to the next priority starts. Example: If you configure failoverThreshold to 70, and you have deployed 10 destination dataplane proxies. Load balancing to next priority will start when number of live destination dataplane proxies drops below 7. Default 50
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "failoverThreshold")]
    pub failover_threshold: Option<MeshLoadBalancingStrategyToDefaultLocalityAwarenessCrossZoneFailoverThreshold>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLocalityAwarenessCrossZoneFailover {
    /// From defines the list of zones to which the rule applies
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<MeshLoadBalancingStrategyToDefaultLocalityAwarenessCrossZoneFailoverFrom>,
    /// To defines to which zones the traffic should be load balanced
    pub to: MeshLoadBalancingStrategyToDefaultLocalityAwarenessCrossZoneFailoverTo,
}

/// From defines the list of zones to which the rule applies
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLocalityAwarenessCrossZoneFailoverFrom {
    pub zones: Vec<String>,
}

/// To defines to which zones the traffic should be load balanced
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLocalityAwarenessCrossZoneFailoverTo {
    /// Type defines how target zones will be picked from available zones
    #[serde(rename = "type")]
    pub r#type: MeshLoadBalancingStrategyToDefaultLocalityAwarenessCrossZoneFailoverToType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zones: Option<Vec<String>>,
}

/// To defines to which zones the traffic should be load balanced
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum MeshLoadBalancingStrategyToDefaultLocalityAwarenessCrossZoneFailoverToType {
    None,
    Only,
    Any,
    AnyExcept,
}

/// FailoverThreshold defines the percentage of live destination dataplane proxies below which load balancing to the next priority starts. Example: If you configure failoverThreshold to 70, and you have deployed 10 destination dataplane proxies. Load balancing to next priority will start when number of live destination dataplane proxies drops below 7. Default 50
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLocalityAwarenessCrossZoneFailoverThreshold {
    pub percentage: IntOrString,
}

/// LocalZone defines locality aware load balancing priorities between dataplane proxies inside a zone
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLocalityAwarenessLocalZone {
    /// AffinityTags list of tags for local zone load balancing.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "affinityTags")]
    pub affinity_tags: Option<Vec<MeshLoadBalancingStrategyToDefaultLocalityAwarenessLocalZoneAffinityTags>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToDefaultLocalityAwarenessLocalZoneAffinityTags {
    /// Key defines tag for which affinity is configured
    pub key: String,
    /// Weight of the tag used for load balancing. The bigger the weight the bigger the priority. Percentage of local traffic load balanced to tag is computed by dividing weight by sum of weights from all tags. For example with two affinity tags first with weight 80 and second with weight 20, then 80% of traffic will be redirected to the first tag, and 20% of traffic will be redirected to second one. Setting weights is not mandatory. When weights are not set control plane will compute default weight based on list order. Default: If you do not specify weight we will adjust them so that 90% traffic goes to first tag, 9% to next, and 1% to third and so on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<i32>,
}

/// TargetRef is a reference to the resource that represents a group of destinations.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MeshLoadBalancingStrategyToTargetRef {
    /// Kind of the referenced resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<MeshLoadBalancingStrategyToTargetRefKind>,
    /// Mesh is reserved for future use to identify cross mesh resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh: Option<String>,
    /// Name of the referenced resource. Can only be used with kinds: `MeshService`, `MeshServiceSubset` and `MeshGatewayRoute`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Tags used to select a subset of proxies by tags. Can only be used with kinds `MeshSubset` and `MeshServiceSubset`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,
}

/// TargetRef is a reference to the resource that represents a group of destinations.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum MeshLoadBalancingStrategyToTargetRefKind {
    Mesh,
    MeshSubset,
    MeshGateway,
    MeshService,
    MeshServiceSubset,
    #[serde(rename = "MeshHTTPRoute")]
    MeshHttpRoute,
}
