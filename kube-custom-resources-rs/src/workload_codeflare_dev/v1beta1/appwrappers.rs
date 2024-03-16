// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/project-codeflare/codeflare-operator/workload.codeflare.dev/v1beta1/appwrappers.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// AppWrapperSpec describes how the App Wrapper will look like.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "workload.codeflare.dev", version = "v1beta1", kind = "AppWrapper", plural = "appwrappers")]
#[kube(namespaced)]
#[kube(status = "AppWrapperStatus")]
#[kube(schema = "disabled")]
pub struct AppWrapperSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priorityslope: Option<f32>,
    /// a collection of AppWrapperResource
    pub resources: AppWrapperResources,
    /// SchedSpec specifies the parameters used for scheduling generic items wrapped inside AppWrappers. It defines the policy for requeuing jobs based on the number of running pods.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "schedulingSpec")]
    pub scheduling_spec: Option<AppWrapperSchedulingSpec>,
    /// A label selector is a label query over a set of resources. The result of matchLabels and matchExpressions are ANDed. An empty label selector matches all objects. A null label selector matches no objects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<AppWrapperSelector>,
    /// AppWrapperService is App Wrapper service definition
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<AppWrapperService>,
}

/// a collection of AppWrapperResource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AppWrapperResources {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "GenericItems")]
    pub generic_items: Option<Vec<AppWrapperResourcesGenericItems>>,
}

/// AppWrapperGenericResource is App Wrapper aggregation resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AppWrapperResourcesGenericItems {
    /// The number of allocated replicas from this resource type
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocated: Option<i32>,
    /// Optional field that drives completion status of this AppWrapper. This field within an item of an AppWrapper determines the full state of the AppWrapper. The completionstatus field contains a list of conditions that make the associate item considered completed, for instance: - completion conditions could be "Complete" or "Failed". The associated item's level .status.conditions[].type field is monitored for any one of these conditions. Once all items with this option is set and the conditionstatus is met the entire AppWrapper state will be changed to one of the valid AppWrapper completion state. Note: - this is an AND operation for all items where this option is set. See the list of AppWrapper states for a list of valid complete states.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completionstatus: Option<String>,
    /// Optional section that specifies resource requirements for non-standard k8s resources, follows same format as that of standard k8s resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custompodresources: Option<Vec<AppWrapperResourcesGenericItemsCustompodresources>>,
    /// The template for the resource; it is now a raw text because we don't know for what resource it should be instantiated
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generictemplate: Option<BTreeMap<String, serde_json::Value>>,
    /// The minimal available pods to run for this AppWrapper; the default value is nil
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minavailable: Option<i32>,
    /// The priority of this resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
    /// The increasing rate of priority value for this resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priorityslope: Option<f32>,
    /// Replicas is the number of desired replicas
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<i32>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AppWrapperResourcesGenericItemsCustompodresources {
    /// ResourceList is a set of (resource name, quantity) pairs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<BTreeMap<String, IntOrString>>,
    pub replicas: i64,
    /// todo: replace with Containers []Container Contain v1.ResourceRequirements
    pub requests: BTreeMap<String, IntOrString>,
}

/// SchedSpec specifies the parameters used for scheduling generic items wrapped inside AppWrappers. It defines the policy for requeuing jobs based on the number of running pods.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AppWrapperSchedulingSpec {
    /// Wall clock duration time of appwrapper in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dispatchDuration")]
    pub dispatch_duration: Option<AppWrapperSchedulingSpecDispatchDuration>,
    /// Expected number of pods in running and/or completed state. Requeuing is triggered when the number of running/completed pods is not equal to this value. When not specified, requeuing is disabled and no check is performed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "minAvailable")]
    pub min_available: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nodeSelector")]
    pub node_selector: Option<BTreeMap<String, String>>,
    /// Specification of the requeuing strategy based on waiting time. Values in this field control how often the pod check should happen, and if requeuing has reached its maximum number of times.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requeuing: Option<AppWrapperSchedulingSpecRequeuing>,
}

/// Wall clock duration time of appwrapper in seconds.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AppWrapperSchedulingSpecDispatchDuration {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overrun: Option<bool>,
}

/// Specification of the requeuing strategy based on waiting time. Values in this field control how often the pod check should happen, and if requeuing has reached its maximum number of times.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AppWrapperSchedulingSpecRequeuing {
    /// Growth strategy to increase the waiting time between requeuing checks. The values available are 'exponential', 'linear', or 'none'. For example, 'exponential' growth would double the 'timeInSeconds' value every time a requeuing event is triggered. If the string value is misspelled or not one of the possible options, the growth behavior is defaulted to 'none'.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "growthType")]
    pub growth_type: Option<String>,
    /// Value to keep track of the initial wait time. Users cannot set this as it is taken from 'timeInSeconds'.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "initialTimeInSeconds")]
    pub initial_time_in_seconds: Option<i64>,
    /// Maximum number of requeuing events allowed. Once this value is reached (e.g., 'numRequeuings = maxNumRequeuings', no more requeuing checks are performed and the generic items are stopped and removed from the cluster (AppWrapper remains deployed).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxNumRequeuings")]
    pub max_num_requeuings: Option<i64>,
    /// Maximum waiting time for requeuing checks.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxTimeInSeconds")]
    pub max_time_in_seconds: Option<i64>,
    /// Field to keep track of how many times a requeuing event has been triggered.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "numRequeuings")]
    pub num_requeuings: Option<i64>,
    /// Initial waiting time before requeuing conditions are checked. This value is specified by the user, but it may grow as requeuing events happen.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "timeInSeconds")]
    pub time_in_seconds: Option<i64>,
}

/// A label selector is a label query over a set of resources. The result of matchLabels and matchExpressions are ANDed. An empty label selector matches all objects. A null label selector matches no objects.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AppWrapperSelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<AppWrapperSelectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AppWrapperSelectorMatchExpressions {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// AppWrapperService is App Wrapper service definition
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AppWrapperService {
    /// ServiceSpec describes the attributes that a user creates on a service.
    pub spec: AppWrapperServiceSpec,
}

/// ServiceSpec describes the attributes that a user creates on a service.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AppWrapperServiceSpec {
    /// allocateLoadBalancerNodePorts defines if NodePorts will be automatically allocated for services with type LoadBalancer.  Default is "true". It may be set to "false" if the cluster load-balancer does not rely on NodePorts.  If the caller requests specific NodePorts (by specifying a value), those requests will be respected, regardless of this field. This field may only be set for services with type LoadBalancer and will be cleared if the type is changed to any other type.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "allocateLoadBalancerNodePorts")]
    pub allocate_load_balancer_node_ports: Option<bool>,
    /// clusterIP is the IP address of the service and is usually assigned randomly. If an address is specified manually, is in-range (as per system configuration), and is not in use, it will be allocated to the service; otherwise creation of the service will fail. This field may not be changed through updates unless the type field is also being changed to ExternalName (which requires this field to be blank) or the type field is being changed from ExternalName (in which case this field may optionally be specified, as describe above).  Valid values are "None", empty string (""), or a valid IP address. Setting this to "None" makes a "headless service" (no virtual IP), which is useful when direct endpoint connections are preferred and proxying is not required.  Only applies to types ClusterIP, NodePort, and LoadBalancer. If this field is specified when creating a Service of type ExternalName, creation will fail. This field will be wiped when updating a Service to type ExternalName. More info: https://kubernetes.io/docs/concepts/services-networking/service/#virtual-ips-and-service-proxies
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clusterIP")]
    pub cluster_ip: Option<String>,
    /// ClusterIPs is a list of IP addresses assigned to this service, and are usually assigned randomly.  If an address is specified manually, is in-range (as per system configuration), and is not in use, it will be allocated to the service; otherwise creation of the service will fail. This field may not be changed through updates unless the type field is also being changed to ExternalName (which requires this field to be empty) or the type field is being changed from ExternalName (in which case this field may optionally be specified, as describe above).  Valid values are "None", empty string (""), or a valid IP address.  Setting this to "None" makes a "headless service" (no virtual IP), which is useful when direct endpoint connections are preferred and proxying is not required.  Only applies to types ClusterIP, NodePort, and LoadBalancer. If this field is specified when creating a Service of type ExternalName, creation will fail. This field will be wiped when updating a Service to type ExternalName.  If this field is not specified, it will be initialized from the clusterIP field.  If this field is specified, clients must ensure that clusterIPs[0] and clusterIP have the same value. 
    ///  This field may hold a maximum of two entries (dual-stack IPs, in either order). These IPs must correspond to the values of the ipFamilies field. Both clusterIPs and ipFamilies are governed by the ipFamilyPolicy field. More info: https://kubernetes.io/docs/concepts/services-networking/service/#virtual-ips-and-service-proxies
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clusterIPs")]
    pub cluster_i_ps: Option<Vec<String>>,
    /// externalIPs is a list of IP addresses for which nodes in the cluster will also accept traffic for this service.  These IPs are not managed by Kubernetes.  The user is responsible for ensuring that traffic arrives at a node with this IP.  A common example is external load-balancers that are not part of the Kubernetes system.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "externalIPs")]
    pub external_i_ps: Option<Vec<String>>,
    /// externalName is the external reference that discovery mechanisms will return as an alias for this service (e.g. a DNS CNAME record). No proxying will be involved.  Must be a lowercase RFC-1123 hostname (https://tools.ietf.org/html/rfc1123) and requires `type` to be "ExternalName".
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "externalName")]
    pub external_name: Option<String>,
    /// externalTrafficPolicy describes how nodes distribute service traffic they receive on one of the Service's "externally-facing" addresses (NodePorts, ExternalIPs, and LoadBalancer IPs). If set to "Local", the proxy will configure the service in a way that assumes that external load balancers will take care of balancing the service traffic between nodes, and so each node will deliver traffic only to the node-local endpoints of the service, without masquerading the client source IP. (Traffic mistakenly sent to a node with no endpoints will be dropped.) The default value, "Cluster", uses the standard behavior of routing to all endpoints evenly (possibly modified by topology and other features). Note that traffic sent to an External IP or LoadBalancer IP from within the cluster will always get "Cluster" semantics, but clients sending to a NodePort from within the cluster may need to take traffic policy into account when picking a node.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "externalTrafficPolicy")]
    pub external_traffic_policy: Option<String>,
    /// healthCheckNodePort specifies the healthcheck nodePort for the service. This only applies when type is set to LoadBalancer and externalTrafficPolicy is set to Local. If a value is specified, is in-range, and is not in use, it will be used.  If not specified, a value will be automatically allocated.  External systems (e.g. load-balancers) can use this port to determine if a given node holds endpoints for this service or not.  If this field is specified when creating a Service which does not need it, creation will fail. This field will be wiped when updating a Service to no longer need it (e.g. changing type). This field cannot be updated once set.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "healthCheckNodePort")]
    pub health_check_node_port: Option<i32>,
    /// InternalTrafficPolicy describes how nodes distribute service traffic they receive on the ClusterIP. If set to "Local", the proxy will assume that pods only want to talk to endpoints of the service on the same node as the pod, dropping the traffic if there are no local endpoints. The default value, "Cluster", uses the standard behavior of routing to all endpoints evenly (possibly modified by topology and other features).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "internalTrafficPolicy")]
    pub internal_traffic_policy: Option<String>,
    /// IPFamilies is a list of IP families (e.g. IPv4, IPv6) assigned to this service. This field is usually assigned automatically based on cluster configuration and the ipFamilyPolicy field. If this field is specified manually, the requested family is available in the cluster, and ipFamilyPolicy allows it, it will be used; otherwise creation of the service will fail. This field is conditionally mutable: it allows for adding or removing a secondary IP family, but it does not allow changing the primary IP family of the Service. Valid values are "IPv4" and "IPv6".  This field only applies to Services of types ClusterIP, NodePort, and LoadBalancer, and does apply to "headless" services. This field will be wiped when updating a Service to type ExternalName. 
    ///  This field may hold a maximum of two entries (dual-stack families, in either order).  These families must correspond to the values of the clusterIPs field, if specified. Both clusterIPs and ipFamilies are governed by the ipFamilyPolicy field.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ipFamilies")]
    pub ip_families: Option<Vec<String>>,
    /// IPFamilyPolicy represents the dual-stack-ness requested or required by this Service. If there is no value provided, then this field will be set to SingleStack. Services can be "SingleStack" (a single IP family), "PreferDualStack" (two IP families on dual-stack configured clusters or a single IP family on single-stack clusters), or "RequireDualStack" (two IP families on dual-stack configured clusters, otherwise fail). The ipFamilies and clusterIPs fields depend on the value of this field. This field will be wiped when updating a service to type ExternalName.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ipFamilyPolicy")]
    pub ip_family_policy: Option<String>,
    /// loadBalancerClass is the class of the load balancer implementation this Service belongs to. If specified, the value of this field must be a label-style identifier, with an optional prefix, e.g. "internal-vip" or "example.com/internal-vip". Unprefixed names are reserved for end-users. This field can only be set when the Service type is 'LoadBalancer'. If not set, the default load balancer implementation is used, today this is typically done through the cloud provider integration, but should apply for any default implementation. If set, it is assumed that a load balancer implementation is watching for Services with a matching class. Any default load balancer implementation (e.g. cloud providers) should ignore Services that set this field. This field can only be set when creating or updating a Service to type 'LoadBalancer'. Once set, it can not be changed. This field will be wiped when a service is updated to a non 'LoadBalancer' type.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "loadBalancerClass")]
    pub load_balancer_class: Option<String>,
    /// Only applies to Service Type: LoadBalancer. This feature depends on whether the underlying cloud-provider supports specifying the loadBalancerIP when a load balancer is created. This field will be ignored if the cloud-provider does not support the feature. Deprecated: This field was under-specified and its meaning varies across implementations, and it cannot support dual-stack. As of Kubernetes v1.24, users are encouraged to use implementation-specific annotations when available. This field may be removed in a future API version.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "loadBalancerIP")]
    pub load_balancer_ip: Option<String>,
    /// If specified and supported by the platform, this will restrict traffic through the cloud-provider load-balancer will be restricted to the specified client IPs. This field will be ignored if the cloud-provider does not support the feature." More info: https://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "loadBalancerSourceRanges")]
    pub load_balancer_source_ranges: Option<Vec<String>>,
    /// The list of ports that are exposed by this service. More info: https://kubernetes.io/docs/concepts/services-networking/service/#virtual-ips-and-service-proxies
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<AppWrapperServiceSpecPorts>>,
    /// publishNotReadyAddresses indicates that any agent which deals with endpoints for this Service should disregard any indications of ready/not-ready. The primary use case for setting this field is for a StatefulSet's Headless Service to propagate SRV DNS records for its Pods for the purpose of peer discovery. The Kubernetes controllers that generate Endpoints and EndpointSlice resources for Services interpret this to mean that all endpoints are considered "ready" even if the Pods themselves are not. Agents which consume only Kubernetes generated endpoints through the Endpoints or EndpointSlice resources can safely assume this behavior.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "publishNotReadyAddresses")]
    pub publish_not_ready_addresses: Option<bool>,
    /// Route service traffic to pods with label keys and values matching this selector. If empty or not present, the service is assumed to have an external process managing its endpoints, which Kubernetes will not modify. Only applies to types ClusterIP, NodePort, and LoadBalancer. Ignored if type is ExternalName. More info: https://kubernetes.io/docs/concepts/services-networking/service/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<BTreeMap<String, String>>,
    /// Supports "ClientIP" and "None". Used to maintain session affinity. Enable client IP based session affinity. Must be ClientIP or None. Defaults to None. More info: https://kubernetes.io/docs/concepts/services-networking/service/#virtual-ips-and-service-proxies
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sessionAffinity")]
    pub session_affinity: Option<String>,
    /// sessionAffinityConfig contains the configurations of session affinity.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sessionAffinityConfig")]
    pub session_affinity_config: Option<AppWrapperServiceSpecSessionAffinityConfig>,
    /// type determines how the Service is exposed. Defaults to ClusterIP. Valid options are ExternalName, ClusterIP, NodePort, and LoadBalancer. "ClusterIP" allocates a cluster-internal IP address for load-balancing to endpoints. Endpoints are determined by the selector or if that is not specified, by manual construction of an Endpoints object or EndpointSlice objects. If clusterIP is "None", no virtual IP is allocated and the endpoints are published as a set of endpoints rather than a virtual IP. "NodePort" builds on ClusterIP and allocates a port on every node which routes to the same endpoints as the clusterIP. "LoadBalancer" builds on NodePort and creates an external load-balancer (if supported in the current cloud) which routes to the same endpoints as the clusterIP. "ExternalName" aliases this service to the specified externalName. Several other fields do not apply to ExternalName services. More info: https://kubernetes.io/docs/concepts/services-networking/service/#publishing-services-service-types
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
}

/// ServicePort contains information on service's port.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AppWrapperServiceSpecPorts {
    /// The application protocol for this port. This field follows standard Kubernetes label syntax. Un-prefixed names are reserved for IANA standard service names (as per RFC-6335 and https://www.iana.org/assignments/service-names). Non-standard protocols should use prefixed names such as mycompany.com/my-custom-protocol.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "appProtocol")]
    pub app_protocol: Option<String>,
    /// The name of this port within the service. This must be a DNS_LABEL. All ports within a ServiceSpec must have unique names. When considering the endpoints for a Service, this must match the 'name' field in the EndpointPort. Optional if only one ServicePort is defined on this service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The port on each node on which this service is exposed when type is NodePort or LoadBalancer.  Usually assigned by the system. If a value is specified, in-range, and not in use it will be used, otherwise the operation will fail.  If not specified, a port will be allocated if this Service requires one.  If this field is specified when creating a Service which does not need it, creation will fail. This field will be wiped when updating a Service to no longer need it (e.g. changing type from NodePort to ClusterIP). More info: https://kubernetes.io/docs/concepts/services-networking/service/#type-nodeport
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nodePort")]
    pub node_port: Option<i32>,
    /// The port that will be exposed by this service.
    pub port: i32,
    /// The IP protocol for this port. Supports "TCP", "UDP", and "SCTP". Default is TCP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Number or name of the port to access on the pods targeted by the service. Number must be in the range 1 to 65535. Name must be an IANA_SVC_NAME. If this is a string, it will be looked up as a named port in the target Pod's container ports. If this is not specified, the value of the 'port' field is used (an identity map). This field is ignored for services with clusterIP=None, and should be omitted or set equal to the 'port' field. More info: https://kubernetes.io/docs/concepts/services-networking/service/#defining-a-service
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "targetPort")]
    pub target_port: Option<IntOrString>,
}

/// sessionAffinityConfig contains the configurations of session affinity.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AppWrapperServiceSpecSessionAffinityConfig {
    /// clientIP contains the configurations of Client IP based session affinity.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clientIP")]
    pub client_ip: Option<AppWrapperServiceSpecSessionAffinityConfigClientIp>,
}

/// clientIP contains the configurations of Client IP based session affinity.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AppWrapperServiceSpecSessionAffinityConfigClientIp {
    /// timeoutSeconds specifies the seconds of ClientIP type session sticky time. The value must be >0 && <=86400(for 1 day) if ServiceAffinity == "ClientIP". Default value is 10800(for 3 hours).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "timeoutSeconds")]
    pub timeout_seconds: Option<i32>,
}

/// AppWrapperStatus represents the current state of a AppWrapper
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AppWrapperStatus {
    /// The number of resources which reached phase Succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Succeeded")]
    pub succeeded: Option<i32>,
    /// Can run?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canrun: Option<bool>,
    /// Represents the latest available observations of the AppWrapper's current condition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<AppWrapperStatusConditions>>,
    /// Microsecond level timestamp when controller first dispatches the AppWrapper
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controllerfirstdispatchtimestamp: Option<String>,
    /// Microsecond level timestamp when controller first sees QueueJob (by Informer)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controllerfirsttimestamp: Option<String>,
    /// The number of resources which reached phase Failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<i32>,
    /// Tell Informer to ignore this update message (do not generate a controller event)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filterignore: Option<bool>,
    /// Is Dispatched?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isdispatched: Option<bool>,
    /// Indicate if message is a duplicate (for Informer to recognize duplicate messages)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Field to keep track of how many times a requeuing event has been triggered
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "numberOfRequeueings")]
    pub number_of_requeueings: Option<i64>,
    /// The number of pending pods.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<i32>,
    /// Represents the latest available observations of pods belonging to the AppWrapper.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pendingpodconditions: Option<Vec<AppWrapperStatusPendingpodconditions>>,
    /// State of QueueJob - Init, Queueing, HeadOfLine, Rejoining, ...
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queuejobstate: Option<String>,
    /// Field to keep track of total number of seconds spent in requeueing
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "requeueingTimeInSeconds")]
    pub requeueing_time_in_seconds: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub running: Option<i32>,
    /// Indicate sender of this message (extremely useful for debugging)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    /// State - Pending, Running, Failed, Deleted
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// System defined Priority
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub systempriority: Option<f32>,
    /// The minimal available resources to run for this AppWrapper (is this different from the MinAvailable from JobStatus)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<i32>,
    /// The number of CPU consumed by all pods belonging to the AppWrapper.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totalcpu: Option<i32>,
    /// The total number of GPUs consumed by all pods belonging to the AppWrapper.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totalgpu: Option<i32>,
    /// The amount of memory consumed by all pods belonging to the AppWrapper.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totalmemory: Option<i32>,
}

/// AppWrapperCondition describes the state of an AppWrapper at a certain point.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AppWrapperStatusConditions {
    /// Last time the condition transitioned from one status to another.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastTransitionMicroTime")]
    pub last_transition_micro_time: Option<String>,
    /// The last time this condition was updated.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastUpdateMicroTime")]
    pub last_update_micro_time: Option<String>,
    /// A human-readable message indicating details about the transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// The reason for the condition's last transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Status of the condition, one of True, False, Unknown.
    pub status: String,
    /// Type of AppWrapper condition.
    #[serde(rename = "type")]
    pub r#type: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AppWrapperStatusPendingpodconditions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub podname: Option<String>,
}

