// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/clusternet/clusternet/clusters.clusternet.io/v1beta1/managedclusters.yaml --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use std::collections::BTreeMap;
    pub use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
    pub use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
}
use self::prelude::*;

/// ManagedClusterSpec defines the desired state of ManagedCluster
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "clusters.clusternet.io", version = "v1beta1", kind = "ManagedCluster", plural = "managedclusters")]
#[kube(namespaced)]
#[kube(status = "ManagedClusterStatus")]
#[kube(schema = "disabled")]
#[kube(derive="PartialEq")]
pub struct ManagedClusterSpec {
    /// ClusterID, a Random (Version 4) UUID, is a unique value in time and space value representing for child cluster.
    /// It is typically generated by the clusternet agent on the successful creation of a "clusternet-agent" Lease
    /// in the child cluster.
    /// Also it is not allowed to change on PUT operations.
    #[serde(rename = "clusterId")]
    pub cluster_id: String,
    /// ClusterInitBaseName denotes the name of a Base used for initialization.
    /// Also a taint "clusters.clusternet.io/initialization:NoSchedule" will be added during the operation and removed
    /// after successful initialization.
    /// If this cluster has got an annotation "clusters.clusternet.io/skip-cluster-init", this field will be empty.
    /// Normally this field is fully managed by clusternet-controller-manager and immutable.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clusterInitBaseName")]
    pub cluster_init_base_name: Option<String>,
    /// ClusterType denotes the type of the child cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clusterType")]
    pub cluster_type: Option<String>,
    /// SyncMode decides how to sync resources from parent cluster to child cluster.
    #[serde(rename = "syncMode")]
    pub sync_mode: ManagedClusterSyncMode,
    /// Taints has the "effect" on any resource that does not tolerate the Taint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taints: Option<Vec<ManagedClusterTaints>>,
}

/// ManagedClusterSpec defines the desired state of ManagedCluster
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ManagedClusterSyncMode {
    Push,
    Pull,
    Dual,
}

/// The node this Taint is attached to has the "effect" on
/// any pod that does not tolerate the Taint.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ManagedClusterTaints {
    /// Required. The effect of the taint on pods
    /// that do not tolerate the taint.
    /// Valid effects are NoSchedule, PreferNoSchedule and NoExecute.
    pub effect: String,
    /// Required. The taint key to be applied to a node.
    pub key: String,
    /// TimeAdded represents the time at which the taint was added.
    /// It is only written for NoExecute taints.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "timeAdded")]
    pub time_added: Option<String>,
    /// The taint value corresponding to the taint key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// ManagedClusterStatus defines the observed state of ManagedCluster
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ManagedClusterStatus {
    /// Allocatable is the sum of allocatable resources for nodes in the cluster
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocatable: Option<BTreeMap<String, IntOrString>>,
    /// APIServerURL indicates the advertising url/address of managed Kubernetes cluster
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiserverURL")]
    pub apiserver_url: Option<String>,
    /// AppPusher indicates whether to allow parent cluster deploying applications in Push or Dual Mode.
    /// Mainly for security concerns.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "appPusher")]
    pub app_pusher: Option<bool>,
    /// Capacity is the sum of capacity resources for nodes in the cluster
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity: Option<BTreeMap<String, IntOrString>>,
    /// ClusterCIDR is the CIDR range of the cluster
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clusterCIDR")]
    pub cluster_cidr: Option<String>,
    /// Conditions is an array of current cluster conditions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// Healthz indicates the healthz status of the cluster
    /// which is deprecated since Kubernetes v1.16. Please use Livez and Readyz instead.
    /// Leave it here only for compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub healthz: Option<bool>,
    /// heartbeatFrequencySeconds is the frequency at which the agent reports current cluster status
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "heartbeatFrequencySeconds")]
    pub heartbeat_frequency_seconds: Option<i64>,
    /// k8sVersion is the Kubernetes version of the cluster
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "k8sVersion")]
    pub k8s_version: Option<String>,
    /// KubeBurst allows extra queries to accumulate when a client is exceeding its rate.
    /// Used by deployer in Clusternet to control the burst to current child cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "kubeBurst")]
    pub kube_burst: Option<i32>,
    /// KubeQPS controls the number of queries per second allowed for this connection.
    /// Used by deployer in Clusternet to control the qps to current child cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "kubeQPS")]
    pub kube_qps: Option<f64>,
    /// lastObservedTime is the time when last status from the series was seen before last heartbeat.
    /// RFC 3339 date and time at which the object was acknowledged by the Clusternet Agent.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastObservedTime")]
    pub last_observed_time: Option<String>,
    /// Livez indicates the livez status of the cluster
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub livez: Option<bool>,
    /// NodeStatistics is the info summary of nodes in the cluster
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nodeStatistics")]
    pub node_statistics: Option<ManagedClusterStatusNodeStatistics>,
    /// platform indicates the running platform of the cluster
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// PodStatistics is the info summary of pods in the cluster
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "podStatistics")]
    pub pod_statistics: Option<ManagedClusterStatusPodStatistics>,
    /// PredictorAddress shows the predictor address
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "predictorAddress")]
    pub predictor_address: Option<String>,
    /// PredictorDirectAccess indicates whether the predictor can be accessed directly by clusternet-scheduler
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "predictorDirectAccess")]
    pub predictor_direct_access: Option<bool>,
    /// PredictorEnabled indicates whether predictor is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "predictorEnabled")]
    pub predictor_enabled: Option<bool>,
    /// Readyz indicates the readyz status of the cluster
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readyz: Option<bool>,
    /// ResourceUsage is the cpu(m) and memory(Mi) already used in the cluster
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "resourceUsage")]
    pub resource_usage: Option<ManagedClusterStatusResourceUsage>,
    /// ServcieCIDR is the CIDR range of the services
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "serviceCIDR")]
    pub service_cidr: Option<String>,
    /// UseSocket indicates whether to use socket proxy when connecting to child cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "useSocket")]
    pub use_socket: Option<bool>,
}

/// NodeStatistics is the info summary of nodes in the cluster
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ManagedClusterStatusNodeStatistics {
    /// LostNodes is the number of states lost nodes in the cluster
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lostNodes")]
    pub lost_nodes: Option<i32>,
    /// NotReadyNodes is the number of not ready nodes in the cluster
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "notReadyNodes")]
    pub not_ready_nodes: Option<i32>,
    /// ReadyNodes is the number of ready nodes in the cluster
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "readyNodes")]
    pub ready_nodes: Option<i32>,
    /// UnknownNodes is the number of unknown nodes in the cluster
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "unknownNodes")]
    pub unknown_nodes: Option<i32>,
}

/// PodStatistics is the info summary of pods in the cluster
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ManagedClusterStatusPodStatistics {
    /// RunningPods is the number of running pods in the cluster
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "runningPods")]
    pub running_pods: Option<i32>,
    /// TotalPods is the number of all pods in the cluster
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "totalPods")]
    pub total_pods: Option<i32>,
}

/// ResourceUsage is the cpu(m) and memory(Mi) already used in the cluster
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ManagedClusterStatusResourceUsage {
    /// CpuUsage is the total cpu(m) already used in the whole cluster, k8s reserved not include
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "cpuUsage")]
    pub cpu_usage: Option<IntOrString>,
    /// MemoryUsage is the total memory(Mi) already used in the whole cluster, k8s reserved not include
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "memoryUsage")]
    pub memory_usage: Option<IntOrString>,
}

