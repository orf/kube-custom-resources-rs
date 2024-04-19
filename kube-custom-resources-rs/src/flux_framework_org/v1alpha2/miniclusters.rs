// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/flux-framework/flux-operator/flux-framework.org/v1alpha2/miniclusters.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// MiniCluster is an HPC cluster in Kubernetes you can control
/// Either to submit a single job (and go away) or for a persistent single- or multi- user cluster
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "flux-framework.org", version = "v1alpha2", kind = "MiniCluster", plural = "miniclusters")]
#[kube(namespaced)]
#[kube(status = "MiniClusterStatus")]
#[kube(schema = "disabled")]
pub struct MiniClusterSpec {
    /// Archive to load or save
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive: Option<MiniClusterArchive>,
    /// Cleanup the pods and storage when the index broker pod is complete
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup: Option<bool>,
    /// Containers is one or more containers to be created in a pod.
    /// There should only be one container to run flux with runFlux
    pub containers: Vec<MiniClusterContainers>,
    /// Should the job be limited to a particular number of seconds?
    /// Approximately one year. This cannot be zero or job won't start
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "deadlineSeconds")]
    pub deadline_seconds: Option<i64>,
    /// Flux options for the broker, shared across cluster
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flux: Option<MiniClusterFlux>,
    /// Run a single-user, interactive minicluster
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interactive: Option<bool>,
    /// Labels for the job
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "jobLabels")]
    pub job_labels: Option<BTreeMap<String, String>>,
    /// Logging modes determine the output you see in the job log
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logging: Option<MiniClusterLogging>,
    /// MaxSize (maximum number of pods to allow scaling to)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxSize")]
    pub max_size: Option<i32>,
    /// MinSize (minimum number of pods that must be up for Flux)
    /// Note that this option does not edit the number of tasks,
    /// so a job could run with fewer (and then not start)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "minSize")]
    pub min_size: Option<i32>,
    /// A spec for exposing or defining the cluster headless service
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<MiniClusterNetwork>,
    /// Pod spec details
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod: Option<MiniClusterPod>,
    /// Services are one or more service containers to bring up
    /// alongside the MiniCluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<MiniClusterServices>>,
    /// Share process namespace?
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "shareProcessNamespace")]
    pub share_process_namespace: Option<bool>,
    /// Size (number of job pods to run, size of minicluster in pods)
    /// This is also the minimum number required to start Flux
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<i32>,
    /// Total number of CPUs being run across entire cluster
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tasks: Option<i32>,
}

/// Archive to load or save
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterArchive {
    /// Save or load from this directory path
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterContainers {
    /// Indicate that the command is a batch job that will be written to a file to submit
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch: Option<bool>,
    /// Don't wrap batch commands in flux submit (provide custom logic myself)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "batchRaw")]
    pub batch_raw: Option<bool>,
    /// Single user executable to provide to flux start
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// More specific or detailed commands for just workers/broker
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commands: Option<MiniClusterContainersCommands>,
    /// Key/value pairs for the environment
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<BTreeMap<String, String>>,
    /// Container image must contain flux and flux-sched install
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Allow the user to pull authenticated images
    /// By default no secret is selected. Setting
    /// this with the name of an already existing
    /// imagePullSecret will specify that secret
    /// in the pod spec.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "imagePullSecret")]
    pub image_pull_secret: Option<String>,
    /// Indicate that the command is a launcher that will
    /// ask for its own jobs (and provided directly to flux start)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launcher: Option<bool>,
    /// Lifecycle can handle post start commands, etc.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lifeCycle")]
    pub life_cycle: Option<MiniClusterContainersLifeCycle>,
    /// Log output directory
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logs: Option<String>,
    /// Container name is only required for non flux runners
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Do not wrap the entrypoint to wait for flux, add to path, etc?
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "noWrapEntrypoint")]
    pub no_wrap_entrypoint: Option<bool>,
    /// Ports to be exposed to other containers in the cluster
    /// We take a single list of integers and map to the same
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<i64>>,
    /// Allow the user to dictate pulling
    /// By default we pull if not present. Setting
    /// this to true will indicate to pull always
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "pullAlways")]
    pub pull_always: Option<bool>,
    /// Resources include limits and requests
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<MiniClusterContainersResources>,
    /// Application container intended to run flux (broker)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "runFlux")]
    pub run_flux: Option<bool>,
    /// Secrets that will be added to the environment
    /// The user is expected to create their own secrets for the operator to find
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<BTreeMap<String, MiniClusterContainersSecrets>>,
    /// Security Context
    /// https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "securityContext")]
    pub security_context: Option<MiniClusterContainersSecurityContext>,
    /// Existing volumes that can be mounted
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volumes: Option<BTreeMap<String, MiniClusterContainersVolumes>>,
    /// Working directory to run command from
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "workingDir")]
    pub working_dir: Option<String>,
}

/// More specific or detailed commands for just workers/broker
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterContainersCommands {
    /// A single command for only the broker to run
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "brokerPre")]
    pub broker_pre: Option<String>,
    /// init command is run before anything
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub init: Option<String>,
    /// post command is run in the entrypoint when the broker exits / finishes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post: Option<String>,
    /// pre command is run after global PreCommand, after asFlux is set (can override)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre: Option<String>,
    /// Prefix to flux start / submit / broker
    /// Typically used for a wrapper command to mount, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Custom script for submit (e.g., multiple lines)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    /// A command only for service start.sh tor run
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "servicePre")]
    pub service_pre: Option<String>,
    /// A command only for workers to run
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "workerPre")]
    pub worker_pre: Option<String>,
}

/// Lifecycle can handle post start commands, etc.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterContainersLifeCycle {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "postStartExec")]
    pub post_start_exec: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "preStopExec")]
    pub pre_stop_exec: Option<String>,
}

/// Resources include limits and requests
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterContainersResources {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<BTreeMap<String, IntOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<BTreeMap<String, IntOrString>>,
}

/// Secrets that will be added to the environment
/// The user is expected to create their own secrets for the operator to find
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterContainersSecrets {
    /// Key under secretKeyRef->Key
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Name under secretKeyRef->Name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Security Context
/// https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterContainersSecurityContext {
    /// Capabilities to add
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "addCapabilities")]
    pub add_capabilities: Option<Vec<String>>,
    /// Privileged container
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,
}

/// Existing volumes that can be mounted
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterContainersVolumes {
    /// Claim name if the existing volume is a PVC
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "claimName")]
    pub claim_name: Option<String>,
    /// Config map name if the existing volume is a config map
    /// You should also define items if you are using this
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "configMapName")]
    pub config_map_name: Option<String>,
    /// An existing hostPath to bind to path
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "hostPath")]
    pub host_path: Option<String>,
    /// Items (key and paths) for the config map
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<BTreeMap<String, String>>,
    /// Path and claim name are always required if a secret isn't defined
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "readOnly")]
    pub read_only: Option<bool>,
    /// An existing secret
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretName")]
    pub secret_name: Option<String>,
}

/// Flux options for the broker, shared across cluster
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterFlux {
    /// Change the arch string - determines the binaries
    /// that are downloaded to run the entrypoint
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// Optionally provide a manually created broker config
    /// this is intended for bursting to remote clusters
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "brokerConfig")]
    pub broker_config: Option<String>,
    /// Bursting - one or more external clusters to burst to
    /// We assume a single, central MiniCluster with an ipaddress
    /// that all connect to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bursting: Option<MiniClusterFluxBursting>,
    /// Complete workers when they fail
    /// This is ideal if you don't want them to restart
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "completeWorkers")]
    pub complete_workers: Option<bool>,
    /// Single user executable to provide to flux start
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "connectTimeout")]
    pub connect_timeout: Option<String>,
    /// Container base for flux
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<MiniClusterFluxContainer>,
    /// Optionally provide an already existing curve certificate
    /// This is not recommended in favor of providing the secret
    /// name as curveCertSecret, below
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "curveCert")]
    pub curve_cert: Option<String>,
    /// Log level to use for flux logging (only in non TestMode)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "logLevel")]
    pub log_level: Option<i32>,
    /// Only expose the broker service (to reduce load on DNS)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "minimalService")]
    pub minimal_service: Option<bool>,
    /// Expect a secret (named according to this string)
    /// for a munge key. This is intended for bursting.
    /// Assumed to be at /etc/munge/munge.key
    /// This is binary data.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "mungeSecret")]
    pub munge_secret: Option<String>,
    /// Do not wait for the socket
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "noWaitSocket")]
    pub no_wait_socket: Option<bool>,
    /// Flux option flags, usually provided with -o
    /// optional - if needed, default option flags for the server
    /// These can also be set in the user interface to override here.
    /// This is only valid for a FluxRunner "runFlux" true
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "optionFlags")]
    pub option_flags: Option<String>,
    /// Custom attributes for the fluxion scheduler
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduler: Option<MiniClusterFluxScheduler>,
    /// Modify flux submit to be something else
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "submitCommand")]
    pub submit_command: Option<String>,
    /// Commands for flux start --wrap
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrap: Option<String>,
}

/// Bursting - one or more external clusters to burst to
/// We assume a single, central MiniCluster with an ipaddress
/// that all connect to.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterFluxBursting {
    /// External clusters to burst to. Each external
    /// cluster must share the same listing to align ranks
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clusters: Option<Vec<MiniClusterFluxBurstingClusters>>,
    /// Hostlist is a custom hostlist for the broker.toml
    /// that includes the local plus bursted cluster. This
    /// is typically used for bursting to another resource
    /// type, where we can predict the hostnames but they
    /// don't follow the same convention as the Flux Operator
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostlist: Option<String>,
    /// The lead broker ip address to join to. E.g., if we burst
    /// to cluster 2, this is the address to connect to cluster 1
    /// For the first cluster, this should not be defined
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "leadBroker")]
    pub lead_broker: Option<MiniClusterFluxBurstingLeadBroker>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterFluxBurstingClusters {
    /// The hostnames for the bursted clusters
    /// If set, the user is responsible for ensuring
    /// uniqueness. The operator will set to burst-N
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Size of bursted cluster.
    /// Defaults to same size as local minicluster if not set
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<i32>,
}

/// The lead broker ip address to join to. E.g., if we burst
/// to cluster 2, this is the address to connect to cluster 1
/// For the first cluster, this should not be defined
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterFluxBurstingLeadBroker {
    /// Lead broker address (ip or hostname)
    pub address: String,
    /// We need the name of the lead job to assemble the hostnames
    pub name: String,
    /// Lead broker port - should only be used for external cluster
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<i32>,
    /// Lead broker size
    pub size: i32,
}

/// Container base for flux
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterFluxContainer {
    /// Disable the sidecar container, assuming that the main application container has flux
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Allow the user to pull authenticated images
    /// By default no secret is selected. Setting
    /// this with the name of an already existing
    /// imagePullSecret will specify that secret
    /// in the pod spec.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "imagePullSecret")]
    pub image_pull_secret: Option<String>,
    /// Mount path for flux to be at (will be added to path)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "mountPath")]
    pub mount_path: Option<String>,
    /// Container name is only required for non flux runners
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Allow the user to dictate pulling
    /// By default we pull if not present. Setting
    /// this to true will indicate to pull always
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "pullAlways")]
    pub pull_always: Option<bool>,
    /// Customize python path for flux
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "pythonPath")]
    pub python_path: Option<String>,
    /// Resources include limits and requests
    /// These must be defined for cpu and memory
    /// for the QoS to be Guaranteed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<MiniClusterFluxContainerResources>,
    /// Working directory to run command from
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "workingDir")]
    pub working_dir: Option<String>,
}

/// Resources include limits and requests
/// These must be defined for cpu and memory
/// for the QoS to be Guaranteed
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterFluxContainerResources {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<BTreeMap<String, IntOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<BTreeMap<String, IntOrString>>,
}

/// Custom attributes for the fluxion scheduler
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterFluxScheduler {
    /// Scheduler queue policy, defaults to "fcfs" can also be "easy"
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "queuePolicy")]
    pub queue_policy: Option<String>,
}

/// Logging modes determine the output you see in the job log
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterLogging {
    /// Debug mode adds extra verbosity to Flux
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debug: Option<bool>,
    /// Quiet mode silences all output so the job only shows the test running
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quiet: Option<bool>,
    /// Strict mode ensures any failure will not continue in the job entrypoint
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict: Option<bool>,
    /// Timed mode adds timing to Flux commands
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timed: Option<bool>,
    /// Enable Zeromq logging
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zeromq: Option<bool>,
}

/// A spec for exposing or defining the cluster headless service
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterNetwork {
    /// Disable affinity rules that guarantee one network address / node
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "disableAffinity")]
    pub disable_affinity: Option<bool>,
    /// Name for cluster headless service
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "headlessName")]
    pub headless_name: Option<String>,
}

/// Pod spec details
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterPod {
    /// Annotations for each pod
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
    /// Labels for each pod
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    /// NodeSelectors for a pod
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nodeSelector")]
    pub node_selector: Option<BTreeMap<String, String>>,
    /// Resources include limits and requests
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<BTreeMap<String, IntOrString>>,
    /// Scheduler name for the pod
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "schedulerName")]
    pub scheduler_name: Option<String>,
    /// Service account name for the pod
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "serviceAccountName")]
    pub service_account_name: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterServices {
    /// Indicate that the command is a batch job that will be written to a file to submit
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch: Option<bool>,
    /// Don't wrap batch commands in flux submit (provide custom logic myself)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "batchRaw")]
    pub batch_raw: Option<bool>,
    /// Single user executable to provide to flux start
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// More specific or detailed commands for just workers/broker
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commands: Option<MiniClusterServicesCommands>,
    /// Key/value pairs for the environment
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<BTreeMap<String, String>>,
    /// Container image must contain flux and flux-sched install
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Allow the user to pull authenticated images
    /// By default no secret is selected. Setting
    /// this with the name of an already existing
    /// imagePullSecret will specify that secret
    /// in the pod spec.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "imagePullSecret")]
    pub image_pull_secret: Option<String>,
    /// Indicate that the command is a launcher that will
    /// ask for its own jobs (and provided directly to flux start)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launcher: Option<bool>,
    /// Lifecycle can handle post start commands, etc.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lifeCycle")]
    pub life_cycle: Option<MiniClusterServicesLifeCycle>,
    /// Log output directory
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logs: Option<String>,
    /// Container name is only required for non flux runners
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Do not wrap the entrypoint to wait for flux, add to path, etc?
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "noWrapEntrypoint")]
    pub no_wrap_entrypoint: Option<bool>,
    /// Ports to be exposed to other containers in the cluster
    /// We take a single list of integers and map to the same
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<i64>>,
    /// Allow the user to dictate pulling
    /// By default we pull if not present. Setting
    /// this to true will indicate to pull always
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "pullAlways")]
    pub pull_always: Option<bool>,
    /// Resources include limits and requests
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<MiniClusterServicesResources>,
    /// Application container intended to run flux (broker)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "runFlux")]
    pub run_flux: Option<bool>,
    /// Secrets that will be added to the environment
    /// The user is expected to create their own secrets for the operator to find
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<BTreeMap<String, MiniClusterServicesSecrets>>,
    /// Security Context
    /// https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "securityContext")]
    pub security_context: Option<MiniClusterServicesSecurityContext>,
    /// Existing volumes that can be mounted
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volumes: Option<BTreeMap<String, MiniClusterServicesVolumes>>,
    /// Working directory to run command from
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "workingDir")]
    pub working_dir: Option<String>,
}

/// More specific or detailed commands for just workers/broker
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterServicesCommands {
    /// A single command for only the broker to run
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "brokerPre")]
    pub broker_pre: Option<String>,
    /// init command is run before anything
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub init: Option<String>,
    /// post command is run in the entrypoint when the broker exits / finishes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post: Option<String>,
    /// pre command is run after global PreCommand, after asFlux is set (can override)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre: Option<String>,
    /// Prefix to flux start / submit / broker
    /// Typically used for a wrapper command to mount, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Custom script for submit (e.g., multiple lines)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    /// A command only for service start.sh tor run
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "servicePre")]
    pub service_pre: Option<String>,
    /// A command only for workers to run
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "workerPre")]
    pub worker_pre: Option<String>,
}

/// Lifecycle can handle post start commands, etc.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterServicesLifeCycle {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "postStartExec")]
    pub post_start_exec: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "preStopExec")]
    pub pre_stop_exec: Option<String>,
}

/// Resources include limits and requests
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterServicesResources {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<BTreeMap<String, IntOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<BTreeMap<String, IntOrString>>,
}

/// Secrets that will be added to the environment
/// The user is expected to create their own secrets for the operator to find
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterServicesSecrets {
    /// Key under secretKeyRef->Key
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Name under secretKeyRef->Name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Security Context
/// https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterServicesSecurityContext {
    /// Capabilities to add
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "addCapabilities")]
    pub add_capabilities: Option<Vec<String>>,
    /// Privileged container
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,
}

/// Existing volumes that can be mounted
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterServicesVolumes {
    /// Claim name if the existing volume is a PVC
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "claimName")]
    pub claim_name: Option<String>,
    /// Config map name if the existing volume is a config map
    /// You should also define items if you are using this
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "configMapName")]
    pub config_map_name: Option<String>,
    /// An existing hostPath to bind to path
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "hostPath")]
    pub host_path: Option<String>,
    /// Items (key and paths) for the config map
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<BTreeMap<String, String>>,
    /// Path and claim name are always required if a secret isn't defined
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "readOnly")]
    pub read_only: Option<bool>,
    /// An existing secret
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretName")]
    pub secret_name: Option<String>,
}

/// MiniClusterStatus defines the observed state of Flux
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MiniClusterStatus {
    /// conditions hold the latest Flux Job and MiniCluster states
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// The Jobid is set internally to associate to a miniCluster
    /// This isn't currently in use, we only have one!
    pub jobid: String,
    /// We keep the original size of the MiniCluster request as
    /// this is the absolute maximum
    #[serde(rename = "maximumSize")]
    pub maximum_size: i32,
    pub selector: String,
    /// These are for the sub-resource scale functionality
    pub size: i32,
}

