// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kiegroup/kogito-operator/app.kiegroup.org/v1beta1/kogitosupportingservices.yaml --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// KogitoSupportingServiceSpec defines the desired state of KogitoSupportingService.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "app.kiegroup.org", version = "v1beta1", kind = "KogitoSupportingService", plural = "kogitosupportingservices")]
#[kube(namespaced)]
#[kube(status = "KogitoSupportingServiceStatus")]
#[kube(schema = "disabled")]
pub struct KogitoSupportingServiceSpec {
    /// Application properties that will be set to the service. For example 'MY_VAR: my_value'.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<BTreeMap<String, String>>,
    /// Additional labels to be added to the Deployment and Pods managed by the operator.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "deploymentLabels")]
    pub deployment_labels: Option<BTreeMap<String, String>>,
    /// A flag indicating that routes are disabled. Usable just on OpenShift. 
    ///  If not provided, defaults to 'false'.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "disableRoute")]
    pub disable_route: Option<bool>,
    /// Environment variables to be added to the runtime container. Keys must be a C_IDENTIFIER.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<KogitoSupportingServiceEnv>>,
    /// Image definition for the service. Example: "quay.io/kiegroup/kogito-service:latest". 
    ///  On OpenShift an ImageStream will be created in the current namespace pointing to the given image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Infra provides list of dependent KogitoInfra objects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub infra: Option<Vec<String>>,
    /// A flag indicating that image streams created by Kogito Operator should be configured to allow pulling from insecure registries. Usable just on OpenShift. 
    ///  Defaults to 'false'.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "insecureImageRegistry")]
    pub insecure_image_registry: Option<bool>,
    /// Create Service monitor instance to connect with Monitoring service
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitoring: Option<KogitoSupportingServiceMonitoring>,
    /// Configure liveness, readiness and startup probes for containers
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probes: Option<KogitoSupportingServiceProbes>,
    /// Custom ConfigMap with application.properties file to be mounted for the Kogito service. 
    ///  The ConfigMap must be created in the same namespace. 
    ///  Use this property if you need custom properties to be mounted before the application deployment. 
    ///  If left empty, one will be created for you. Later it can be updated to add any custom properties to apply to the service.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "propertiesConfigMap")]
    pub properties_config_map: Option<String>,
    /// Number of replicas that the service will have deployed in the cluster. 
    ///  Default value: 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<i32>,
    /// Defined compute resource requirements for the deployed service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<KogitoSupportingServiceResources>,
    /// Additional labels to be added to the Service managed by the operator.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "serviceLabels")]
    pub service_labels: Option<BTreeMap<String, String>>,
    /// Defines the type for the supporting service, eg: DataIndex, JobsService Default value: JobsService
    #[serde(rename = "serviceType")]
    pub service_type: KogitoSupportingServiceServiceType,
    /// Custom JKS TrustStore that will be used by this service to make calls to TLS endpoints. 
    ///  It's expected that the secret has two keys: `keyStorePassword` containing the password for the KeyStore and `cacerts` containing the binary data of the given KeyStore.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "trustStoreSecret")]
    pub trust_store_secret: Option<String>,
}

/// EnvVar represents an environment variable present in a Container.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceEnv {
    /// Name of the environment variable. Must be a C_IDENTIFIER.
    pub name: String,
    /// Variable references $(VAR_NAME) are expanded using the previously defined environment variables in the container and any service environment variables. If a variable cannot be resolved, the reference in the input string will be unchanged. Double $$ are reduced to a single $, which allows for escaping the $(VAR_NAME) syntax: i.e. "$$(VAR_NAME)" will produce the string literal "$(VAR_NAME)". Escaped references will never be expanded, regardless of whether the variable exists or not. Defaults to "".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Source for the environment variable's value. Cannot be used if value is not empty.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "valueFrom")]
    pub value_from: Option<KogitoSupportingServiceEnvValueFrom>,
}

/// Source for the environment variable's value. Cannot be used if value is not empty.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceEnvValueFrom {
    /// Selects a key of a ConfigMap.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "configMapKeyRef")]
    pub config_map_key_ref: Option<KogitoSupportingServiceEnvValueFromConfigMapKeyRef>,
    /// Selects a field of the pod: supports metadata.name, metadata.namespace, `metadata.labels['<KEY>']`, `metadata.annotations['<KEY>']`, spec.nodeName, spec.serviceAccountName, status.hostIP, status.podIP, status.podIPs.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "fieldRef")]
    pub field_ref: Option<KogitoSupportingServiceEnvValueFromFieldRef>,
    /// Selects a resource of the container: only resources limits and requests (limits.cpu, limits.memory, limits.ephemeral-storage, requests.cpu, requests.memory and requests.ephemeral-storage) are currently supported.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "resourceFieldRef")]
    pub resource_field_ref: Option<KogitoSupportingServiceEnvValueFromResourceFieldRef>,
    /// Selects a key of a secret in the pod's namespace
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretKeyRef")]
    pub secret_key_ref: Option<KogitoSupportingServiceEnvValueFromSecretKeyRef>,
}

/// Selects a key of a ConfigMap.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceEnvValueFromConfigMapKeyRef {
    /// The key to select.
    pub key: String,
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Specify whether the ConfigMap or its key must be defined
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// Selects a field of the pod: supports metadata.name, metadata.namespace, `metadata.labels['<KEY>']`, `metadata.annotations['<KEY>']`, spec.nodeName, spec.serviceAccountName, status.hostIP, status.podIP, status.podIPs.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceEnvValueFromFieldRef {
    /// Version of the schema the FieldPath is written in terms of, defaults to "v1".
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiVersion")]
    pub api_version: Option<String>,
    /// Path of the field to select in the specified API version.
    #[serde(rename = "fieldPath")]
    pub field_path: String,
}

/// Selects a resource of the container: only resources limits and requests (limits.cpu, limits.memory, limits.ephemeral-storage, requests.cpu, requests.memory and requests.ephemeral-storage) are currently supported.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceEnvValueFromResourceFieldRef {
    /// Container name: required for volumes, optional for env vars
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "containerName")]
    pub container_name: Option<String>,
    /// Specifies the output format of the exposed resources, defaults to "1"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub divisor: Option<IntOrString>,
    /// Required: resource to select
    pub resource: String,
}

/// Selects a key of a secret in the pod's namespace
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceEnvValueFromSecretKeyRef {
    /// The key of the secret to select from.  Must be a valid secret key.
    pub key: String,
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Specify whether the Secret or its key must be defined
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// Create Service monitor instance to connect with Monitoring service
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceMonitoring {
    /// HTTP path to scrape for metrics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// HTTP scheme to use for scraping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
}

/// Configure liveness, readiness and startup probes for containers
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceProbes {
    /// LivenessProbe describes how the Kogito container liveness probe should work
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "livenessProbe")]
    pub liveness_probe: Option<KogitoSupportingServiceProbesLivenessProbe>,
    /// ReadinessProbe describes how the Kogito container readiness probe should work
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "readinessProbe")]
    pub readiness_probe: Option<KogitoSupportingServiceProbesReadinessProbe>,
    /// StartupProbe describes how the Kogito container startup probe should work
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "startupProbe")]
    pub startup_probe: Option<KogitoSupportingServiceProbesStartupProbe>,
}

/// LivenessProbe describes how the Kogito container liveness probe should work
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceProbesLivenessProbe {
    /// Exec specifies the action to take.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<KogitoSupportingServiceProbesLivenessProbeExec>,
    /// Minimum consecutive failures for the probe to be considered failed after having succeeded. Defaults to 3. Minimum value is 1.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "failureThreshold")]
    pub failure_threshold: Option<i32>,
    /// GRPC specifies an action involving a GRPC port. This is an alpha field and requires enabling GRPCContainerProbe feature gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc: Option<KogitoSupportingServiceProbesLivenessProbeGrpc>,
    /// HTTPGet specifies the http request to perform.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "httpGet")]
    pub http_get: Option<KogitoSupportingServiceProbesLivenessProbeHttpGet>,
    /// Number of seconds after the container has started before liveness probes are initiated. More info: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle#container-probes
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "initialDelaySeconds")]
    pub initial_delay_seconds: Option<i32>,
    /// How often (in seconds) to perform the probe. Default to 10 seconds. Minimum value is 1.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "periodSeconds")]
    pub period_seconds: Option<i32>,
    /// Minimum consecutive successes for the probe to be considered successful after having failed. Defaults to 1. Must be 1 for liveness and startup. Minimum value is 1.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "successThreshold")]
    pub success_threshold: Option<i32>,
    /// TCPSocket specifies an action involving a TCP port.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "tcpSocket")]
    pub tcp_socket: Option<KogitoSupportingServiceProbesLivenessProbeTcpSocket>,
    /// Optional duration in seconds the pod needs to terminate gracefully upon probe failure. The grace period is the duration in seconds after the processes running in the pod are sent a termination signal and the time when the processes are forcibly halted with a kill signal. Set this value longer than the expected cleanup time for your process. If this value is nil, the pod's terminationGracePeriodSeconds will be used. Otherwise, this value overrides the value provided by the pod spec. Value must be non-negative integer. The value zero indicates stop immediately via the kill signal (no opportunity to shut down). This is a beta field and requires enabling ProbeTerminationGracePeriod feature gate. Minimum value is 1. spec.terminationGracePeriodSeconds is used if unset.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "terminationGracePeriodSeconds")]
    pub termination_grace_period_seconds: Option<i64>,
    /// Number of seconds after which the probe times out. Defaults to 1 second. Minimum value is 1. More info: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle#container-probes
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "timeoutSeconds")]
    pub timeout_seconds: Option<i32>,
}

/// Exec specifies the action to take.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceProbesLivenessProbeExec {
    /// Command is the command line to execute inside the container, the working directory for the command  is root ('/') in the container's filesystem. The command is simply exec'd, it is not run inside a shell, so traditional shell instructions ('|', etc) won't work. To use a shell, you need to explicitly call out to that shell. Exit status of 0 is treated as live/healthy and non-zero is unhealthy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
}

/// GRPC specifies an action involving a GRPC port. This is an alpha field and requires enabling GRPCContainerProbe feature gate.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceProbesLivenessProbeGrpc {
    /// Port number of the gRPC service. Number must be in the range 1 to 65535.
    pub port: i32,
    /// Service is the name of the service to place in the gRPC HealthCheckRequest (see https://github.com/grpc/grpc/blob/master/doc/health-checking.md). 
    ///  If this is not specified, the default behavior is defined by gRPC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
}

/// HTTPGet specifies the http request to perform.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceProbesLivenessProbeHttpGet {
    /// Host name to connect to, defaults to the pod IP. You probably want to set "Host" in httpHeaders instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Custom headers to set in the request. HTTP allows repeated headers.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "httpHeaders")]
    pub http_headers: Option<Vec<KogitoSupportingServiceProbesLivenessProbeHttpGetHttpHeaders>>,
    /// Path to access on the HTTP server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Name or number of the port to access on the container. Number must be in the range 1 to 65535. Name must be an IANA_SVC_NAME.
    pub port: IntOrString,
    /// Scheme to use for connecting to the host. Defaults to HTTP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
}

/// HTTPHeader describes a custom header to be used in HTTP probes
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceProbesLivenessProbeHttpGetHttpHeaders {
    /// The header field name
    pub name: String,
    /// The header field value
    pub value: String,
}

/// TCPSocket specifies an action involving a TCP port.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceProbesLivenessProbeTcpSocket {
    /// Optional: Host name to connect to, defaults to the pod IP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Number or name of the port to access on the container. Number must be in the range 1 to 65535. Name must be an IANA_SVC_NAME.
    pub port: IntOrString,
}

/// ReadinessProbe describes how the Kogito container readiness probe should work
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceProbesReadinessProbe {
    /// Exec specifies the action to take.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<KogitoSupportingServiceProbesReadinessProbeExec>,
    /// Minimum consecutive failures for the probe to be considered failed after having succeeded. Defaults to 3. Minimum value is 1.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "failureThreshold")]
    pub failure_threshold: Option<i32>,
    /// GRPC specifies an action involving a GRPC port. This is an alpha field and requires enabling GRPCContainerProbe feature gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc: Option<KogitoSupportingServiceProbesReadinessProbeGrpc>,
    /// HTTPGet specifies the http request to perform.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "httpGet")]
    pub http_get: Option<KogitoSupportingServiceProbesReadinessProbeHttpGet>,
    /// Number of seconds after the container has started before liveness probes are initiated. More info: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle#container-probes
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "initialDelaySeconds")]
    pub initial_delay_seconds: Option<i32>,
    /// How often (in seconds) to perform the probe. Default to 10 seconds. Minimum value is 1.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "periodSeconds")]
    pub period_seconds: Option<i32>,
    /// Minimum consecutive successes for the probe to be considered successful after having failed. Defaults to 1. Must be 1 for liveness and startup. Minimum value is 1.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "successThreshold")]
    pub success_threshold: Option<i32>,
    /// TCPSocket specifies an action involving a TCP port.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "tcpSocket")]
    pub tcp_socket: Option<KogitoSupportingServiceProbesReadinessProbeTcpSocket>,
    /// Optional duration in seconds the pod needs to terminate gracefully upon probe failure. The grace period is the duration in seconds after the processes running in the pod are sent a termination signal and the time when the processes are forcibly halted with a kill signal. Set this value longer than the expected cleanup time for your process. If this value is nil, the pod's terminationGracePeriodSeconds will be used. Otherwise, this value overrides the value provided by the pod spec. Value must be non-negative integer. The value zero indicates stop immediately via the kill signal (no opportunity to shut down). This is a beta field and requires enabling ProbeTerminationGracePeriod feature gate. Minimum value is 1. spec.terminationGracePeriodSeconds is used if unset.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "terminationGracePeriodSeconds")]
    pub termination_grace_period_seconds: Option<i64>,
    /// Number of seconds after which the probe times out. Defaults to 1 second. Minimum value is 1. More info: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle#container-probes
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "timeoutSeconds")]
    pub timeout_seconds: Option<i32>,
}

/// Exec specifies the action to take.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceProbesReadinessProbeExec {
    /// Command is the command line to execute inside the container, the working directory for the command  is root ('/') in the container's filesystem. The command is simply exec'd, it is not run inside a shell, so traditional shell instructions ('|', etc) won't work. To use a shell, you need to explicitly call out to that shell. Exit status of 0 is treated as live/healthy and non-zero is unhealthy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
}

/// GRPC specifies an action involving a GRPC port. This is an alpha field and requires enabling GRPCContainerProbe feature gate.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceProbesReadinessProbeGrpc {
    /// Port number of the gRPC service. Number must be in the range 1 to 65535.
    pub port: i32,
    /// Service is the name of the service to place in the gRPC HealthCheckRequest (see https://github.com/grpc/grpc/blob/master/doc/health-checking.md). 
    ///  If this is not specified, the default behavior is defined by gRPC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
}

/// HTTPGet specifies the http request to perform.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceProbesReadinessProbeHttpGet {
    /// Host name to connect to, defaults to the pod IP. You probably want to set "Host" in httpHeaders instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Custom headers to set in the request. HTTP allows repeated headers.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "httpHeaders")]
    pub http_headers: Option<Vec<KogitoSupportingServiceProbesReadinessProbeHttpGetHttpHeaders>>,
    /// Path to access on the HTTP server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Name or number of the port to access on the container. Number must be in the range 1 to 65535. Name must be an IANA_SVC_NAME.
    pub port: IntOrString,
    /// Scheme to use for connecting to the host. Defaults to HTTP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
}

/// HTTPHeader describes a custom header to be used in HTTP probes
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceProbesReadinessProbeHttpGetHttpHeaders {
    /// The header field name
    pub name: String,
    /// The header field value
    pub value: String,
}

/// TCPSocket specifies an action involving a TCP port.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceProbesReadinessProbeTcpSocket {
    /// Optional: Host name to connect to, defaults to the pod IP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Number or name of the port to access on the container. Number must be in the range 1 to 65535. Name must be an IANA_SVC_NAME.
    pub port: IntOrString,
}

/// StartupProbe describes how the Kogito container startup probe should work
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceProbesStartupProbe {
    /// Exec specifies the action to take.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<KogitoSupportingServiceProbesStartupProbeExec>,
    /// Minimum consecutive failures for the probe to be considered failed after having succeeded. Defaults to 3. Minimum value is 1.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "failureThreshold")]
    pub failure_threshold: Option<i32>,
    /// GRPC specifies an action involving a GRPC port. This is an alpha field and requires enabling GRPCContainerProbe feature gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc: Option<KogitoSupportingServiceProbesStartupProbeGrpc>,
    /// HTTPGet specifies the http request to perform.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "httpGet")]
    pub http_get: Option<KogitoSupportingServiceProbesStartupProbeHttpGet>,
    /// Number of seconds after the container has started before liveness probes are initiated. More info: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle#container-probes
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "initialDelaySeconds")]
    pub initial_delay_seconds: Option<i32>,
    /// How often (in seconds) to perform the probe. Default to 10 seconds. Minimum value is 1.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "periodSeconds")]
    pub period_seconds: Option<i32>,
    /// Minimum consecutive successes for the probe to be considered successful after having failed. Defaults to 1. Must be 1 for liveness and startup. Minimum value is 1.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "successThreshold")]
    pub success_threshold: Option<i32>,
    /// TCPSocket specifies an action involving a TCP port.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "tcpSocket")]
    pub tcp_socket: Option<KogitoSupportingServiceProbesStartupProbeTcpSocket>,
    /// Optional duration in seconds the pod needs to terminate gracefully upon probe failure. The grace period is the duration in seconds after the processes running in the pod are sent a termination signal and the time when the processes are forcibly halted with a kill signal. Set this value longer than the expected cleanup time for your process. If this value is nil, the pod's terminationGracePeriodSeconds will be used. Otherwise, this value overrides the value provided by the pod spec. Value must be non-negative integer. The value zero indicates stop immediately via the kill signal (no opportunity to shut down). This is a beta field and requires enabling ProbeTerminationGracePeriod feature gate. Minimum value is 1. spec.terminationGracePeriodSeconds is used if unset.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "terminationGracePeriodSeconds")]
    pub termination_grace_period_seconds: Option<i64>,
    /// Number of seconds after which the probe times out. Defaults to 1 second. Minimum value is 1. More info: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle#container-probes
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "timeoutSeconds")]
    pub timeout_seconds: Option<i32>,
}

/// Exec specifies the action to take.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceProbesStartupProbeExec {
    /// Command is the command line to execute inside the container, the working directory for the command  is root ('/') in the container's filesystem. The command is simply exec'd, it is not run inside a shell, so traditional shell instructions ('|', etc) won't work. To use a shell, you need to explicitly call out to that shell. Exit status of 0 is treated as live/healthy and non-zero is unhealthy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
}

/// GRPC specifies an action involving a GRPC port. This is an alpha field and requires enabling GRPCContainerProbe feature gate.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceProbesStartupProbeGrpc {
    /// Port number of the gRPC service. Number must be in the range 1 to 65535.
    pub port: i32,
    /// Service is the name of the service to place in the gRPC HealthCheckRequest (see https://github.com/grpc/grpc/blob/master/doc/health-checking.md). 
    ///  If this is not specified, the default behavior is defined by gRPC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
}

/// HTTPGet specifies the http request to perform.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceProbesStartupProbeHttpGet {
    /// Host name to connect to, defaults to the pod IP. You probably want to set "Host" in httpHeaders instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Custom headers to set in the request. HTTP allows repeated headers.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "httpHeaders")]
    pub http_headers: Option<Vec<KogitoSupportingServiceProbesStartupProbeHttpGetHttpHeaders>>,
    /// Path to access on the HTTP server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Name or number of the port to access on the container. Number must be in the range 1 to 65535. Name must be an IANA_SVC_NAME.
    pub port: IntOrString,
    /// Scheme to use for connecting to the host. Defaults to HTTP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
}

/// HTTPHeader describes a custom header to be used in HTTP probes
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceProbesStartupProbeHttpGetHttpHeaders {
    /// The header field name
    pub name: String,
    /// The header field value
    pub value: String,
}

/// TCPSocket specifies an action involving a TCP port.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceProbesStartupProbeTcpSocket {
    /// Optional: Host name to connect to, defaults to the pod IP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Number or name of the port to access on the container. Number must be in the range 1 to 65535. Name must be an IANA_SVC_NAME.
    pub port: IntOrString,
}

/// Defined compute resource requirements for the deployed service.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceResources {
    /// Limits describes the maximum amount of compute resources allowed. More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<BTreeMap<String, IntOrString>>,
    /// Requests describes the minimum amount of compute resources required. If Requests is omitted for a container, it defaults to Limits if that is explicitly specified, otherwise to an implementation-defined value. More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<BTreeMap<String, IntOrString>>,
}

/// KogitoSupportingServiceSpec defines the desired state of KogitoSupportingService.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum KogitoSupportingServiceServiceType {
    DataIndex,
    Explainability,
    JobsService,
    MgmtConsole,
    TaskConsole,
    #[serde(rename = "TrustyAI")]
    TrustyAi,
    #[serde(rename = "TrustyUI")]
    TrustyUi,
}

/// KogitoSupportingServiceStatus defines the observed state of KogitoSupportingService.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceStatus {
    /// Describes the CloudEvents that this instance can consume or produce
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "cloudEvents")]
    pub cloud_events: Option<KogitoSupportingServiceStatusCloudEvents>,
    /// History of conditions for the resource
    pub conditions: Vec<Condition>,
    /// General conditions for the Kogito Service deployment.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "deploymentConditions")]
    pub deployment_conditions: Option<Vec<KogitoSupportingServiceStatusDeploymentConditions>>,
    /// URI is where the service is exposed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "externalURI")]
    pub external_uri: Option<String>,
    /// Image is the resolved image for this service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// General conditions for the Kogito Service route.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "routeConditions")]
    pub route_conditions: Option<Vec<KogitoSupportingServiceStatusRouteConditions>>,
}

/// Describes the CloudEvents that this instance can consume or produce
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceStatusCloudEvents {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumes: Option<Vec<KogitoSupportingServiceStatusCloudEventsConsumes>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub produces: Option<Vec<KogitoSupportingServiceStatusCloudEventsProduces>>,
}

/// KogitoCloudEventInfo describes the CloudEvent information based on the specification
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceStatusCloudEventsConsumes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "type")]
    pub r#type: String,
}

/// KogitoCloudEventInfo describes the CloudEvent information based on the specification
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceStatusCloudEventsProduces {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "type")]
    pub r#type: String,
}

/// DeploymentCondition describes the state of a deployment at a certain point.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceStatusDeploymentConditions {
    /// Last time the condition transitioned from one status to another.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastTransitionTime")]
    pub last_transition_time: Option<String>,
    /// The last time this condition was updated.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastUpdateTime")]
    pub last_update_time: Option<String>,
    /// A human readable message indicating details about the transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// The reason for the condition's last transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Status of the condition, one of True, False, Unknown.
    pub status: String,
    /// Type of deployment condition.
    #[serde(rename = "type")]
    pub r#type: String,
}

/// Condition contains details for one aspect of the current state of this API Resource. --- This struct is intended for direct use as an array at the field path .status.conditions.  For example, type FooStatus struct{ // Represents the observations of a foo's current state. // Known .status.conditions.type are: "Available", "Progressing", and "Degraded" // +patchMergeKey=type // +patchStrategy=merge // +listType=map // +listMapKey=type Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"` 
///  // other fields }
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KogitoSupportingServiceStatusRouteConditions {
    /// lastTransitionTime is the last time the condition transitioned from one status to another. This should be when the underlying condition changed.  If that is not known, then using the time when the API field changed is acceptable.
    #[serde(rename = "lastTransitionTime")]
    pub last_transition_time: String,
    /// message is a human readable message indicating details about the transition. This may be an empty string.
    pub message: String,
    /// observedGeneration represents the .metadata.generation that the condition was set based upon. For instance, if .metadata.generation is currently 12, but the .status.conditions[x].observedGeneration is 9, the condition is out of date with respect to the current state of the instance.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
    /// reason contains a programmatic identifier indicating the reason for the condition's last transition. Producers of specific condition types may define expected values and meanings for this field, and whether the values are considered a guaranteed API. The value should be a CamelCase string. This field may not be empty.
    pub reason: String,
    /// status of the condition, one of True, False, Unknown.
    pub status: KogitoSupportingServiceStatusRouteConditionsStatus,
    /// type of condition in CamelCase or in foo.example.com/CamelCase. --- Many .condition.type values are consistent across resources like Available, but because arbitrary conditions can be useful (see .node.status.conditions), the ability to deconflict is important. The regex it matches is (dns1123SubdomainFmt/)?(qualifiedNameFmt)
    #[serde(rename = "type")]
    pub r#type: String,
}

/// Condition contains details for one aspect of the current state of this API Resource. --- This struct is intended for direct use as an array at the field path .status.conditions.  For example, type FooStatus struct{ // Represents the observations of a foo's current state. // Known .status.conditions.type are: "Available", "Progressing", and "Degraded" // +patchMergeKey=type // +patchStrategy=merge // +listType=map // +listMapKey=type Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"` 
///  // other fields }
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum KogitoSupportingServiceStatusRouteConditionsStatus {
    True,
    False,
    Unknown,
}

