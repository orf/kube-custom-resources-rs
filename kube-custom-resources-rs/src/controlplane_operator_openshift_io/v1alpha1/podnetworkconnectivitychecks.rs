// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/openshift/api/controlplane.operator.openshift.io/v1alpha1/podnetworkconnectivitychecks.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// Spec defines the source and target of the connectivity check
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "controlplane.operator.openshift.io", version = "v1alpha1", kind = "PodNetworkConnectivityCheck", plural = "podnetworkconnectivitychecks")]
#[kube(namespaced)]
#[kube(status = "PodNetworkConnectivityCheckStatus")]
#[kube(schema = "disabled")]
pub struct PodNetworkConnectivityCheckSpec {
    /// SourcePod names the pod from which the condition will be checked
    #[serde(rename = "sourcePod")]
    pub source_pod: String,
    /// EndpointAddress to check. A TCP address of the form host:port. Note that if host is a DNS name, then the check would fail if the DNS name cannot be resolved. Specify an IP address for host to bypass DNS name lookup.
    #[serde(rename = "targetEndpoint")]
    pub target_endpoint: String,
    /// TLSClientCert, if specified, references a kubernetes.io/tls type secret with 'tls.crt' and 'tls.key' entries containing an optional TLS client certificate and key to be used when checking endpoints that require a client certificate in order to gracefully preform the scan without causing excessive logging in the endpoint process. The secret must exist in the same namespace as this resource.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "tlsClientCert")]
    pub tls_client_cert: Option<PodNetworkConnectivityCheckTlsClientCert>,
}

/// TLSClientCert, if specified, references a kubernetes.io/tls type secret with 'tls.crt' and 'tls.key' entries containing an optional TLS client certificate and key to be used when checking endpoints that require a client certificate in order to gracefully preform the scan without causing excessive logging in the endpoint process. The secret must exist in the same namespace as this resource.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodNetworkConnectivityCheckTlsClientCert {
    /// name is the metadata.name of the referenced secret
    pub name: String,
}

/// Status contains the observed status of the connectivity check
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodNetworkConnectivityCheckStatus {
    /// Conditions summarize the status of the check
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// Failures contains logs of unsuccessful check actions
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<Vec<PodNetworkConnectivityCheckStatusFailures>>,
    /// Outages contains logs of time periods of outages
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outages: Option<Vec<PodNetworkConnectivityCheckStatusOutages>>,
    /// Successes contains logs successful check actions
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successes: Option<Vec<PodNetworkConnectivityCheckStatusSuccesses>>,
}

/// LogEntry records events
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodNetworkConnectivityCheckStatusFailures {
    /// Latency records how long the action mentioned in the entry took.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency: Option<String>,
    /// Message explaining status in a human readable format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Reason for status in a machine readable format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Success indicates if the log entry indicates a success or failure.
    pub success: bool,
    /// Start time of check action.
    pub time: String,
}

/// OutageEntry records time period of an outage
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodNetworkConnectivityCheckStatusOutages {
    /// End of outage detected
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
    /// EndLogs contains log entries related to the end of this outage. Should contain the success entry that resolved the outage and possibly a few of the failure log entries that preceded it.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "endLogs")]
    pub end_logs: Option<Vec<PodNetworkConnectivityCheckStatusOutagesEndLogs>>,
    /// Message summarizes outage details in a human readable format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Start of outage detected
    pub start: String,
    /// StartLogs contains log entries related to the start of this outage. Should contain the original failure, any entries where the failure mode changed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "startLogs")]
    pub start_logs: Option<Vec<PodNetworkConnectivityCheckStatusOutagesStartLogs>>,
}

/// LogEntry records events
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodNetworkConnectivityCheckStatusOutagesEndLogs {
    /// Latency records how long the action mentioned in the entry took.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency: Option<String>,
    /// Message explaining status in a human readable format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Reason for status in a machine readable format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Success indicates if the log entry indicates a success or failure.
    pub success: bool,
    /// Start time of check action.
    pub time: String,
}

/// LogEntry records events
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodNetworkConnectivityCheckStatusOutagesStartLogs {
    /// Latency records how long the action mentioned in the entry took.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency: Option<String>,
    /// Message explaining status in a human readable format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Reason for status in a machine readable format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Success indicates if the log entry indicates a success or failure.
    pub success: bool,
    /// Start time of check action.
    pub time: String,
}

/// LogEntry records events
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodNetworkConnectivityCheckStatusSuccesses {
    /// Latency records how long the action mentioned in the entry took.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency: Option<String>,
    /// Message explaining status in a human readable format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Reason for status in a machine readable format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Success indicates if the log entry indicates a success or failure.
    pub success: bool,
    /// Start time of check action.
    pub time: String,
}

