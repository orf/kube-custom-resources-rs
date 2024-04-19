// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/vmware-tanzu/velero/velero.io/v1/serverstatusrequests.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// ServerStatusRequestSpec is the specification for a ServerStatusRequest.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "velero.io", version = "v1", kind = "ServerStatusRequest", plural = "serverstatusrequests")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct ServerStatusRequestSpec {
}

/// ServerStatusRequestStatus is the current status of a ServerStatusRequest.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ServerStatusRequestStatus {
    /// Phase is the current lifecycle phase of the ServerStatusRequest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<ServerStatusRequestStatusPhase>,
    /// Plugins list information about the plugins running on the Velero server
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugins: Option<Vec<ServerStatusRequestStatusPlugins>>,
    /// ProcessedTimestamp is when the ServerStatusRequest was processed by the ServerStatusRequestController.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "processedTimestamp")]
    pub processed_timestamp: Option<String>,
    /// ServerVersion is the Velero server version.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "serverVersion")]
    pub server_version: Option<String>,
}

/// ServerStatusRequestStatus is the current status of a ServerStatusRequest.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ServerStatusRequestStatusPhase {
    New,
    Processed,
}

/// PluginInfo contains attributes of a Velero plugin
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ServerStatusRequestStatusPlugins {
    pub kind: String,
    pub name: String,
}

