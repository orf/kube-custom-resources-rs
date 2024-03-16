// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/nginxinc/kubernetes-ingress/appprotectdos.f5.com/v1beta1/dosprotectedresources.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// DosProtectedResourceSpec defines the properties and values a DosProtectedResource can have.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "appprotectdos.f5.com", version = "v1beta1", kind = "DosProtectedResource", plural = "dosprotectedresources")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct DosProtectedResourceSpec {
    /// ApDosMonitor is how NGINX App Protect DoS monitors the stress level of the protected object. The monitor requests are sent from localhost (127.0.0.1). Default value: URI - None, protocol - http1, timeout - NGINX App Protect DoS default.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apDosMonitor")]
    pub ap_dos_monitor: Option<DosProtectedResourceApDosMonitor>,
    /// ApDosPolicy is the namespace/name of a ApDosPolicy resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apDosPolicy")]
    pub ap_dos_policy: Option<String>,
    /// DosAccessLogDest is the network address for the access logs
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dosAccessLogDest")]
    pub dos_access_log_dest: Option<String>,
    /// DosSecurityLog defines the security log of the DosProtectedResource.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dosSecurityLog")]
    pub dos_security_log: Option<DosProtectedResourceDosSecurityLog>,
    /// Enable enables the DOS feature if set to true
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable: Option<bool>,
    /// Name is the name of protected object, max of 63 characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// ApDosMonitor is how NGINX App Protect DoS monitors the stress level of the protected object. The monitor requests are sent from localhost (127.0.0.1). Default value: URI - None, protocol - http1, timeout - NGINX App Protect DoS default.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct DosProtectedResourceApDosMonitor {
    /// Protocol determines if the server listens on http1 / http2 / grpc / websocket. The default is http1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<DosProtectedResourceApDosMonitorProtocol>,
    /// Timeout determines how long (in seconds) should NGINX App Protect DoS wait for a response. Default is 10 seconds for http1/http2 and 5 seconds for grpc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<i64>,
    /// URI is the destination to the desired protected object in the nginx.conf:
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

/// ApDosMonitor is how NGINX App Protect DoS monitors the stress level of the protected object. The monitor requests are sent from localhost (127.0.0.1). Default value: URI - None, protocol - http1, timeout - NGINX App Protect DoS default.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum DosProtectedResourceApDosMonitorProtocol {
    #[serde(rename = "http1")]
    Http1,
    #[serde(rename = "http2")]
    Http2,
    #[serde(rename = "grpc")]
    Grpc,
    #[serde(rename = "websocket")]
    Websocket,
}

/// DosSecurityLog defines the security log of the DosProtectedResource.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct DosProtectedResourceDosSecurityLog {
    /// ApDosLogConf is the namespace/name of a APDosLogConf resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apDosLogConf")]
    pub ap_dos_log_conf: Option<String>,
    /// DosLogDest is the network address of a logging service, can be either IP or DNS name.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dosLogDest")]
    pub dos_log_dest: Option<String>,
    /// Enable enables the security logging feature if set to true
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable: Option<bool>,
}

