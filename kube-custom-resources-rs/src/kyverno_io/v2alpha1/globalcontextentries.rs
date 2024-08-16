// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kyverno/kyverno/kyverno.io/v2alpha1/globalcontextentries.yaml --derive=Default --derive=PartialEq --smart-derive-elision
// kopium version: 0.20.1

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
}
use self::prelude::*;

/// Spec declares policy exception behaviors.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "kyverno.io", version = "v2alpha1", kind = "GlobalContextEntry", plural = "globalcontextentries")]
#[kube(status = "GlobalContextEntryStatus")]
#[kube(schema = "disabled")]
#[kube(derive="Default")]
#[kube(derive="PartialEq")]
pub struct GlobalContextEntrySpec {
    /// Stores results from an API call which will be cached.
    /// Mutually exclusive with KubernetesResource.
    /// This can be used to make calls to external (non-Kubernetes API server) services.
    /// It can also be used to make calls to the Kubernetes API server in such cases:
    /// 1. A POST is needed to create a resource.
    /// 2. Finer-grained control is needed. Example: To restrict the number of resources cached.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiCall")]
    pub api_call: Option<GlobalContextEntryApiCall>,
    /// Stores a list of Kubernetes resources which will be cached.
    /// Mutually exclusive with APICall.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "kubernetesResource")]
    pub kubernetes_resource: Option<GlobalContextEntryKubernetesResource>,
}

/// Stores results from an API call which will be cached.
/// Mutually exclusive with KubernetesResource.
/// This can be used to make calls to external (non-Kubernetes API server) services.
/// It can also be used to make calls to the Kubernetes API server in such cases:
/// 1. A POST is needed to create a resource.
/// 2. Finer-grained control is needed. Example: To restrict the number of resources cached.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct GlobalContextEntryApiCall {
    /// The data object specifies the POST data sent to the server.
    /// Only applicable when the method field is set to POST.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<GlobalContextEntryApiCallData>>,
    /// Method is the HTTP request type (GET or POST). Defaults to GET.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<GlobalContextEntryApiCallMethod>,
    /// RefreshInterval defines the interval in duration at which to poll the APICall.
    /// The duration is a sequence of decimal numbers, each with optional fraction and a unit suffix,
    /// such as "300ms", "1.5h" or "2h45m". Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "refreshInterval")]
    pub refresh_interval: Option<String>,
    /// Service is an API call to a JSON web service.
    /// This is used for non-Kubernetes API server calls.
    /// It's mutually exclusive with the URLPath field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<GlobalContextEntryApiCallService>,
    /// URLPath is the URL path to be used in the HTTP GET or POST request to the
    /// Kubernetes API server (e.g. "/api/v1/namespaces" or  "/apis/apps/v1/deployments").
    /// The format required is the same format used by the `kubectl get --raw` command.
    /// See https://kyverno.io/docs/writing-policies/external-data-sources/#variables-from-kubernetes-api-server-calls
    /// for details.
    /// It's mutually exclusive with the Service field.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "urlPath")]
    pub url_path: Option<String>,
}

/// RequestData contains the HTTP POST data
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct GlobalContextEntryApiCallData {
    /// Key is a unique identifier for the data value
    pub key: String,
    /// Value is the data value
    pub value: serde_json::Value,
}

/// Stores results from an API call which will be cached.
/// Mutually exclusive with KubernetesResource.
/// This can be used to make calls to external (non-Kubernetes API server) services.
/// It can also be used to make calls to the Kubernetes API server in such cases:
/// 1. A POST is needed to create a resource.
/// 2. Finer-grained control is needed. Example: To restrict the number of resources cached.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum GlobalContextEntryApiCallMethod {
    #[serde(rename = "GET")]
    Get,
    #[serde(rename = "POST")]
    Post,
}

/// Service is an API call to a JSON web service.
/// This is used for non-Kubernetes API server calls.
/// It's mutually exclusive with the URLPath field.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct GlobalContextEntryApiCallService {
    /// CABundle is a PEM encoded CA bundle which will be used to validate
    /// the server certificate.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "caBundle")]
    pub ca_bundle: Option<String>,
    /// URL is the JSON web service URL. A typical form is
    /// `https://{service}.{namespace}:{port}/{path}`.
    pub url: String,
}

/// Stores a list of Kubernetes resources which will be cached.
/// Mutually exclusive with APICall.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct GlobalContextEntryKubernetesResource {
    /// Group defines the group of the resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Namespace defines the namespace of the resource. Leave empty for cluster scoped resources.
    /// If left empty for namespaced resources, all resources from all namespaces will be cached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Resource defines the type of the resource.
    /// Requires the pluralized form of the resource kind in lowercase. (Ex., "deployments")
    pub resource: String,
    /// Version defines the version of the resource.
    pub version: String,
}

/// Status contains globalcontextentry runtime data.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct GlobalContextEntryStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// Indicates the time when the globalcontextentry was last refreshed successfully for the API Call
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastRefreshTime")]
    pub last_refresh_time: Option<String>,
    /// Deprecated in favor of Conditions
    pub ready: bool,
}

