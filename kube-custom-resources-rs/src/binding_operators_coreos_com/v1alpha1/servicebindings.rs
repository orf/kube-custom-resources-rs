// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/redhat-developer/service-binding-operator/binding.operators.coreos.com/v1alpha1/servicebindings.yaml --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// ServiceBindingSpec defines the desired state of ServiceBinding.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "binding.operators.coreos.com", version = "v1alpha1", kind = "ServiceBinding", plural = "servicebindings")]
#[kube(namespaced)]
#[kube(status = "ServiceBindingStatus")]
#[kube(schema = "disabled")]
pub struct ServiceBindingSpec {
    /// Application identifies the application connecting to the backing service.
    pub application: ServiceBindingApplication,
    /// BindAsFiles makes the binding values available as files in the application's container.  By default, values are mounted under the path "/bindings"; this can be changed by setting the SERVICE_BINDING_ROOT environment variable.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "bindAsFiles")]
    pub bind_as_files: Option<bool>,
    /// DetectBindingResources is a flag that, when set to true, will cause SBO to search for binding information in the owned resources of the specified services.  If this binding information exists, then the application is bound to these subresources.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "detectBindingResources")]
    pub detect_binding_resources: Option<bool>,
    /// Mappings specifies custom mappings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mappings: Option<Vec<ServiceBindingMappings>>,
    /// Name is the name of the service as projected into the workload container.  Defaults to .metadata.name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// NamingStrategy defines custom string template for preparing binding names.  It can be set to pre-defined strategies: `none`, `lowercase`, or `uppercase`.  Otherwise, it is treated as a custom go template, and it is handled accordingly.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "namingStrategy")]
    pub naming_strategy: Option<String>,
    /// Services indicates the backing services to be connected to by an application.  At least one service must be specified.
    pub services: Vec<ServiceBindingServices>,
}

/// Application identifies the application connecting to the backing service.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ServiceBindingApplication {
    /// BindingPath refers to the paths in the application workload's schema where the binding workload would be referenced.  If BindingPath is not specified, then the default path locations are used.  The default location for ContainersPath is "spec.template.spec.containers".  If SecretPath is not specified, then the name of the secret object does not need to be specified.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "bindingPath")]
    pub binding_path: Option<ServiceBindingApplicationBindingPath>,
    /// Group of the referent.
    pub group: String,
    /// Kind of the referent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// A label selector is a label query over a set of resources. The result of matchLabels and matchExpressions are ANDed. An empty label selector matches all objects. A null label selector matches no objects.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "labelSelector")]
    pub label_selector: Option<ServiceBindingApplicationLabelSelector>,
    /// Name of the referent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Resource of the referent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// Version of the referent.
    pub version: String,
}

/// BindingPath refers to the paths in the application workload's schema where the binding workload would be referenced.  If BindingPath is not specified, then the default path locations are used.  The default location for ContainersPath is "spec.template.spec.containers".  If SecretPath is not specified, then the name of the secret object does not need to be specified.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ServiceBindingApplicationBindingPath {
    /// ContainersPath defines the path to the corev1.Containers reference. If BindingPath is not specified, the default location is "spec.template.spec.containers".
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "containersPath")]
    pub containers_path: Option<String>,
    /// SecretPath defines the path to a string field where the name of the secret object is going to be assigned.  Note: The name of the secret object is same as that of the name of service binding custom resource (metadata.name).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretPath")]
    pub secret_path: Option<String>,
}

/// A label selector is a label query over a set of resources. The result of matchLabels and matchExpressions are ANDed. An empty label selector matches all objects. A null label selector matches no objects.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ServiceBindingApplicationLabelSelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<ServiceBindingApplicationLabelSelectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ServiceBindingApplicationLabelSelectorMatchExpressions {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// ServiceBindingMapping defines a new binding from a set of existing bindings.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ServiceBindingMappings {
    /// Name is the name of new binding.
    pub name: String,
    /// Value specificies a go template that will be rendered and injected into the application.
    pub value: String,
}

/// Service defines the selector based on resource name, version, and resource kind.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ServiceBindingServices {
    /// Group of the referent.
    pub group: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Kind of the referent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Name of the referent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Namespace of the referent.  If unspecified, assumes the same namespace as ServiceBinding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Resource of the referent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// Version of the referent.
    pub version: String,
}

/// ServiceBindingStatus defines the observed state of ServiceBinding.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ServiceBindingStatus {
    /// Conditions describes the state of the operator's reconciliation functionality.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// Secret indicates the name of the binding secret.
    pub secret: String,
}

