// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/3scale/3scale-operator/capabilities.3scale.net/v1beta1/activedocs.yaml --derive=Default --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
}
use self::prelude::*;

/// ActiveDocSpec defines the desired state of ActiveDoc
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "capabilities.3scale.net", version = "v1beta1", kind = "ActiveDoc", plural = "activedocs")]
#[kube(namespaced)]
#[kube(status = "ActiveDocStatus")]
#[kube(schema = "disabled")]
#[kube(derive="Default")]
#[kube(derive="PartialEq")]
pub struct ActiveDocSpec {
    /// ActiveDocOpenAPIRef Reference to the OpenAPI Specification
    #[serde(rename = "activeDocOpenAPIRef")]
    pub active_doc_open_api_ref: ActiveDocActiveDocOpenApiRef,
    /// Description is a human readable text of the activedoc
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Name is human readable name for the activedoc
    pub name: String,
    /// ProductSystemName identifies uniquely the product
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "productSystemName")]
    pub product_system_name: Option<String>,
    /// ProviderAccountRef references account provider credentials
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "providerAccountRef")]
    pub provider_account_ref: Option<ActiveDocProviderAccountRef>,
    /// Published switch to publish the activedoc
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published: Option<bool>,
    /// SkipSwaggerValidations switch to skip OpenAPI validation
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "skipSwaggerValidations")]
    pub skip_swagger_validations: Option<bool>,
    /// SystemName identifies uniquely the activedoc within the account provider Default value will be sanitized Name
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "systemName")]
    pub system_name: Option<String>,
}

/// ActiveDocOpenAPIRef Reference to the OpenAPI Specification
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ActiveDocActiveDocOpenApiRef {
    /// SecretRef refers to the secret object that contains the OpenAPI Document
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretRef")]
    pub secret_ref: Option<ActiveDocActiveDocOpenApiRefSecretRef>,
    /// URL Remote URL from where to fetch the OpenAPI Document
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// SecretRef refers to the secret object that contains the OpenAPI Document
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ActiveDocActiveDocOpenApiRefSecretRef {
    /// API version of the referent.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiVersion")]
    pub api_version: Option<String>,
    /// If referring to a piece of an object instead of an entire object, this string should contain a valid JSON/Go field access statement, such as desiredState.manifest.containers[2]. For example, if the object reference is to a container within a pod, this would take on a value like: "spec.containers{name}" (where "name" refers to the name of the container that triggered the event) or if no container name is specified "spec.containers[2]" (container with index 2 in this pod). This syntax is chosen only to have some well-defined way of referencing a part of an object. TODO: this design is not final and this field is subject to change in the future.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "fieldPath")]
    pub field_path: Option<String>,
    /// Kind of the referent. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Namespace of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Specific resourceVersion to which this reference is made, if any. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#concurrency-control-and-consistency
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "resourceVersion")]
    pub resource_version: Option<String>,
    /// UID of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#uids
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
}

/// ProviderAccountRef references account provider credentials
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ActiveDocProviderAccountRef {
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// ActiveDocStatus defines the observed state of ActiveDoc
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ActiveDocStatus {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "activeDocId")]
    pub active_doc_id: Option<i64>,
    /// Current state of the activedoc resource. Conditions represent the latest available observations of an object's state
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// ObservedGeneration reflects the generation of the most recently observed Backend Spec.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
    /// ProductResourceName references the managed 3scale product
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "productResourceName")]
    pub product_resource_name: Option<ActiveDocStatusProductResourceName>,
    /// ProviderAccountHost contains the 3scale account's provider URL
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "providerAccountHost")]
    pub provider_account_host: Option<String>,
}

/// ProductResourceName references the managed 3scale product
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ActiveDocStatusProductResourceName {
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

