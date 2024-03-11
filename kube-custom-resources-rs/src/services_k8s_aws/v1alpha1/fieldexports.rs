// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/eks-controller/services.k8s.aws/v1alpha1/fieldexports.yaml --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// FieldExportSpec defines the desired state of the FieldExport.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "services.k8s.aws", version = "v1alpha1", kind = "FieldExport", plural = "fieldexports")]
#[kube(namespaced)]
#[kube(status = "FieldExportStatus")]
#[kube(schema = "disabled")]
pub struct FieldExportSpec {
    /// ResourceFieldSelector provides the values necessary to identify an individual
    /// field on an individual K8s resource.
    pub from: FieldExportFrom,
    /// FieldExportTarget provides the values necessary to identify the
    /// output path for a field export.
    pub to: FieldExportTo,
}

/// ResourceFieldSelector provides the values necessary to identify an individual
/// field on an individual K8s resource.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FieldExportFrom {
    pub path: String,
    /// NamespacedResource provides all the values necessary to identify an ACK
    /// resource of a given type (within the same namespace as the custom resource
    /// containing this type).
    pub resource: FieldExportFromResource,
}

/// NamespacedResource provides all the values necessary to identify an ACK
/// resource of a given type (within the same namespace as the custom resource
/// containing this type).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FieldExportFromResource {
    pub group: String,
    pub kind: String,
    pub name: String,
}

/// FieldExportTarget provides the values necessary to identify the
/// output path for a field export.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FieldExportTo {
    /// Key overrides the default value (`<namespace>.<FieldExport-resource-name>`) for the FieldExport target
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// FieldExportOutputType represents all types that can be produced by a field
    /// export operation
    pub kind: FieldExportToKind,
    pub name: String,
    /// Namespace is marked as optional, so we cannot compose `NamespacedName`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// FieldExportTarget provides the values necessary to identify the
/// output path for a field export.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum FieldExportToKind {
    #[serde(rename = "configmap")]
    Configmap,
    #[serde(rename = "secret")]
    Secret,
}

/// FieldExportStatus defines the observed status of the FieldExport.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FieldExportStatus {
    /// A collection of `ackv1alpha1.Condition` objects that describe the various
    /// recoverable states of the field CR
    pub conditions: Vec<Condition>,
}

