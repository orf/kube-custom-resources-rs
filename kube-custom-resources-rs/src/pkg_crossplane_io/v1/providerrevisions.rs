// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/crossplane/crossplane/pkg.crossplane.io/v1/providerrevisions.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// ProviderRevisionSpec specifies configuration for a ProviderRevision.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "pkg.crossplane.io", version = "v1", kind = "ProviderRevision", plural = "providerrevisions")]
#[kube(status = "ProviderRevisionStatus")]
#[kube(schema = "disabled")]
pub struct ProviderRevisionSpec {
    /// Map of string keys and values that can be used to organize and categorize
    /// (scope and select) objects. May match selectors of replication controllers
    /// and services.
    /// More info: http://kubernetes.io/docs/user-guide/labels
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "commonLabels")]
    pub common_labels: Option<BTreeMap<String, String>>,
    /// ControllerConfigRef references a ControllerConfig resource that will be
    /// used to configure the packaged controller Deployment.
    /// Deprecated: Use RuntimeConfigReference instead.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "controllerConfigRef")]
    pub controller_config_ref: Option<ProviderRevisionControllerConfigRef>,
    /// DesiredState of the PackageRevision. Can be either Active or Inactive.
    #[serde(rename = "desiredState")]
    pub desired_state: String,
    /// IgnoreCrossplaneConstraints indicates to the package manager whether to
    /// honor Crossplane version constrains specified by the package.
    /// Default is false.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ignoreCrossplaneConstraints")]
    pub ignore_crossplane_constraints: Option<bool>,
    /// Package image used by install Pod to extract package contents.
    pub image: String,
    /// PackagePullPolicy defines the pull policy for the package. It is also
    /// applied to any images pulled for the package, such as a provider's
    /// controller image.
    /// Default is IfNotPresent.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "packagePullPolicy")]
    pub package_pull_policy: Option<String>,
    /// PackagePullSecrets are named secrets in the same namespace that can be
    /// used to fetch packages from private registries. They are also applied to
    /// any images pulled for the package, such as a provider's controller image.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "packagePullSecrets")]
    pub package_pull_secrets: Option<Vec<ProviderRevisionPackagePullSecrets>>,
    /// Revision number. Indicates when the revision will be garbage collected
    /// based on the parent's RevisionHistoryLimit.
    pub revision: i64,
    /// RuntimeConfigRef references a RuntimeConfig resource that will be used
    /// to configure the package runtime.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "runtimeConfigRef")]
    pub runtime_config_ref: Option<ProviderRevisionRuntimeConfigRef>,
    /// SkipDependencyResolution indicates to the package manager whether to skip
    /// resolving dependencies for a package. Setting this value to true may have
    /// unintended consequences.
    /// Default is false.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "skipDependencyResolution")]
    pub skip_dependency_resolution: Option<bool>,
    /// TLSClientSecretName is the name of the TLS Secret that stores client
    /// certificates of the Provider.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "tlsClientSecretName")]
    pub tls_client_secret_name: Option<String>,
    /// TLSServerSecretName is the name of the TLS Secret that stores server
    /// certificates of the Provider.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "tlsServerSecretName")]
    pub tls_server_secret_name: Option<String>,
}

/// ControllerConfigRef references a ControllerConfig resource that will be
/// used to configure the packaged controller Deployment.
/// Deprecated: Use RuntimeConfigReference instead.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ProviderRevisionControllerConfigRef {
    /// Name of the ControllerConfig.
    pub name: String,
}

/// LocalObjectReference contains enough information to let you locate the
/// referenced object inside the same namespace.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ProviderRevisionPackagePullSecrets {
    /// Name of the referent.
    /// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
    /// TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// RuntimeConfigRef references a RuntimeConfig resource that will be used
/// to configure the package runtime.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ProviderRevisionRuntimeConfigRef {
    /// API version of the referent.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiVersion")]
    pub api_version: Option<String>,
    /// Kind of the referent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Name of the RuntimeConfig.
    pub name: String,
}

/// PackageRevisionStatus represents the observed state of a PackageRevision.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ProviderRevisionStatus {
    /// Conditions of the resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// Dependency information.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "foundDependencies")]
    pub found_dependencies: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "installedDependencies")]
    pub installed_dependencies: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "invalidDependencies")]
    pub invalid_dependencies: Option<i64>,
    /// References to objects owned by PackageRevision.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "objectRefs")]
    pub object_refs: Option<Vec<ProviderRevisionStatusObjectRefs>>,
    /// PermissionRequests made by this package. The package declares that its
    /// controller needs these permissions to run. The RBAC manager is
    /// responsible for granting them.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "permissionRequests")]
    pub permission_requests: Option<Vec<ProviderRevisionStatusPermissionRequests>>,
}

/// A TypedReference refers to an object by Name, Kind, and APIVersion. It is
/// commonly used to reference cluster-scoped objects or objects where the
/// namespace is already known.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ProviderRevisionStatusObjectRefs {
    /// APIVersion of the referenced object.
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    /// Kind of the referenced object.
    pub kind: String,
    /// Name of the referenced object.
    pub name: String,
    /// UID of the referenced object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
}

/// PolicyRule holds information that describes a policy rule, but does not contain information
/// about who the rule applies to or which namespace the rule applies to.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ProviderRevisionStatusPermissionRequests {
    /// APIGroups is the name of the APIGroup that contains the resources.  If multiple API groups are specified, any action requested against one of
    /// the enumerated resources in any API group will be allowed. "" represents the core API group and "*" represents all API groups.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiGroups")]
    pub api_groups: Option<Vec<String>>,
    /// NonResourceURLs is a set of partial urls that a user should have access to.  *s are allowed, but only as the full, final step in the path
    /// Since non-resource URLs are not namespaced, this field is only applicable for ClusterRoles referenced from a ClusterRoleBinding.
    /// Rules can either apply to API resources (such as "pods" or "secrets") or non-resource URL paths (such as "/api"),  but not both.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nonResourceURLs")]
    pub non_resource_ur_ls: Option<Vec<String>>,
    /// ResourceNames is an optional white list of names that the rule applies to.  An empty set means that everything is allowed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "resourceNames")]
    pub resource_names: Option<Vec<String>>,
    /// Resources is a list of resources this rule applies to. '*' represents all resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<String>>,
    /// Verbs is a list of Verbs that apply to ALL the ResourceKinds contained in this rule. '*' represents all verbs.
    pub verbs: Vec<String>,
}

