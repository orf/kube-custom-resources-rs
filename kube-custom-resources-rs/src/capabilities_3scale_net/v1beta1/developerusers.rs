// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/3scale/3scale-operator/capabilities.3scale.net/v1beta1/developerusers.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// DeveloperUserSpec defines the desired state of DeveloperUser
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "capabilities.3scale.net", version = "v1beta1", kind = "DeveloperUser", plural = "developerusers")]
#[kube(namespaced)]
#[kube(status = "DeveloperUserStatus")]
#[kube(schema = "disabled")]
pub struct DeveloperUserSpec {
    /// DeveloperAccountRef is the reference to the parent developer account
    #[serde(rename = "developerAccountRef")]
    pub developer_account_ref: DeveloperUserDeveloperAccountRef,
    /// Email
    pub email: String,
    /// Password
    #[serde(rename = "passwordCredentialsRef")]
    pub password_credentials_ref: DeveloperUserPasswordCredentialsRef,
    /// ProviderAccountRef references account provider credentials
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "providerAccountRef")]
    pub provider_account_ref: Option<DeveloperUserProviderAccountRef>,
    /// Role defines the desired 3scale role. Defaults to "member"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<DeveloperUserRole>,
    /// State defines the desired state. Defaults to "false", ie, active
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspended: Option<bool>,
    /// Username
    pub username: String,
}

/// DeveloperAccountRef is the reference to the parent developer account
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct DeveloperUserDeveloperAccountRef {
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Password
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct DeveloperUserPasswordCredentialsRef {
    /// name is unique within a namespace to reference a secret resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// namespace defines the space within which the secret name must be unique.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// ProviderAccountRef references account provider credentials
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct DeveloperUserProviderAccountRef {
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// DeveloperUserSpec defines the desired state of DeveloperUser
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum DeveloperUserRole {
    #[serde(rename = "admin")]
    Admin,
    #[serde(rename = "member")]
    Member,
}

/// DeveloperUserStatus defines the observed state of DeveloperUser
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct DeveloperUserStatus {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "accoundID")]
    pub accound_id: Option<i64>,
    /// Current state of the 3scale backend. Conditions represent the latest available observations of an object's state
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "developerUserID")]
    pub developer_user_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "developerUserState")]
    pub developer_user_state: Option<String>,
    /// ObservedGeneration reflects the generation of the most recently observed Backend Spec.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
    /// 3scale control plane host
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "providerAccountHost")]
    pub provider_account_host: Option<String>,
}

