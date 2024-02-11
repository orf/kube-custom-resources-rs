// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/3scale/3scale-operator/capabilities.3scale.net/v1beta1/developerusers.yaml --derive=Default --derive=PartialEq
// kopium version: 0.16.5

use kube::CustomResource;
use serde::{Serialize, Deserialize};

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
    pub conditions: Option<Vec<DeveloperUserStatusConditions>>,
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

/// Condition represents an observation of an object's state. Conditions are an extension mechanism intended to be used when the details of an observation are not a priori known or would not apply to all instances of a given Kind. 
///  Conditions should be added to explicitly convey properties that users and components care about rather than requiring those properties to be inferred from other observations. Once defined, the meaning of a Condition can not be changed arbitrarily - it becomes part of the API, and has the same backwards- and forwards-compatibility concerns of any other part of the API.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct DeveloperUserStatusConditions {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastTransitionTime")]
    pub last_transition_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// ConditionReason is intended to be a one-word, CamelCase representation of the category of cause of the current status. It is intended to be used in concise output, such as one-line kubectl get output, and in summarizing occurrences of causes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub status: String,
    /// ConditionType is the type of the condition and is typically a CamelCased word or short phrase. 
    ///  Condition types should indicate state in the "abnormal-true" polarity. For example, if the condition indicates when a policy is invalid, the "is valid" case is probably the norm, so the condition should be called "Invalid".
    #[serde(rename = "type")]
    pub r#type: String,
}
