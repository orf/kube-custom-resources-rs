// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/FairwindsOps/rbac-manager/rbacmanager.reactiveops.io/v1beta1/rbacdefinitions.yaml --derive=PartialEq
// kopium version: 0.18.0


use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RBACDefinitionRbacBindings {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clusterRoleBindings")]
    pub cluster_role_bindings: Option<Vec<RBACDefinitionRbacBindingsClusterRoleBindings>>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "roleBindings")]
    pub role_bindings: Option<Vec<RBACDefinitionRbacBindingsRoleBindings>>,
    pub subjects: Vec<RBACDefinitionRbacBindingsSubjects>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RBACDefinitionRbacBindingsClusterRoleBindings {
    #[serde(rename = "clusterRole")]
    pub cluster_role: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RBACDefinitionRbacBindingsRoleBindings {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clusterRole")]
    pub cluster_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "namespaceSelector")]
    pub namespace_selector: Option<RBACDefinitionRbacBindingsRoleBindingsNamespaceSelector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RBACDefinitionRbacBindingsRoleBindingsNamespaceSelector {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<RBACDefinitionRbacBindingsRoleBindingsNamespaceSelectorMatchExpressions>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RBACDefinitionRbacBindingsRoleBindingsNamespaceSelectorMatchExpressions {
    pub key: String,
    pub operator: RBACDefinitionRbacBindingsRoleBindingsNamespaceSelectorMatchExpressionsOperator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum RBACDefinitionRbacBindingsRoleBindingsNamespaceSelectorMatchExpressionsOperator {
    Exists,
    DoesNotExist,
    In,
    NotIn,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RBACDefinitionRbacBindingsSubjects {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "automountServiceAccountToken")]
    pub automount_service_account_token: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "imagePullSecrets")]
    pub image_pull_secrets: Option<Vec<String>>,
    pub kind: RBACDefinitionRbacBindingsSubjectsKind,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum RBACDefinitionRbacBindingsSubjectsKind {
    Group,
    ServiceAccount,
    User,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RBACDefinitionStatus {
}

