// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/mariadb-operator/mariadb-operator/mariadb.mmontes.io/v1alpha1/connections.yaml --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// ConnectionSpec defines the desired state of Connection
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "mariadb.mmontes.io", version = "v1alpha1", kind = "Connection", plural = "connections")]
#[kube(namespaced)]
#[kube(status = "ConnectionStatus")]
#[kube(schema = "disabled")]
pub struct ConnectionSpec {
    /// Database to use when configuring the Connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    /// HealthCheck to be used in the Connection.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "healthCheck")]
    pub health_check: Option<ConnectionHealthCheck>,
    /// Host to connect to. If not provided, it defaults to the MariaDB host or to the MaxScale host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// MariaDBRef is a reference to the MariaDB to connect to. Either MariaDBRef or MaxScaleRef must be provided.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "mariaDbRef")]
    pub maria_db_ref: Option<ConnectionMariaDbRef>,
    /// MaxScaleRef is a reference to the MaxScale to connect to. Either MariaDBRef or MaxScaleRef must be provided.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxScaleRef")]
    pub max_scale_ref: Option<ConnectionMaxScaleRef>,
    /// Params to be used in the Connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<BTreeMap<String, String>>,
    /// PasswordSecretKeyRef is a reference to the password to use for configuring the Connection.
    #[serde(rename = "passwordSecretKeyRef")]
    pub password_secret_key_ref: ConnectionPasswordSecretKeyRef,
    /// Port to connect to. If not provided, it defaults to the MariaDB port or to the first MaxScale listener.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<i32>,
    /// SecretName to be used in the Connection.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretName")]
    pub secret_name: Option<String>,
    /// SecretTemplate to be used in the Connection.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretTemplate")]
    pub secret_template: Option<ConnectionSecretTemplate>,
    /// ServiceName to be used in the Connection.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "serviceName")]
    pub service_name: Option<String>,
    /// Username to use for configuring the Connection.
    pub username: String,
}

/// HealthCheck to be used in the Connection.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ConnectionHealthCheck {
    /// Interval used to perform health checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,
    /// RetryInterval is the intervañ used to perform health check retries.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "retryInterval")]
    pub retry_interval: Option<String>,
}

/// MariaDBRef is a reference to the MariaDB to connect to. Either MariaDBRef or MaxScaleRef must be provided.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ConnectionMariaDbRef {
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
    /// WaitForIt indicates whether the controller using this reference should wait for MariaDB to be ready.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "waitForIt")]
    pub wait_for_it: Option<bool>,
}

/// MaxScaleRef is a reference to the MaxScale to connect to. Either MariaDBRef or MaxScaleRef must be provided.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ConnectionMaxScaleRef {
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

/// PasswordSecretKeyRef is a reference to the password to use for configuring the Connection.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ConnectionPasswordSecretKeyRef {
    /// The key of the secret to select from.  Must be a valid secret key.
    pub key: String,
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Specify whether the Secret or its key must be defined
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// SecretTemplate to be used in the Connection.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ConnectionSecretTemplate {
    /// Annotations to be added to the Secret object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
    /// DatabaseKey to be used in the Secret.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "databaseKey")]
    pub database_key: Option<String>,
    /// Format to be used in the Secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// HostKey to be used in the Secret.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "hostKey")]
    pub host_key: Option<String>,
    /// Key to be used in the Secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Labels to be added to the Secret object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    /// PasswordKey to be used in the Secret.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "passwordKey")]
    pub password_key: Option<String>,
    /// PortKey to be used in the Secret.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "portKey")]
    pub port_key: Option<String>,
    /// UsernameKey to be used in the Secret.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "usernameKey")]
    pub username_key: Option<String>,
}

/// ConnectionStatus defines the observed state of Connection
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ConnectionStatus {
    /// Conditions for the Connection object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
}

