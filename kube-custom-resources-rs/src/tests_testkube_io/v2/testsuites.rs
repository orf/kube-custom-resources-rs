// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kubeshop/testkube-operator/tests.testkube.io/v2/testsuites.yaml --derive=Default --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use std::collections::BTreeMap;
    pub use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
}
use self::prelude::*;

/// TestSuiteSpec defines the desired state of TestSuite
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "tests.testkube.io", version = "v2", kind = "TestSuite", plural = "testsuites")]
#[kube(namespaced)]
#[kube(status = "TestSuiteStatus")]
#[kube(schema = "disabled")]
#[kube(derive="Default")]
#[kube(derive="PartialEq")]
pub struct TestSuiteSpec {
    /// After steps is list of tests which will be sequentially orchestrated
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Vec<TestSuiteAfter>>,
    /// Before steps is list of tests which will be sequentially orchestrated
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<Vec<TestSuiteBefore>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// TestSuiteExecutionRequest defines the execution request body
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "executionRequest")]
    pub execution_request: Option<TestSuiteExecutionRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repeats: Option<i64>,
    /// schedule in cron job format for scheduled test execution
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
    /// Steps is list of tests which will be sequentially orchestrated
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub steps: Option<Vec<TestSuiteSteps>>,
}

/// TestSuiteStepSpec for particular type will have config for possible step types
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TestSuiteAfter {
    /// TestSuiteStepDelay contains step delay parameters
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay: Option<TestSuiteAfterDelay>,
    /// TestSuiteStepExecute defines step to be executed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execute: Option<TestSuiteAfterExecute>,
    /// TestSuiteStepType defines different type of test suite steps
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<TestSuiteAfterType>,
}

/// TestSuiteStepDelay contains step delay parameters
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TestSuiteAfterDelay {
    /// Duration in ms
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration: Option<i32>,
}

/// TestSuiteStepExecute defines step to be executed
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TestSuiteAfterExecute {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "stopOnFailure")]
    pub stop_on_failure: Option<bool>,
}

/// TestSuiteStepSpec for particular type will have config for possible step types
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum TestSuiteAfterType {
    #[serde(rename = "execute")]
    Execute,
    #[serde(rename = "delay")]
    Delay,
}

/// TestSuiteStepSpec for particular type will have config for possible step types
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TestSuiteBefore {
    /// TestSuiteStepDelay contains step delay parameters
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay: Option<TestSuiteBeforeDelay>,
    /// TestSuiteStepExecute defines step to be executed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execute: Option<TestSuiteBeforeExecute>,
    /// TestSuiteStepType defines different type of test suite steps
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<TestSuiteBeforeType>,
}

/// TestSuiteStepDelay contains step delay parameters
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TestSuiteBeforeDelay {
    /// Duration in ms
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration: Option<i32>,
}

/// TestSuiteStepExecute defines step to be executed
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TestSuiteBeforeExecute {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "stopOnFailure")]
    pub stop_on_failure: Option<bool>,
}

/// TestSuiteStepSpec for particular type will have config for possible step types
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum TestSuiteBeforeType {
    #[serde(rename = "execute")]
    Execute,
    #[serde(rename = "delay")]
    Delay,
}

/// TestSuiteExecutionRequest defines the execution request body
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TestSuiteExecutionRequest {
    /// cron job template extensions
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "cronJobTemplate")]
    pub cron_job_template: Option<String>,
    /// execution labels
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "executionLabels")]
    pub execution_labels: Option<BTreeMap<String, String>>,
    /// http proxy for executor containers
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "httpProxy")]
    pub http_proxy: Option<String>,
    /// https proxy for executor containers
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "httpsProxy")]
    pub https_proxy: Option<String>,
    /// test suite labels
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    /// test execution custom name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// test kubernetes namespace (\"testkube\" when not set)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// secret uuid
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretUUID")]
    pub secret_uuid: Option<String>,
    /// whether to start execution sync or async
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync: Option<bool>,
    /// timeout for test suite execution
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variables: Option<BTreeMap<String, TestSuiteExecutionRequestVariables>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TestSuiteExecutionRequestVariables {
    /// variable name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// variable type
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
    /// variable string value
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// or load it from var source
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "valueFrom")]
    pub value_from: Option<TestSuiteExecutionRequestVariablesValueFrom>,
}

/// or load it from var source
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TestSuiteExecutionRequestVariablesValueFrom {
    /// Selects a key of a ConfigMap.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "configMapKeyRef")]
    pub config_map_key_ref: Option<TestSuiteExecutionRequestVariablesValueFromConfigMapKeyRef>,
    /// Selects a field of the pod: supports metadata.name, metadata.namespace, `metadata.labels['<KEY>']`, `metadata.annotations['<KEY>']`, spec.nodeName, spec.serviceAccountName, status.hostIP, status.podIP, status.podIPs.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "fieldRef")]
    pub field_ref: Option<TestSuiteExecutionRequestVariablesValueFromFieldRef>,
    /// Selects a resource of the container: only resources limits and requests (limits.cpu, limits.memory, limits.ephemeral-storage, requests.cpu, requests.memory and requests.ephemeral-storage) are currently supported.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "resourceFieldRef")]
    pub resource_field_ref: Option<TestSuiteExecutionRequestVariablesValueFromResourceFieldRef>,
    /// Selects a key of a secret in the pod's namespace
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretKeyRef")]
    pub secret_key_ref: Option<TestSuiteExecutionRequestVariablesValueFromSecretKeyRef>,
}

/// Selects a key of a ConfigMap.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TestSuiteExecutionRequestVariablesValueFromConfigMapKeyRef {
    /// The key to select.
    pub key: String,
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Specify whether the ConfigMap or its key must be defined
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// Selects a field of the pod: supports metadata.name, metadata.namespace, `metadata.labels['<KEY>']`, `metadata.annotations['<KEY>']`, spec.nodeName, spec.serviceAccountName, status.hostIP, status.podIP, status.podIPs.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TestSuiteExecutionRequestVariablesValueFromFieldRef {
    /// Version of the schema the FieldPath is written in terms of, defaults to "v1".
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiVersion")]
    pub api_version: Option<String>,
    /// Path of the field to select in the specified API version.
    #[serde(rename = "fieldPath")]
    pub field_path: String,
}

/// Selects a resource of the container: only resources limits and requests (limits.cpu, limits.memory, limits.ephemeral-storage, requests.cpu, requests.memory and requests.ephemeral-storage) are currently supported.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TestSuiteExecutionRequestVariablesValueFromResourceFieldRef {
    /// Container name: required for volumes, optional for env vars
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "containerName")]
    pub container_name: Option<String>,
    /// Specifies the output format of the exposed resources, defaults to "1"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub divisor: Option<IntOrString>,
    /// Required: resource to select
    pub resource: String,
}

/// Selects a key of a secret in the pod's namespace
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TestSuiteExecutionRequestVariablesValueFromSecretKeyRef {
    /// The key of the secret to select from.  Must be a valid secret key.
    pub key: String,
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Specify whether the Secret or its key must be defined
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// TestSuiteStepSpec for particular type will have config for possible step types
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TestSuiteSteps {
    /// TestSuiteStepDelay contains step delay parameters
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay: Option<TestSuiteStepsDelay>,
    /// TestSuiteStepExecute defines step to be executed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execute: Option<TestSuiteStepsExecute>,
    /// TestSuiteStepType defines different type of test suite steps
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<TestSuiteStepsType>,
}

/// TestSuiteStepDelay contains step delay parameters
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TestSuiteStepsDelay {
    /// Duration in ms
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration: Option<i32>,
}

/// TestSuiteStepExecute defines step to be executed
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TestSuiteStepsExecute {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "stopOnFailure")]
    pub stop_on_failure: Option<bool>,
}

/// TestSuiteStepSpec for particular type will have config for possible step types
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum TestSuiteStepsType {
    #[serde(rename = "execute")]
    Execute,
    #[serde(rename = "delay")]
    Delay,
}

/// TestSuiteStatus defines the observed state of TestSuite
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TestSuiteStatus {
    /// latest execution result
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "latestExecution")]
    pub latest_execution: Option<TestSuiteStatusLatestExecution>,
}

/// latest execution result
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TestSuiteStatusLatestExecution {
    /// test suite execution end time
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "endTime")]
    pub end_time: Option<String>,
    /// execution id
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// test suite execution start time
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "startTime")]
    pub start_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<TestSuiteStatusLatestExecutionStatus>,
}

/// latest execution result
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum TestSuiteStatusLatestExecutionStatus {
    #[serde(rename = "queued")]
    Queued,
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "passed")]
    Passed,
    #[serde(rename = "failed")]
    Failed,
    #[serde(rename = "aborting")]
    Aborting,
    #[serde(rename = "aborted")]
    Aborted,
    #[serde(rename = "timeout")]
    Timeout,
}

