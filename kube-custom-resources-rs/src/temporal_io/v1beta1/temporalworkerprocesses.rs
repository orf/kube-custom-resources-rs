// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/alexandrevilain/temporal-operator/temporal.io/v1beta1/temporalworkerprocesses.yaml --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// TemporalWorkerProcessSpec defines the desired state of TemporalWorkerProcess.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "temporal.io", version = "v1beta1", kind = "TemporalWorkerProcess", plural = "temporalworkerprocesses")]
#[kube(namespaced)]
#[kube(status = "TemporalWorkerProcessStatus")]
#[kube(schema = "disabled")]
pub struct TemporalWorkerProcessSpec {
    /// Builder is the configuration for building a TemporalWorkerProcess. THIS FEATURE IS HIGHLY EXPERIMENTAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder: Option<TemporalWorkerProcessBuilder>,
    /// Reference to the temporal cluster the worker will connect to.
    #[serde(rename = "clusterRef")]
    pub cluster_ref: TemporalWorkerProcessClusterRef,
    /// Image defines the temporal worker docker image the instance should run.
    pub image: String,
    /// An optional list of references to secrets in the same namespace to use for pulling temporal images from registries.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "imagePullSecrets")]
    pub image_pull_secrets: Option<Vec<TemporalWorkerProcessImagePullSecrets>>,
    /// JobTTLSecondsAfterFinished is amount of time to keep job pods after jobs are completed. Defaults to 300 seconds.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "jobTtlSecondsAfterFinished")]
    pub job_ttl_seconds_after_finished: Option<i32>,
    /// Image pull policy for determining how to pull worker process images.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "pullPolicy")]
    pub pull_policy: Option<String>,
    /// Number of desired replicas. Default to 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<i32>,
    /// TemporalNamespace that worker will poll.
    #[serde(rename = "temporalNamespace")]
    pub temporal_namespace: String,
    /// Version defines the worker process version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Builder is the configuration for building a TemporalWorkerProcess. THIS FEATURE IS HIGHLY EXPERIMENTAL.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TemporalWorkerProcessBuilder {
    /// BuildAttempt is the build attempt number of a given version
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<i32>,
    /// BuildDir is the location of where the sources will be built.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "buildDir")]
    pub build_dir: Option<String>,
    /// BuildRegistry specifies how to connect to container registry.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "buildRegistry")]
    pub build_registry: Option<TemporalWorkerProcessBuilderBuildRegistry>,
    /// Enabled defines if the operator should build the temporal worker process.
    pub enabled: bool,
    /// GitRepository specifies how to connect to Git source control.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "gitRepository")]
    pub git_repository: Option<TemporalWorkerProcessBuilderGitRepository>,
    /// Image is the image that will be used to build worker image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Version is the version of the image that will be used to build worker image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// BuildRegistry specifies how to connect to container registry.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TemporalWorkerProcessBuilderBuildRegistry {
    /// PasswordSecret is the reference to the secret holding the docker repo password.
    #[serde(rename = "passwordSecretRef")]
    pub password_secret_ref: TemporalWorkerProcessBuilderBuildRegistryPasswordSecretRef,
    /// Repository is the fqdn to the image repo.
    pub repository: String,
    /// Username is the username for the container repo.
    pub username: String,
}

/// PasswordSecret is the reference to the secret holding the docker repo password.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TemporalWorkerProcessBuilderBuildRegistryPasswordSecretRef {
    /// Key in the Secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Name of the Secret.
    pub name: String,
}

/// GitRepository specifies how to connect to Git source control.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TemporalWorkerProcessBuilderGitRepository {
    /// Reference specifies the Git reference to resolve and monitor for changes, defaults to the 'master' branch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<TemporalWorkerProcessBuilderGitRepositoryReference>,
    /// URL specifies the Git repository URL, it can be an HTTP/S or SSH address.
    pub url: String,
}

/// Reference specifies the Git reference to resolve and monitor for changes, defaults to the 'master' branch.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TemporalWorkerProcessBuilderGitRepositoryReference {
    /// Branch to check out, defaults to 'main' if no other field is defined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
}

/// Reference to the temporal cluster the worker will connect to.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TemporalWorkerProcessClusterRef {
    /// The name of the TemporalCluster to reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The namespace of the TemporalCluster to reference. Defaults to the namespace of the requested resource if omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// LocalObjectReference contains enough information to let you locate the referenced object inside the same namespace.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TemporalWorkerProcessImagePullSecrets {
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// TemporalWorkerProcessStatus defines the observed state of TemporalWorkerProcess.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TemporalWorkerProcessStatus {
    /// BuildAttempt is the build attempt number of a given version
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<i32>,
    /// Conditions represent the latest available observations of the worker process state.
    pub conditions: Vec<Condition>,
    /// Created indicates if the worker process image was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<bool>,
    /// Ready defines if the worker process is ready.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<bool>,
    /// Version is the version of the image that will be used to build worker image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

