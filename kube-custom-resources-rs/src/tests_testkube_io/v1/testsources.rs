// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kubeshop/testkube-operator/tests.testkube.io/v1/testsources.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// TestSourceSpec defines the desired state of TestSource
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "tests.testkube.io", version = "v1", kind = "TestSource", plural = "testsources")]
#[kube(namespaced)]
#[kube(status = "TestSourceStatus")]
#[kube(schema = "disabled")]
pub struct TestSourceSpec {
    /// test content body
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// repository of test content
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<TestSourceRepository>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<TestSourceType>,
    /// uri of test content
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

/// repository of test content
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TestSourceRepository {
    /// auth type for git requests
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "authType")]
    pub auth_type: Option<TestSourceRepositoryAuthType>,
    /// branch/tag name for checkout
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// git auth certificate secret for private repositories
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "certificateSecret")]
    pub certificate_secret: Option<String>,
    /// commit id (sha) for checkout
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// If specified, does a sparse checkout of the repository at the given path
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// SecretRef is the Testkube internal reference for secret storage in Kubernetes secrets
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "tokenSecret")]
    pub token_secret: Option<TestSourceRepositoryTokenSecret>,
    /// VCS repository type
    #[serde(rename = "type")]
    pub r#type: String,
    /// uri of content file or git directory
    pub uri: String,
    /// SecretRef is the Testkube internal reference for secret storage in Kubernetes secrets
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "usernameSecret")]
    pub username_secret: Option<TestSourceRepositoryUsernameSecret>,
    /// if provided we checkout the whole repository and run test from this directory
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "workingDir")]
    pub working_dir: Option<String>,
}

/// repository of test content
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum TestSourceRepositoryAuthType {
    #[serde(rename = "basic")]
    Basic,
    #[serde(rename = "header")]
    Header,
}

/// SecretRef is the Testkube internal reference for secret storage in Kubernetes secrets
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TestSourceRepositoryTokenSecret {
    /// object key
    pub key: String,
    /// object name
    pub name: String,
}

/// SecretRef is the Testkube internal reference for secret storage in Kubernetes secrets
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TestSourceRepositoryUsernameSecret {
    /// object key
    pub key: String,
    /// object name
    pub name: String,
}

/// TestSourceSpec defines the desired state of TestSource
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum TestSourceType {
    #[serde(rename = "string")]
    String,
    #[serde(rename = "file-uri")]
    FileUri,
    #[serde(rename = "git-file")]
    GitFile,
    #[serde(rename = "git-dir")]
    GitDir,
    #[serde(rename = "git")]
    Git,
}

/// TestSourceStatus defines the observed state of TestSource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TestSourceStatus {
}

