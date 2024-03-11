// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/fluxcd/source-controller/source.toolkit.fluxcd.io/v1beta1/gitrepositories.yaml --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// GitRepositorySpec defines the desired state of a Git repository.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "source.toolkit.fluxcd.io", version = "v1beta1", kind = "GitRepository", plural = "gitrepositories")]
#[kube(namespaced)]
#[kube(status = "GitRepositoryStatus")]
#[kube(schema = "disabled")]
pub struct GitRepositorySpec {
    /// AccessFrom defines an Access Control List for allowing cross-namespace references to this object.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "accessFrom")]
    pub access_from: Option<GitRepositoryAccessFrom>,
    /// Determines which git client library to use. Defaults to go-git, valid values are ('go-git', 'libgit2').
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "gitImplementation")]
    pub git_implementation: Option<GitRepositoryGitImplementation>,
    /// Ignore overrides the set of excluded patterns in the .sourceignore format (which is the same as .gitignore). If not provided, a default will be used, consult the documentation for your version to find out what those are.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ignore: Option<String>,
    /// Extra git repositories to map into the repository
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include: Option<Vec<GitRepositoryInclude>>,
    /// The interval at which to check for repository updates.
    pub interval: String,
    /// When enabled, after the clone is created, initializes all submodules within, using their default settings. This option is available only when using the 'go-git' GitImplementation.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "recurseSubmodules")]
    pub recurse_submodules: Option<bool>,
    /// The Git reference to checkout and monitor for changes, defaults to master branch.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ref")]
    pub r#ref: Option<GitRepositoryRef>,
    /// The secret name containing the Git credentials. For HTTPS repositories the secret must contain username and password fields. For SSH repositories the secret must contain identity and known_hosts fields.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretRef")]
    pub secret_ref: Option<GitRepositorySecretRef>,
    /// This flag tells the controller to suspend the reconciliation of this source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspend: Option<bool>,
    /// The timeout for remote Git operations like cloning, defaults to 60s.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
    /// The repository URL, can be a HTTP/S or SSH address.
    pub url: String,
    /// Verify OpenPGP signature for the Git commit HEAD points to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify: Option<GitRepositoryVerify>,
}

/// AccessFrom defines an Access Control List for allowing cross-namespace references to this object.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GitRepositoryAccessFrom {
    /// NamespaceSelectors is the list of namespace selectors to which this ACL applies. Items in this list are evaluated using a logical OR operation.
    #[serde(rename = "namespaceSelectors")]
    pub namespace_selectors: Vec<GitRepositoryAccessFromNamespaceSelectors>,
}

/// NamespaceSelector selects the namespaces to which this ACL applies. An empty map of MatchLabels matches all namespaces in a cluster.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GitRepositoryAccessFromNamespaceSelectors {
    /// MatchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// GitRepositorySpec defines the desired state of a Git repository.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum GitRepositoryGitImplementation {
    #[serde(rename = "go-git")]
    GoGit,
    #[serde(rename = "libgit2")]
    Libgit2,
}

/// GitRepositoryInclude defines a source with a from and to path.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GitRepositoryInclude {
    /// The path to copy contents from, defaults to the root directory.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "fromPath")]
    pub from_path: Option<String>,
    /// Reference to a GitRepository to include.
    pub repository: GitRepositoryIncludeRepository,
    /// The path to copy contents to, defaults to the name of the source ref.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "toPath")]
    pub to_path: Option<String>,
}

/// Reference to a GitRepository to include.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GitRepositoryIncludeRepository {
    /// Name of the referent.
    pub name: String,
}

/// The Git reference to checkout and monitor for changes, defaults to master branch.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GitRepositoryRef {
    /// The Git branch to checkout, defaults to master.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// The Git commit SHA to checkout, if specified Tag filters will be ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// The Git tag semver expression, takes precedence over Tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semver: Option<String>,
    /// The Git tag to checkout, takes precedence over Branch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

/// The secret name containing the Git credentials. For HTTPS repositories the secret must contain username and password fields. For SSH repositories the secret must contain identity and known_hosts fields.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GitRepositorySecretRef {
    /// Name of the referent.
    pub name: String,
}

/// Verify OpenPGP signature for the Git commit HEAD points to.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GitRepositoryVerify {
    /// Mode describes what git object should be verified, currently ('head').
    pub mode: GitRepositoryVerifyMode,
    /// The secret name containing the public keys of all trusted Git authors.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretRef")]
    pub secret_ref: Option<GitRepositoryVerifySecretRef>,
}

/// Verify OpenPGP signature for the Git commit HEAD points to.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum GitRepositoryVerifyMode {
    #[serde(rename = "head")]
    Head,
}

/// The secret name containing the public keys of all trusted Git authors.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GitRepositoryVerifySecretRef {
    /// Name of the referent.
    pub name: String,
}

/// GitRepositoryStatus defines the observed state of a Git repository.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GitRepositoryStatus {
    /// Artifact represents the output of the last successful repository sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<GitRepositoryStatusArtifact>,
    /// Conditions holds the conditions for the GitRepository.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// IncludedArtifacts represents the included artifacts from the last successful repository sync.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "includedArtifacts")]
    pub included_artifacts: Option<Vec<GitRepositoryStatusIncludedArtifacts>>,
    /// LastHandledReconcileAt holds the value of the most recent reconcile request value, so a change of the annotation value can be detected.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastHandledReconcileAt")]
    pub last_handled_reconcile_at: Option<String>,
    /// ObservedGeneration is the last observed generation.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
    /// URL is the download link for the artifact output of the last repository sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Artifact represents the output of the last successful repository sync.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GitRepositoryStatusArtifact {
    /// Checksum is the SHA256 checksum of the artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
    /// LastUpdateTime is the timestamp corresponding to the last update of this artifact.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastUpdateTime")]
    pub last_update_time: Option<String>,
    /// Path is the relative file path of this artifact.
    pub path: String,
    /// Revision is a human readable identifier traceable in the origin source system. It can be a Git commit SHA, Git tag, a Helm index timestamp, a Helm chart version, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    /// URL is the HTTP address of this artifact.
    pub url: String,
}

/// Artifact represents the output of a source synchronisation.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GitRepositoryStatusIncludedArtifacts {
    /// Checksum is the SHA256 checksum of the artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
    /// LastUpdateTime is the timestamp corresponding to the last update of this artifact.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastUpdateTime")]
    pub last_update_time: Option<String>,
    /// Path is the relative file path of this artifact.
    pub path: String,
    /// Revision is a human readable identifier traceable in the origin source system. It can be a Git commit SHA, Git tag, a Helm index timestamp, a Helm chart version, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    /// URL is the HTTP address of this artifact.
    pub url: String,
}

