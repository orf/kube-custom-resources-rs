// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/fluxcd/image-automation-controller/image.toolkit.fluxcd.io/v1beta2/imageupdateautomations.yaml --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use std::collections::BTreeMap;
    pub use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
}
use self::prelude::*;

/// ImageUpdateAutomationSpec defines the desired state of ImageUpdateAutomation
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "image.toolkit.fluxcd.io", version = "v1beta2", kind = "ImageUpdateAutomation", plural = "imageupdateautomations")]
#[kube(namespaced)]
#[kube(status = "ImageUpdateAutomationStatus")]
#[kube(schema = "disabled")]
#[kube(derive="PartialEq")]
pub struct ImageUpdateAutomationSpec {
    /// GitSpec contains all the git-specific definitions. This is
    /// technically optional, but in practice mandatory until there are
    /// other kinds of source allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<ImageUpdateAutomationGit>,
    /// Interval gives an lower bound for how often the automation
    /// run should be attempted.
    pub interval: String,
    /// PolicySelector allows to filter applied policies based on labels.
    /// By default includes all policies in namespace.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "policySelector")]
    pub policy_selector: Option<ImageUpdateAutomationPolicySelector>,
    /// SourceRef refers to the resource giving access details
    /// to a git repository.
    #[serde(rename = "sourceRef")]
    pub source_ref: ImageUpdateAutomationSourceRef,
    /// Suspend tells the controller to not run this automation, until
    /// it is unset (or set to false). Defaults to false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspend: Option<bool>,
    /// Update gives the specification for how to update the files in
    /// the repository. This can be left empty, to use the default
    /// value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update: Option<ImageUpdateAutomationUpdate>,
}

/// GitSpec contains all the git-specific definitions. This is
/// technically optional, but in practice mandatory until there are
/// other kinds of source allowed.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ImageUpdateAutomationGit {
    /// Checkout gives the parameters for cloning the git repository,
    /// ready to make changes. If not present, the `spec.ref` field from the
    /// referenced `GitRepository` or its default will be used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkout: Option<ImageUpdateAutomationGitCheckout>,
    /// Commit specifies how to commit to the git repository.
    pub commit: ImageUpdateAutomationGitCommit,
    /// Push specifies how and where to push commits made by the
    /// automation. If missing, commits are pushed (back) to
    /// `.spec.checkout.branch` or its default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push: Option<ImageUpdateAutomationGitPush>,
}

/// Checkout gives the parameters for cloning the git repository,
/// ready to make changes. If not present, the `spec.ref` field from the
/// referenced `GitRepository` or its default will be used.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ImageUpdateAutomationGitCheckout {
    /// Reference gives a branch, tag or commit to clone from the Git
    /// repository.
    #[serde(rename = "ref")]
    pub r#ref: ImageUpdateAutomationGitCheckoutRef,
}

/// Reference gives a branch, tag or commit to clone from the Git
/// repository.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ImageUpdateAutomationGitCheckoutRef {
    /// Branch to check out, defaults to 'master' if no other field is defined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// Commit SHA to check out, takes precedence over all reference fields.
    /// 
    /// 
    /// This can be combined with Branch to shallow clone the branch, in which
    /// the commit is expected to exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// Name of the reference to check out; takes precedence over Branch, Tag and SemVer.
    /// 
    /// 
    /// It must be a valid Git reference: https://git-scm.com/docs/git-check-ref-format#_description
    /// Examples: "refs/heads/main", "refs/tags/v0.1.0", "refs/pull/420/head", "refs/merge-requests/1/head"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// SemVer tag expression to check out, takes precedence over Tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semver: Option<String>,
    /// Tag to check out, takes precedence over Branch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

/// Commit specifies how to commit to the git repository.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ImageUpdateAutomationGitCommit {
    /// Author gives the email and optionally the name to use as the
    /// author of commits.
    pub author: ImageUpdateAutomationGitCommitAuthor,
    /// MessageTemplate provides a template for the commit message,
    /// into which will be interpolated the details of the change made.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "messageTemplate")]
    pub message_template: Option<String>,
    /// SigningKey provides the option to sign commits with a GPG key
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "signingKey")]
    pub signing_key: Option<ImageUpdateAutomationGitCommitSigningKey>,
}

/// Author gives the email and optionally the name to use as the
/// author of commits.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ImageUpdateAutomationGitCommitAuthor {
    /// Email gives the email to provide when making a commit.
    pub email: String,
    /// Name gives the name to provide when making a commit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// SigningKey provides the option to sign commits with a GPG key
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ImageUpdateAutomationGitCommitSigningKey {
    /// SecretRef holds the name to a secret that contains a 'git.asc' key
    /// corresponding to the ASCII Armored file containing the GPG signing
    /// keypair as the value. It must be in the same namespace as the
    /// ImageUpdateAutomation.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretRef")]
    pub secret_ref: Option<ImageUpdateAutomationGitCommitSigningKeySecretRef>,
}

/// SecretRef holds the name to a secret that contains a 'git.asc' key
/// corresponding to the ASCII Armored file containing the GPG signing
/// keypair as the value. It must be in the same namespace as the
/// ImageUpdateAutomation.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ImageUpdateAutomationGitCommitSigningKeySecretRef {
    /// Name of the referent.
    pub name: String,
}

/// Push specifies how and where to push commits made by the
/// automation. If missing, commits are pushed (back) to
/// `.spec.checkout.branch` or its default.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ImageUpdateAutomationGitPush {
    /// Branch specifies that commits should be pushed to the branch
    /// named. The branch is created using `.spec.checkout.branch` as the
    /// starting point, if it doesn't already exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// Options specifies the push options that are sent to the Git
    /// server when performing a push operation. For details, see:
    /// https://git-scm.com/docs/git-push#Documentation/git-push.txt---push-optionltoptiongt
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<BTreeMap<String, String>>,
    /// Refspec specifies the Git Refspec to use for a push operation.
    /// If both Branch and Refspec are provided, then the commit is pushed
    /// to the branch and also using the specified refspec.
    /// For more details about Git Refspecs, see:
    /// https://git-scm.com/book/en/v2/Git-Internals-The-Refspec
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refspec: Option<String>,
}

/// PolicySelector allows to filter applied policies based on labels.
/// By default includes all policies in namespace.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ImageUpdateAutomationPolicySelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<ImageUpdateAutomationPolicySelectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels
    /// map is equivalent to an element of matchExpressions, whose key field is "key", the
    /// operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that
/// relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ImageUpdateAutomationPolicySelectorMatchExpressions {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values.
    /// Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn,
    /// the values array must be non-empty. If the operator is Exists or DoesNotExist,
    /// the values array must be empty. This array is replaced during a strategic
    /// merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// SourceRef refers to the resource giving access details
/// to a git repository.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ImageUpdateAutomationSourceRef {
    /// API version of the referent.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiVersion")]
    pub api_version: Option<String>,
    /// Kind of the referent.
    pub kind: ImageUpdateAutomationSourceRefKind,
    /// Name of the referent.
    pub name: String,
    /// Namespace of the referent, defaults to the namespace of the Kubernetes resource object that contains the reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// SourceRef refers to the resource giving access details
/// to a git repository.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ImageUpdateAutomationSourceRefKind {
    GitRepository,
}

/// Update gives the specification for how to update the files in
/// the repository. This can be left empty, to use the default
/// value.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ImageUpdateAutomationUpdate {
    /// Path to the directory containing the manifests to be updated.
    /// Defaults to 'None', which translates to the root path
    /// of the GitRepositoryRef.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Strategy names the strategy to be used.
    pub strategy: ImageUpdateAutomationUpdateStrategy,
}

/// Update gives the specification for how to update the files in
/// the repository. This can be left empty, to use the default
/// value.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ImageUpdateAutomationUpdateStrategy {
    Setters,
}

/// ImageUpdateAutomationStatus defines the observed state of ImageUpdateAutomation
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ImageUpdateAutomationStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// LastAutomationRunTime records the last time the controller ran
    /// this automation through to completion (even if no updates were
    /// made).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastAutomationRunTime")]
    pub last_automation_run_time: Option<String>,
    /// LastHandledReconcileAt holds the value of the most recent
    /// reconcile request value, so a change of the annotation value
    /// can be detected.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastHandledReconcileAt")]
    pub last_handled_reconcile_at: Option<String>,
    /// LastPushCommit records the SHA1 of the last commit made by the
    /// controller, for this automation object
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastPushCommit")]
    pub last_push_commit: Option<String>,
    /// LastPushTime records the time of the last pushed change.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastPushTime")]
    pub last_push_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
    /// ObservedPolicies is the list of observed ImagePolicies that were
    /// considered by the ImageUpdateAutomation update process.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedPolicies")]
    pub observed_policies: Option<BTreeMap<String, ImageUpdateAutomationStatusObservedPolicies>>,
    /// ObservedPolicies []ObservedPolicy `json:"observedPolicies,omitempty"`
    /// ObservedSourceRevision is the last observed source revision. This can be
    /// used to determine if the source has been updated since last observation.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedSourceRevision")]
    pub observed_source_revision: Option<String>,
}

/// ObservedPolicies is the list of observed ImagePolicies that were
/// considered by the ImageUpdateAutomation update process.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ImageUpdateAutomationStatusObservedPolicies {
    /// Name is the bare image's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Tag is the image's tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}
