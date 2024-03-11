// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/ecr-controller/ecr.services.k8s.aws/v1alpha1/pullthroughcacherules.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// PullThroughCacheRuleSpec defines the desired state of PullThroughCacheRule.
/// 
/// 
/// The details of a pull through cache rule.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "ecr.services.k8s.aws", version = "v1alpha1", kind = "PullThroughCacheRule", plural = "pullthroughcacherules")]
#[kube(namespaced)]
#[kube(status = "PullThroughCacheRuleStatus")]
#[kube(schema = "disabled")]
pub struct PullThroughCacheRuleSpec {
    /// The repository name prefix to use when caching images from the source registry.
    #[serde(rename = "ecrRepositoryPrefix")]
    pub ecr_repository_prefix: String,
    /// The Amazon Web Services account ID associated with the registry to create
    /// the pull through cache rule for. If you do not specify a registry, the default
    /// registry is assumed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "registryID")]
    pub registry_id: Option<String>,
    /// The registry URL of the upstream public registry to use as the source for
    /// the pull through cache rule.
    #[serde(rename = "upstreamRegistryURL")]
    pub upstream_registry_url: String,
}

/// PullThroughCacheRuleStatus defines the observed state of PullThroughCacheRule
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PullThroughCacheRuleStatus {
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
    /// that is used to contain resource sync state, account ownership,
    /// constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<PullThroughCacheRuleStatusAckResourceMetadata>,
    /// All CRS managed by ACK have a common `Status.Conditions` member that
    /// contains a collection of `ackv1alpha1.Condition` objects that describe
    /// the various terminal states of the CR and its backend AWS service API
    /// resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// The date and time, in JavaScript date format, when the pull through cache
    /// rule was created.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "createdAt")]
    pub created_at: Option<String>,
}

/// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
/// that is used to contain resource sync state, account ownership,
/// constructed ARN for the resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PullThroughCacheRuleStatusAckResourceMetadata {
    /// ARN is the Amazon Resource Name for the resource. This is a
    /// globally-unique identifier and is set only by the ACK service controller
    /// once the controller has orchestrated the creation of the resource OR
    /// when it has verified that an "adopted" resource (a resource where the
    /// ARN annotation was set by the Kubernetes user on the CR) exists and
    /// matches the supplied CR's Spec field values.
    /// TODO(vijat@): Find a better strategy for resources that do not have ARN in CreateOutputResponse
    /// https://github.com/aws/aws-controllers-k8s/issues/270
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arn: Option<String>,
    /// OwnerAccountID is the AWS Account ID of the account that owns the
    /// backend AWS service API resource.
    #[serde(rename = "ownerAccountID")]
    pub owner_account_id: String,
    /// Region is the AWS region in which the resource exists or will exist.
    pub region: String,
}

