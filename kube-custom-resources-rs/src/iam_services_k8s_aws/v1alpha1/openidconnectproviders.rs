// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/iam-controller/iam.services.k8s.aws/v1alpha1/openidconnectproviders.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// OpenIDConnectProviderSpec defines the desired state of OpenIDConnectProvider.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "iam.services.k8s.aws", version = "v1alpha1", kind = "OpenIDConnectProvider", plural = "openidconnectproviders")]
#[kube(namespaced)]
#[kube(status = "OpenIDConnectProviderStatus")]
#[kube(schema = "disabled")]
pub struct OpenIDConnectProviderSpec {
    /// Provides a list of client IDs, also known as audiences. When a mobile or
    /// web app registers with an OpenID Connect provider, they establish a value
    /// that identifies the application. This is the value that's sent as the client_id
    /// parameter on OAuth requests.
    /// 
    /// 
    /// You can register multiple client IDs with the same provider. For example,
    /// you might have multiple applications that use the same OIDC provider. You
    /// cannot register more than 100 client IDs with a single IAM OIDC provider.
    /// 
    /// 
    /// There is no defined format for a client ID. The CreateOpenIDConnectProviderRequest
    /// operation accepts client IDs up to 255 characters long.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clientIDs")]
    pub client_i_ds: Option<Vec<String>>,
    /// A list of tags that you want to attach to the new IAM OpenID Connect (OIDC)
    /// provider. Each tag consists of a key name and an associated value. For more
    /// information about tagging, see Tagging IAM resources (https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html)
    /// in the IAM User Guide.
    /// 
    /// 
    /// If any one of the tags is invalid or if you exceed the allowed maximum number
    /// of tags, then the entire request fails and the resource is not created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<OpenIDConnectProviderTags>>,
    /// A list of server certificate thumbprints for the OpenID Connect (OIDC) identity
    /// provider's server certificates. Typically this list includes only one entry.
    /// However, IAM lets you have up to five thumbprints for an OIDC provider. This
    /// lets you maintain multiple thumbprints if the identity provider is rotating
    /// certificates.
    /// 
    /// 
    /// The server certificate thumbprint is the hex-encoded SHA-1 hash value of
    /// the X.509 certificate used by the domain where the OpenID Connect provider
    /// makes its keys available. It is always a 40-character string.
    /// 
    /// 
    /// You must provide at least one thumbprint when creating an IAM OIDC provider.
    /// For example, assume that the OIDC provider is server.example.com and the
    /// provider stores its keys at https://keys.server.example.com/openid-connect.
    /// In that case, the thumbprint string would be the hex-encoded SHA-1 hash value
    /// of the certificate used by https://keys.server.example.com.
    /// 
    /// 
    /// For more information about obtaining the OIDC provider thumbprint, see Obtaining
    /// the thumbprint for an OpenID Connect provider (https://docs.aws.amazon.com/IAM/latest/UserGuide/identity-providers-oidc-obtain-thumbprint.html)
    /// in the IAM user Guide.
    pub thumbprints: Vec<String>,
    /// The URL of the identity provider. The URL must begin with https:// and should
    /// correspond to the iss claim in the provider's OpenID Connect ID tokens. Per
    /// the OIDC standard, path components are allowed but query parameters are not.
    /// Typically the URL consists of only a hostname, like https://server.example.org
    /// or https://example.com. The URL should not contain a port number.
    /// 
    /// 
    /// You cannot register the same provider multiple times in a single Amazon Web
    /// Services account. If you try to submit a URL that has already been used for
    /// an OpenID Connect provider in the Amazon Web Services account, you will get
    /// an error.
    pub url: String,
}

/// A structure that represents user-provided metadata that can be associated
/// with an IAM resource. For more information about tagging, see Tagging IAM
/// resources (https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html)
/// in the IAM User Guide.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct OpenIDConnectProviderTags {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// OpenIDConnectProviderStatus defines the observed state of OpenIDConnectProvider
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct OpenIDConnectProviderStatus {
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
    /// that is used to contain resource sync state, account ownership,
    /// constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<OpenIDConnectProviderStatusAckResourceMetadata>,
    /// All CRS managed by ACK have a common `Status.Conditions` member that
    /// contains a collection of `ackv1alpha1.Condition` objects that describe
    /// the various terminal states of the CR and its backend AWS service API
    /// resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
}

/// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
/// that is used to contain resource sync state, account ownership,
/// constructed ARN for the resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct OpenIDConnectProviderStatusAckResourceMetadata {
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

