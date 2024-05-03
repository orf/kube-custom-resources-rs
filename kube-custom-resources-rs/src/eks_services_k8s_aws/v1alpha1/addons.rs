// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/eks-controller/eks.services.k8s.aws/v1alpha1/addons.yaml --derive=Default --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use std::collections::BTreeMap;
    pub use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
}
use self::prelude::*;

/// AddonSpec defines the desired state of Addon.
/// 
/// 
/// An Amazon EKS add-on. For more information, see Amazon EKS add-ons (https://docs.aws.amazon.com/eks/latest/userguide/eks-add-ons.html)
/// in the Amazon EKS User Guide.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "eks.services.k8s.aws", version = "v1alpha1", kind = "Addon", plural = "addons")]
#[kube(namespaced)]
#[kube(status = "AddonStatus")]
#[kube(schema = "disabled")]
#[kube(derive="Default")]
#[kube(derive="PartialEq")]
pub struct AddonSpec {
    /// The version of the add-on. The version must match one of the versions returned
    /// by DescribeAddonVersions (https://docs.aws.amazon.com/eks/latest/APIReference/API_DescribeAddonVersions.html).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "addonVersion")]
    pub addon_version: Option<String>,
    /// A unique, case-sensitive identifier that you provide to ensure the idempotency
    /// of the request.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clientRequestToken")]
    pub client_request_token: Option<String>,
    /// The name of your cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clusterName")]
    pub cluster_name: Option<String>,
    /// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference
    /// type to provide more user friendly syntax for references using 'from' field
    /// Ex:
    /// APIIDRef:
    /// 
    /// 
    /// 	from:
    /// 	  name: my-api
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clusterRef")]
    pub cluster_ref: Option<AddonClusterRef>,
    /// The set of configuration values for the add-on that's created. The values
    /// that you provide are validated against the schema returned by DescribeAddonConfiguration.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "configurationValues")]
    pub configuration_values: Option<String>,
    /// The name of the add-on. The name must match one of the names returned by
    /// DescribeAddonVersions.
    pub name: String,
    /// How to resolve field value conflicts for an Amazon EKS add-on. Conflicts
    /// are handled based on the value you choose:
    /// 
    /// 
    ///    * None – If the self-managed version of the add-on is installed on your
    ///    cluster, Amazon EKS doesn't change the value. Creation of the add-on might
    ///    fail.
    /// 
    /// 
    ///    * Overwrite – If the self-managed version of the add-on is installed
    ///    on your cluster and the Amazon EKS default value is different than the
    ///    existing value, Amazon EKS changes the value to the Amazon EKS default
    ///    value.
    /// 
    /// 
    ///    * Preserve – This is similar to the NONE option. If the self-managed
    ///    version of the add-on is installed on your cluster Amazon EKS doesn't
    ///    change the add-on resource properties. Creation of the add-on might fail
    ///    if conflicts are detected. This option works differently during the update
    ///    operation. For more information, see UpdateAddon (https://docs.aws.amazon.com/eks/latest/APIReference/API_UpdateAddon.html).
    /// 
    /// 
    /// If you don't currently have the self-managed version of the add-on installed
    /// on your cluster, the Amazon EKS add-on is installed. Amazon EKS sets all
    /// values to default values, regardless of the option that you specify.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "resolveConflicts")]
    pub resolve_conflicts: Option<String>,
    /// The Amazon Resource Name (ARN) of an existing IAM role to bind to the add-on's
    /// service account. The role must be assigned the IAM permissions required by
    /// the add-on. If you don't specify an existing IAM role, then the add-on uses
    /// the permissions assigned to the node IAM role. For more information, see
    /// Amazon EKS node IAM role (https://docs.aws.amazon.com/eks/latest/userguide/create-node-role.html)
    /// in the Amazon EKS User Guide.
    /// 
    /// 
    /// To specify an existing IAM role, you must have an IAM OpenID Connect (OIDC)
    /// provider created for your cluster. For more information, see Enabling IAM
    /// roles for service accounts on your cluster (https://docs.aws.amazon.com/eks/latest/userguide/enable-iam-roles-for-service-accounts.html)
    /// in the Amazon EKS User Guide.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "serviceAccountRoleARN")]
    pub service_account_role_arn: Option<String>,
    /// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference
    /// type to provide more user friendly syntax for references using 'from' field
    /// Ex:
    /// APIIDRef:
    /// 
    /// 
    /// 	from:
    /// 	  name: my-api
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "serviceAccountRoleRef")]
    pub service_account_role_ref: Option<AddonServiceAccountRoleRef>,
    /// Metadata that assists with categorization and organization. Each tag consists
    /// of a key and an optional value. You define both. Tags don't propagate to
    /// any other cluster or Amazon Web Services resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,
}

/// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference
/// type to provide more user friendly syntax for references using 'from' field
/// Ex:
/// APIIDRef:
/// 
/// 
/// 	from:
/// 	  name: my-api
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AddonClusterRef {
    /// AWSResourceReference provides all the values necessary to reference another
    /// k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<AddonClusterRefFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another
/// k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AddonClusterRefFrom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference
/// type to provide more user friendly syntax for references using 'from' field
/// Ex:
/// APIIDRef:
/// 
/// 
/// 	from:
/// 	  name: my-api
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AddonServiceAccountRoleRef {
    /// AWSResourceReference provides all the values necessary to reference another
    /// k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<AddonServiceAccountRoleRefFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another
/// k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AddonServiceAccountRoleRefFrom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// AddonStatus defines the observed state of Addon
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AddonStatus {
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
    /// that is used to contain resource sync state, account ownership,
    /// constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<AddonStatusAckResourceMetadata>,
    /// All CRS managed by ACK have a common `Status.Conditions` member that
    /// contains a collection of `ackv1alpha1.Condition` objects that describe
    /// the various terminal states of the CR and its backend AWS service API
    /// resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// The Unix epoch timestamp at object creation.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "createdAt")]
    pub created_at: Option<String>,
    /// An object that represents the health of the add-on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<AddonStatusHealth>,
    /// Information about an Amazon EKS add-on from the Amazon Web Services Marketplace.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "marketplaceInformation")]
    pub marketplace_information: Option<AddonStatusMarketplaceInformation>,
    /// The Unix epoch timestamp for the last modification to the object.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "modifiedAt")]
    pub modified_at: Option<String>,
    /// The owner of the add-on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// The publisher of the add-on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    /// The status of the add-on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
/// that is used to contain resource sync state, account ownership,
/// constructed ARN for the resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AddonStatusAckResourceMetadata {
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

/// An object that represents the health of the add-on.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AddonStatusHealth {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issues: Option<Vec<AddonStatusHealthIssues>>,
}

/// An issue related to an add-on.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AddonStatusHealthIssues {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "resourceIDs")]
    pub resource_i_ds: Option<Vec<String>>,
}

/// Information about an Amazon EKS add-on from the Amazon Web Services Marketplace.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AddonStatusMarketplaceInformation {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "productID")]
    pub product_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "productURL")]
    pub product_url: Option<String>,
}

