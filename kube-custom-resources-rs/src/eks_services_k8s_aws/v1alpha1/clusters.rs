// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/eks-controller/eks.services.k8s.aws/v1alpha1/clusters.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// ClusterSpec defines the desired state of Cluster.
/// 
/// 
/// An object representing an Amazon EKS cluster.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "eks.services.k8s.aws", version = "v1alpha1", kind = "Cluster", plural = "clusters")]
#[kube(namespaced)]
#[kube(status = "ClusterStatus")]
#[kube(schema = "disabled")]
pub struct ClusterSpec {
    /// The access configuration for the cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "accessConfig")]
    pub access_config: Option<ClusterAccessConfig>,
    /// A unique, case-sensitive identifier that you provide to ensure the idempotency
    /// of the request.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clientRequestToken")]
    pub client_request_token: Option<String>,
    /// The encryption configuration for the cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "encryptionConfig")]
    pub encryption_config: Option<Vec<ClusterEncryptionConfig>>,
    /// The Kubernetes network configuration for the cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "kubernetesNetworkConfig")]
    pub kubernetes_network_config: Option<ClusterKubernetesNetworkConfig>,
    /// Enable or disable exporting the Kubernetes control plane logs for your cluster
    /// to CloudWatch Logs. By default, cluster control plane logs aren't exported
    /// to CloudWatch Logs. For more information, see Amazon EKS Cluster control
    /// plane logs (https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html)
    /// in the Amazon EKS User Guide .
    /// 
    /// 
    /// CloudWatch Logs ingestion, archive storage, and data scanning rates apply
    /// to exported control plane logs. For more information, see CloudWatch Pricing
    /// (http://aws.amazon.com/cloudwatch/pricing/).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logging: Option<ClusterLogging>,
    /// The unique name to give to your cluster.
    pub name: String,
    /// An object representing the configuration of your local Amazon EKS cluster
    /// on an Amazon Web Services Outpost. Before creating a local cluster on an
    /// Outpost, review Local clusters for Amazon EKS on Amazon Web Services Outposts
    /// (https://docs.aws.amazon.com/eks/latest/userguide/eks-outposts-local-cluster-overview.html)
    /// in the Amazon EKS User Guide. This object isn't available for creating Amazon
    /// EKS clusters on the Amazon Web Services cloud.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "outpostConfig")]
    pub outpost_config: Option<ClusterOutpostConfig>,
    /// The VPC configuration that's used by the cluster control plane. Amazon EKS
    /// VPC resources have specific requirements to work properly with Kubernetes.
    /// For more information, see Cluster VPC Considerations (https://docs.aws.amazon.com/eks/latest/userguide/network_reqs.html)
    /// and Cluster Security Group Considerations (https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html)
    /// in the Amazon EKS User Guide. You must specify at least two subnets. You
    /// can specify up to five security groups. However, we recommend that you use
    /// a dedicated security group for your cluster control plane.
    #[serde(rename = "resourcesVPCConfig")]
    pub resources_vpc_config: ClusterResourcesVpcConfig,
    /// The Amazon Resource Name (ARN) of the IAM role that provides permissions
    /// for the Kubernetes control plane to make calls to Amazon Web Services API
    /// operations on your behalf. For more information, see Amazon EKS Service IAM
    /// Role (https://docs.aws.amazon.com/eks/latest/userguide/service_IAM_role.html)
    /// in the Amazon EKS User Guide .
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "roleARN")]
    pub role_arn: Option<String>,
    /// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference
    /// type to provide more user friendly syntax for references using 'from' field
    /// Ex:
    /// APIIDRef:
    /// 
    /// 
    /// 	from:
    /// 	  name: my-api
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "roleRef")]
    pub role_ref: Option<ClusterRoleRef>,
    /// Metadata that assists with categorization and organization. Each tag consists
    /// of a key and an optional value. You define both. Tags don't propagate to
    /// any other cluster or Amazon Web Services resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,
    /// The desired Kubernetes version for your cluster. If you don't specify a value
    /// here, the default version available in Amazon EKS is used.
    /// 
    /// 
    /// The default version might not be the latest version available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// The access configuration for the cluster.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterAccessConfig {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "authenticationMode")]
    pub authentication_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "bootstrapClusterCreatorAdminPermissions")]
    pub bootstrap_cluster_creator_admin_permissions: Option<bool>,
}

/// The encryption configuration for the cluster.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterEncryptionConfig {
    /// Identifies the Key Management Service (KMS) key used to encrypt the secrets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<ClusterEncryptionConfigProvider>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<String>>,
}

/// Identifies the Key Management Service (KMS) key used to encrypt the secrets.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterEncryptionConfigProvider {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "keyARN")]
    pub key_arn: Option<String>,
    /// Reference field for KeyARN
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "keyRef")]
    pub key_ref: Option<ClusterEncryptionConfigProviderKeyRef>,
}

/// Reference field for KeyARN
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterEncryptionConfigProviderKeyRef {
    /// AWSResourceReference provides all the values necessary to reference another
    /// k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<ClusterEncryptionConfigProviderKeyRefFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another
/// k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterEncryptionConfigProviderKeyRefFrom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// The Kubernetes network configuration for the cluster.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterKubernetesNetworkConfig {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ipFamily")]
    pub ip_family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "serviceIPv4CIDR")]
    pub service_i_pv4_cidr: Option<String>,
}

/// Enable or disable exporting the Kubernetes control plane logs for your cluster
/// to CloudWatch Logs. By default, cluster control plane logs aren't exported
/// to CloudWatch Logs. For more information, see Amazon EKS Cluster control
/// plane logs (https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html)
/// in the Amazon EKS User Guide .
/// 
/// 
/// CloudWatch Logs ingestion, archive storage, and data scanning rates apply
/// to exported control plane logs. For more information, see CloudWatch Pricing
/// (http://aws.amazon.com/cloudwatch/pricing/).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterLogging {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clusterLogging")]
    pub cluster_logging: Option<Vec<ClusterLoggingClusterLogging>>,
}

/// An object representing the enabled or disabled Kubernetes control plane logs
/// for your cluster.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterLoggingClusterLogging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<String>>,
}

/// An object representing the configuration of your local Amazon EKS cluster
/// on an Amazon Web Services Outpost. Before creating a local cluster on an
/// Outpost, review Local clusters for Amazon EKS on Amazon Web Services Outposts
/// (https://docs.aws.amazon.com/eks/latest/userguide/eks-outposts-local-cluster-overview.html)
/// in the Amazon EKS User Guide. This object isn't available for creating Amazon
/// EKS clusters on the Amazon Web Services cloud.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterOutpostConfig {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "controlPlaneInstanceType")]
    pub control_plane_instance_type: Option<String>,
    /// The placement configuration for all the control plane instances of your local
    /// Amazon EKS cluster on an Amazon Web Services Outpost. For more information,
    /// see Capacity considerations (https://docs.aws.amazon.com/eks/latest/userguide/eks-outposts-capacity-considerations.html)
    /// in the Amazon EKS User Guide.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "controlPlanePlacement")]
    pub control_plane_placement: Option<ClusterOutpostConfigControlPlanePlacement>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "outpostARNs")]
    pub outpost_ar_ns: Option<Vec<String>>,
}

/// The placement configuration for all the control plane instances of your local
/// Amazon EKS cluster on an Amazon Web Services Outpost. For more information,
/// see Capacity considerations (https://docs.aws.amazon.com/eks/latest/userguide/eks-outposts-capacity-considerations.html)
/// in the Amazon EKS User Guide.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterOutpostConfigControlPlanePlacement {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "groupName")]
    pub group_name: Option<String>,
}

/// The VPC configuration that's used by the cluster control plane. Amazon EKS
/// VPC resources have specific requirements to work properly with Kubernetes.
/// For more information, see Cluster VPC Considerations (https://docs.aws.amazon.com/eks/latest/userguide/network_reqs.html)
/// and Cluster Security Group Considerations (https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html)
/// in the Amazon EKS User Guide. You must specify at least two subnets. You
/// can specify up to five security groups. However, we recommend that you use
/// a dedicated security group for your cluster control plane.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterResourcesVpcConfig {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "endpointPrivateAccess")]
    pub endpoint_private_access: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "endpointPublicAccess")]
    pub endpoint_public_access: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "publicAccessCIDRs")]
    pub public_access_cid_rs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "securityGroupIDs")]
    pub security_group_i_ds: Option<Vec<String>>,
    /// Reference field for SecurityGroupIDs
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "securityGroupRefs")]
    pub security_group_refs: Option<Vec<ClusterResourcesVpcConfigSecurityGroupRefs>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "subnetIDs")]
    pub subnet_i_ds: Option<Vec<String>>,
    /// Reference field for SubnetIDs
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "subnetRefs")]
    pub subnet_refs: Option<Vec<ClusterResourcesVpcConfigSubnetRefs>>,
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
pub struct ClusterResourcesVpcConfigSecurityGroupRefs {
    /// AWSResourceReference provides all the values necessary to reference another
    /// k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<ClusterResourcesVpcConfigSecurityGroupRefsFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another
/// k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterResourcesVpcConfigSecurityGroupRefsFrom {
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
pub struct ClusterResourcesVpcConfigSubnetRefs {
    /// AWSResourceReference provides all the values necessary to reference another
    /// k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<ClusterResourcesVpcConfigSubnetRefsFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another
/// k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterResourcesVpcConfigSubnetRefsFrom {
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
pub struct ClusterRoleRef {
    /// AWSResourceReference provides all the values necessary to reference another
    /// k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<ClusterRoleRefFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another
/// k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterRoleRefFrom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// ClusterStatus defines the observed state of Cluster
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterStatus {
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
    /// that is used to contain resource sync state, account ownership,
    /// constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<ClusterStatusAckResourceMetadata>,
    /// The certificate-authority-data for your cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "certificateAuthority")]
    pub certificate_authority: Option<ClusterStatusCertificateAuthority>,
    /// All CRS managed by ACK have a common `Status.Conditions` member that
    /// contains a collection of `ackv1alpha1.Condition` objects that describe
    /// the various terminal states of the CR and its backend AWS service API
    /// resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// The configuration used to connect to a cluster for registration.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "connectorConfig")]
    pub connector_config: Option<ClusterStatusConnectorConfig>,
    /// The Unix epoch timestamp at object creation.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "createdAt")]
    pub created_at: Option<String>,
    /// The endpoint for your Kubernetes API server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// An object representing the health of your local Amazon EKS cluster on an
    /// Amazon Web Services Outpost. This object isn't available for clusters on
    /// the Amazon Web Services cloud.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<ClusterStatusHealth>,
    /// The ID of your local Amazon EKS cluster on an Amazon Web Services Outpost.
    /// This property isn't available for an Amazon EKS cluster on the Amazon Web
    /// Services cloud.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The identity provider information for the cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<ClusterStatusIdentity>,
    /// The platform version of your Amazon EKS cluster. For more information about
    /// clusters deployed on the Amazon Web Services Cloud, see Platform versions
    /// (https://docs.aws.amazon.com/eks/latest/userguide/platform-versions.html)
    /// in the Amazon EKS User Guide . For more information about local clusters
    /// deployed on an Outpost, see Amazon EKS local cluster platform versions (https://docs.aws.amazon.com/eks/latest/userguide/eks-outposts-platform-versions.html)
    /// in the Amazon EKS User Guide .
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "platformVersion")]
    pub platform_version: Option<String>,
    /// The current status of the cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
/// that is used to contain resource sync state, account ownership,
/// constructed ARN for the resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterStatusAckResourceMetadata {
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

/// The certificate-authority-data for your cluster.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterStatusCertificateAuthority {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

/// The configuration used to connect to a cluster for registration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterStatusConnectorConfig {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "activationCode")]
    pub activation_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "activationExpiry")]
    pub activation_expiry: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "activationID")]
    pub activation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "roleARN")]
    pub role_arn: Option<String>,
}

/// An object representing the health of your local Amazon EKS cluster on an
/// Amazon Web Services Outpost. This object isn't available for clusters on
/// the Amazon Web Services cloud.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterStatusHealth {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issues: Option<Vec<ClusterStatusHealthIssues>>,
}

/// An issue with your local Amazon EKS cluster on an Amazon Web Services Outpost.
/// You can't use this API with an Amazon EKS cluster on the Amazon Web Services
/// cloud.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterStatusHealthIssues {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "resourceIDs")]
    pub resource_i_ds: Option<Vec<String>>,
}

/// The identity provider information for the cluster.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterStatusIdentity {
    /// An object representing the OpenID Connect (https://openid.net/connect/) (OIDC)
    /// identity provider information for the cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc: Option<ClusterStatusIdentityOidc>,
}

/// An object representing the OpenID Connect (https://openid.net/connect/) (OIDC)
/// identity provider information for the cluster.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterStatusIdentityOidc {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
}

