// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws/eks-anywhere/anywhere.eks.amazonaws.com/v1alpha1/cloudstackdatacenterconfigs.yaml --derive=Default --derive=PartialEq
// kopium version: 0.16.5

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// CloudStackDatacenterConfigSpec defines the desired state of CloudStackDatacenterConfig.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "anywhere.eks.amazonaws.com", version = "v1alpha1", kind = "CloudStackDatacenterConfig", plural = "cloudstackdatacenterconfigs")]
#[kube(namespaced)]
#[kube(status = "CloudStackDatacenterConfigStatus")]
#[kube(schema = "disabled")]
pub struct CloudStackDatacenterConfigSpec {
    /// Account typically represents a customer of the service provider or a department in a large organization. Multiple users can exist in an account, and all CloudStack resources belong to an account. Accounts have users and users have credentials to operate on resources within that account. If an account name is provided, a domain must also be provided. Deprecated: Please use AvailabilityZones instead
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// AvailabilityZones list of different partitions to distribute VMs across - corresponds to a list of CAPI failure domains
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "availabilityZones")]
    pub availability_zones: Option<Vec<CloudStackDatacenterConfigAvailabilityZones>>,
    /// Domain contains a grouping of accounts. Domains usually contain multiple accounts that have some logical relationship to each other and a set of delegated administrators with some authority over the domain and its subdomains This field is considered as a fully qualified domain name which is the same as the domain path without "ROOT/" prefix. For example, if "foo" is specified then a domain with "ROOT/foo" domain path is picked. The value "ROOT" is a special case that points to "the" ROOT domain of the CloudStack. That is, a domain with a path "ROOT/ROOT" is not allowed. Deprecated: Please use AvailabilityZones instead
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// CloudStack Management API endpoint's IP. It is added to VM's noproxy list Deprecated: Please use AvailabilityZones instead
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "managementApiEndpoint")]
    pub management_api_endpoint: Option<String>,
    /// Zones is a list of one or more zones that are managed by a single CloudStack management endpoint. Deprecated: Please use AvailabilityZones instead
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zones: Option<Vec<CloudStackDatacenterConfigZones>>,
}

/// CloudStackAvailabilityZone maps to a CAPI failure domain to distribute machines across Cloudstack infrastructure.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CloudStackDatacenterConfigAvailabilityZones {
    /// Account typically represents a customer of the service provider or a department in a large organization. Multiple users can exist in an account, and all CloudStack resources belong to an account. Accounts have users and users have credentials to operate on resources within that account. If an account name is provided, a domain must also be provided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// CredentialRef is used to reference a secret in the eksa-system namespace
    #[serde(rename = "credentialsRef")]
    pub credentials_ref: String,
    /// Domain contains a grouping of accounts. Domains usually contain multiple accounts that have some logical relationship to each other and a set of delegated administrators with some authority over the domain and its subdomains This field is considered as a fully qualified domain name which is the same as the domain path without "ROOT/" prefix. For example, if "foo" is specified then a domain with "ROOT/foo" domain path is picked. The value "ROOT" is a special case that points to "the" ROOT domain of the CloudStack. That is, a domain with a path "ROOT/ROOT" is not allowed.
    pub domain: String,
    /// CloudStack Management API endpoint's IP. It is added to VM's noproxy list
    #[serde(rename = "managementApiEndpoint")]
    pub management_api_endpoint: String,
    /// Name is used as a unique identifier for each availability zone
    pub name: String,
    /// Zone represents the properties of the CloudStack zone in which clusters should be created, like the network.
    pub zone: CloudStackDatacenterConfigAvailabilityZonesZone,
}

/// Zone represents the properties of the CloudStack zone in which clusters should be created, like the network.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CloudStackDatacenterConfigAvailabilityZonesZone {
    /// Zone is the name or UUID of the CloudStack zone in which clusters should be created. Zones should be managed by a single CloudStack Management endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Network is the name or UUID of the CloudStack network in which clusters should be created. It can either be an isolated or shared network. If it doesn’t already exist in CloudStack, it’ll automatically be created by CAPC as an isolated network. It can either be specified as a UUID or name In multiple-zones situation, only 'Shared' network is supported.
    pub network: CloudStackDatacenterConfigAvailabilityZonesZoneNetwork,
}

/// Network is the name or UUID of the CloudStack network in which clusters should be created. It can either be an isolated or shared network. If it doesn’t already exist in CloudStack, it’ll automatically be created by CAPC as an isolated network. It can either be specified as a UUID or name In multiple-zones situation, only 'Shared' network is supported.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CloudStackDatacenterConfigAvailabilityZonesZoneNetwork {
    /// Id of a resource in the CloudStack environment. Mutually exclusive with Name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Name of a resource in the CloudStack environment. Mutually exclusive with Id
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// CloudStackZone is an organizational construct typically used to represent a single datacenter, and all its physical and virtual resources exist inside that zone. It can either be specified as a UUID or name.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CloudStackDatacenterConfigZones {
    /// Zone is the name or UUID of the CloudStack zone in which clusters should be created. Zones should be managed by a single CloudStack Management endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Network is the name or UUID of the CloudStack network in which clusters should be created. It can either be an isolated or shared network. If it doesn’t already exist in CloudStack, it’ll automatically be created by CAPC as an isolated network. It can either be specified as a UUID or name In multiple-zones situation, only 'Shared' network is supported.
    pub network: CloudStackDatacenterConfigZonesNetwork,
}

/// Network is the name or UUID of the CloudStack network in which clusters should be created. It can either be an isolated or shared network. If it doesn’t already exist in CloudStack, it’ll automatically be created by CAPC as an isolated network. It can either be specified as a UUID or name In multiple-zones situation, only 'Shared' network is supported.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CloudStackDatacenterConfigZonesNetwork {
    /// Id of a resource in the CloudStack environment. Mutually exclusive with Name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Name of a resource in the CloudStack environment. Mutually exclusive with Id
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// CloudStackDatacenterConfigStatus defines the observed state of CloudStackDatacenterConfig.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CloudStackDatacenterConfigStatus {
    /// FailureMessage indicates that there is a fatal problem reconciling the state, and will be set to a descriptive error message.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "failureMessage")]
    pub failure_message: Option<String>,
    /// ObservedGeneration is the latest generation observed by the controller.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
    /// SpecValid is set to true if cloudstackdatacenterconfig is validated.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "specValid")]
    pub spec_valid: Option<bool>,
}
