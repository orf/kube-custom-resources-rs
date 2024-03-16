// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kubernetes-sigs/cluster-api/ipam.cluster.x-k8s.io/v1alpha1/ipaddressclaims.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// IPAddressClaimSpec is the desired state of an IPAddressClaim.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "ipam.cluster.x-k8s.io", version = "v1alpha1", kind = "IPAddressClaim", plural = "ipaddressclaims")]
#[kube(namespaced)]
#[kube(status = "IPAddressClaimStatus")]
#[kube(schema = "disabled")]
pub struct IPAddressClaimSpec {
    /// PoolRef is a reference to the pool from which an IP address should be created.
    #[serde(rename = "poolRef")]
    pub pool_ref: IPAddressClaimPoolRef,
}

/// PoolRef is a reference to the pool from which an IP address should be created.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct IPAddressClaimPoolRef {
    /// APIGroup is the group for the resource being referenced.
    /// If APIGroup is not specified, the specified Kind must be in the core API group.
    /// For any other third-party types, APIGroup is required.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiGroup")]
    pub api_group: Option<String>,
    /// Kind is the type of resource being referenced
    pub kind: String,
    /// Name is the name of resource being referenced
    pub name: String,
}

/// IPAddressClaimStatus is the observed status of a IPAddressClaim.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct IPAddressClaimStatus {
    /// AddressRef is a reference to the address that was created for this claim.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "addressRef")]
    pub address_ref: Option<IPAddressClaimStatusAddressRef>,
    /// Conditions summarises the current state of the IPAddressClaim
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
}

/// AddressRef is a reference to the address that was created for this claim.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct IPAddressClaimStatusAddressRef {
    /// Name of the referent.
    /// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
    /// TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

