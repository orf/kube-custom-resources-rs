// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/ec2-controller/ec2.services.k8s.aws/v1alpha1/routetables.yaml --derive=Default --derive=PartialEq
// kopium version: 0.16.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// RouteTableSpec defines the desired state of RouteTable. 
///  Describes a route table.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "ec2.services.k8s.aws", version = "v1alpha1", kind = "RouteTable", plural = "routetables")]
#[kube(namespaced)]
#[kube(status = "RouteTableStatus")]
#[kube(schema = "disabled")]
pub struct RouteTableSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routes: Option<Vec<RouteTableRoutes>>,
    /// The tags. The value parameter is required, but if you don't want the tag to have a value, specify the parameter with no value, and we set the value to an empty string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<RouteTableTags>>,
    /// The ID of the VPC.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vpcID")]
    pub vpc_id: Option<String>,
    /// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference type to provide more user friendly syntax for references using 'from' field Ex: APIIDRef: 
    ///  from: name: my-api
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vpcRef")]
    pub vpc_ref: Option<RouteTableVpcRef>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RouteTableRoutes {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "carrierGatewayID")]
    pub carrier_gateway_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "coreNetworkARN")]
    pub core_network_arn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "destinationCIDRBlock")]
    pub destination_cidr_block: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "destinationIPv6CIDRBlock")]
    pub destination_i_pv6_cidr_block: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "destinationPrefixListID")]
    pub destination_prefix_list_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "egressOnlyInternetGatewayID")]
    pub egress_only_internet_gateway_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "gatewayID")]
    pub gateway_id: Option<String>,
    /// Reference field for GatewayID
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "gatewayRef")]
    pub gateway_ref: Option<RouteTableRoutesGatewayRef>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "instanceID")]
    pub instance_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "localGatewayID")]
    pub local_gateway_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "natGatewayID")]
    pub nat_gateway_id: Option<String>,
    /// Reference field for NATGatewayID
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "natGatewayRef")]
    pub nat_gateway_ref: Option<RouteTableRoutesNatGatewayRef>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "networkInterfaceID")]
    pub network_interface_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "transitGatewayID")]
    pub transit_gateway_id: Option<String>,
    /// Reference field for TransitGatewayID
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "transitGatewayRef")]
    pub transit_gateway_ref: Option<RouteTableRoutesTransitGatewayRef>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vpcEndpointID")]
    pub vpc_endpoint_id: Option<String>,
    /// Reference field for VPCEndpointID
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vpcEndpointRef")]
    pub vpc_endpoint_ref: Option<RouteTableRoutesVpcEndpointRef>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vpcPeeringConnectionID")]
    pub vpc_peering_connection_id: Option<String>,
    /// Reference field for VPCPeeringConnectionID
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vpcPeeringConnectionRef")]
    pub vpc_peering_connection_ref: Option<RouteTableRoutesVpcPeeringConnectionRef>,
}

/// Reference field for GatewayID
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RouteTableRoutesGatewayRef {
    /// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<RouteTableRoutesGatewayRefFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RouteTableRoutesGatewayRefFrom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Reference field for NATGatewayID
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RouteTableRoutesNatGatewayRef {
    /// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<RouteTableRoutesNatGatewayRefFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RouteTableRoutesNatGatewayRefFrom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Reference field for TransitGatewayID
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RouteTableRoutesTransitGatewayRef {
    /// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<RouteTableRoutesTransitGatewayRefFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RouteTableRoutesTransitGatewayRefFrom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Reference field for VPCEndpointID
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RouteTableRoutesVpcEndpointRef {
    /// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<RouteTableRoutesVpcEndpointRefFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RouteTableRoutesVpcEndpointRefFrom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Reference field for VPCPeeringConnectionID
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RouteTableRoutesVpcPeeringConnectionRef {
    /// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<RouteTableRoutesVpcPeeringConnectionRefFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RouteTableRoutesVpcPeeringConnectionRefFrom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Describes a tag.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RouteTableTags {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference type to provide more user friendly syntax for references using 'from' field Ex: APIIDRef: 
///  from: name: my-api
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RouteTableVpcRef {
    /// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<RouteTableVpcRefFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RouteTableVpcRefFrom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// RouteTableStatus defines the observed state of RouteTable
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RouteTableStatus {
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member that is used to contain resource sync state, account ownership, constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<RouteTableStatusAckResourceMetadata>,
    /// The associations between the route table and one or more subnets or a gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub associations: Option<Vec<RouteTableStatusAssociations>>,
    /// All CRS managed by ACK have a common `Status.Conditions` member that contains a collection of `ackv1alpha1.Condition` objects that describe the various terminal states of the CR and its backend AWS service API resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<RouteTableStatusConditions>>,
    /// The ID of the Amazon Web Services account that owns the route table.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ownerID")]
    pub owner_id: Option<String>,
    /// Any virtual private gateway (VGW) propagating routes.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "propagatingVGWs")]
    pub propagating_vg_ws: Option<Vec<RouteTableStatusPropagatingVgWs>>,
    /// The routes in the route table.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "routeStatuses")]
    pub route_statuses: Option<Vec<RouteTableStatusRouteStatuses>>,
    /// The ID of the route table.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "routeTableID")]
    pub route_table_id: Option<String>,
}

/// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member that is used to contain resource sync state, account ownership, constructed ARN for the resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RouteTableStatusAckResourceMetadata {
    /// ARN is the Amazon Resource Name for the resource. This is a globally-unique identifier and is set only by the ACK service controller once the controller has orchestrated the creation of the resource OR when it has verified that an "adopted" resource (a resource where the ARN annotation was set by the Kubernetes user on the CR) exists and matches the supplied CR's Spec field values. TODO(vijat@): Find a better strategy for resources that do not have ARN in CreateOutputResponse https://github.com/aws/aws-controllers-k8s/issues/270
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arn: Option<String>,
    /// OwnerAccountID is the AWS Account ID of the account that owns the backend AWS service API resource.
    #[serde(rename = "ownerAccountID")]
    pub owner_account_id: String,
    /// Region is the AWS region in which the resource exists or will exist.
    pub region: String,
}

/// Describes an association between a route table and a subnet or gateway.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RouteTableStatusAssociations {
    /// Describes the state of an association between a route table and a subnet or gateway.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "associationState")]
    pub association_state: Option<RouteTableStatusAssociationsAssociationState>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "gatewayID")]
    pub gateway_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "routeTableAssociationID")]
    pub route_table_association_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "routeTableID")]
    pub route_table_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "subnetID")]
    pub subnet_id: Option<String>,
}

/// Describes the state of an association between a route table and a subnet or gateway.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RouteTableStatusAssociationsAssociationState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "statusMessage")]
    pub status_message: Option<String>,
}

/// Condition is the common struct used by all CRDs managed by ACK service controllers to indicate terminal states  of the CR and its backend AWS service API resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RouteTableStatusConditions {
    /// Last time the condition transitioned from one status to another.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastTransitionTime")]
    pub last_transition_time: Option<String>,
    /// A human readable message indicating details about the transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// The reason for the condition's last transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Status of the condition, one of True, False, Unknown.
    pub status: String,
    /// Type is the type of the Condition
    #[serde(rename = "type")]
    pub r#type: String,
}

/// Describes a virtual private gateway propagating route.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RouteTableStatusPropagatingVgWs {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "gatewayID")]
    pub gateway_id: Option<String>,
}

/// Describes a route in a route table.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RouteTableStatusRouteStatuses {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "carrierGatewayID")]
    pub carrier_gateway_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "coreNetworkARN")]
    pub core_network_arn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "destinationCIDRBlock")]
    pub destination_cidr_block: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "destinationIPv6CIDRBlock")]
    pub destination_i_pv6_cidr_block: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "destinationPrefixListID")]
    pub destination_prefix_list_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "egressOnlyInternetGatewayID")]
    pub egress_only_internet_gateway_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "gatewayID")]
    pub gateway_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "instanceID")]
    pub instance_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "instanceOwnerID")]
    pub instance_owner_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "localGatewayID")]
    pub local_gateway_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "natGatewayID")]
    pub nat_gateway_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "networkInterfaceID")]
    pub network_interface_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "transitGatewayID")]
    pub transit_gateway_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vpcPeeringConnectionID")]
    pub vpc_peering_connection_id: Option<String>,
}
