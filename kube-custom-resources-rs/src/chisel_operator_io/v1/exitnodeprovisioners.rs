// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/FyraLabs/chisel-operator/chisel-operator.io/v1/exitnodeprovisioners.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};

/// ExitNodeProvisioner is a custom resource that represents a Chisel exit node provisioner on a cloud provider.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "chisel-operator.io", version = "v1", kind = "ExitNodeProvisioner", plural = "exitnodeprovisioners")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct ExitNodeProvisionerSpec {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "AWS")]
    pub aws: Option<ExitNodeProvisionerAws>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "DigitalOcean")]
    pub digital_ocean: Option<ExitNodeProvisionerDigitalOcean>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Linode")]
    pub linode: Option<ExitNodeProvisionerLinode>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ExitNodeProvisionerAws {
    /// Reference to a secret containing the AWS access key ID and secret access key, under the `access_key_id` and `secret_access_key` secret keys
    pub auth: String,
    /// Region ID for the AWS region to provision the exit node in See https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html
    pub region: String,
    /// Security group name to use for the exit node, uses the default security group if not specified
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_group: Option<String>,
    /// Size for the EC2 instance See https://aws.amazon.com/ec2/instance-types/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ExitNodeProvisionerDigitalOcean {
    /// Reference to a secret containing the DigitalOcean API token, under the `DIGITALOCEAN_TOKEN` secret key
    pub auth: String,
    /// Region ID of the DigitalOcean datacenter to provision the exit node in If empty, DigitalOcean will randomly select a region for you, which might not be what you want See https://slugs.do-api.dev/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Size for the DigitalOcean droplet See https://slugs.do-api.dev/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    /// SSH key fingerprints to add to the exit node
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_fingerprints: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ExitNodeProvisionerLinode {
    /// Name of the secret containing the Linode API token, under the `LINODE_TOKEN` secret key
    pub auth: String,
    /// Region ID of the Linode datacenter to provision the exit node in See https://api.linode.com/v4/regions
    pub region: String,
    /// Size for the Linode instance See https://api.linode.com/v4/linode/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
}

