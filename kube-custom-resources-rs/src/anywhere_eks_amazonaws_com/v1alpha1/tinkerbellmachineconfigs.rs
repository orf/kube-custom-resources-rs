// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws/eks-anywhere/anywhere.eks.amazonaws.com/v1alpha1/tinkerbellmachineconfigs.yaml --derive=Default --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use std::collections::BTreeMap;
}
use self::prelude::*;

/// TinkerbellMachineConfigSpec defines the desired state of TinkerbellMachineConfig.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "anywhere.eks.amazonaws.com", version = "v1alpha1", kind = "TinkerbellMachineConfig", plural = "tinkerbellmachineconfigs")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
#[kube(derive="Default")]
#[kube(derive="PartialEq")]
pub struct TinkerbellMachineConfigSpec {
    /// HardwareSelector models a simple key-value selector used in Tinkerbell provisioning.
    #[serde(rename = "hardwareSelector")]
    pub hardware_selector: BTreeMap<String, String>,
    /// HostOSConfiguration defines the configuration settings on the host OS.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "hostOSConfiguration")]
    pub host_os_configuration: Option<TinkerbellMachineConfigHostOsConfiguration>,
    #[serde(rename = "osFamily")]
    pub os_family: String,
    /// OSImageURL can be used to override the default OS image path to pull from a local server. OSImageURL is a URL to the OS image used during provisioning. It must include the Kubernetes version(s). For example, a URL used for Kubernetes 1.27 could be http://localhost:8080/ubuntu-2204-1.27.tgz
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "osImageURL")]
    pub os_image_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "templateRef")]
    pub template_ref: Option<TinkerbellMachineConfigTemplateRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<TinkerbellMachineConfigUsers>>,
}

/// HostOSConfiguration defines the configuration settings on the host OS.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TinkerbellMachineConfigHostOsConfiguration {
    /// BottlerocketConfiguration defines the Bottlerocket configuration on the host OS. These settings only take effect when the `osFamily` is bottlerocket.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "bottlerocketConfiguration")]
    pub bottlerocket_configuration: Option<TinkerbellMachineConfigHostOsConfigurationBottlerocketConfiguration>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "certBundles")]
    pub cert_bundles: Option<Vec<TinkerbellMachineConfigHostOsConfigurationCertBundles>>,
    /// NTPConfiguration defines the NTP configuration on the host OS.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ntpConfiguration")]
    pub ntp_configuration: Option<TinkerbellMachineConfigHostOsConfigurationNtpConfiguration>,
}

/// BottlerocketConfiguration defines the Bottlerocket configuration on the host OS. These settings only take effect when the `osFamily` is bottlerocket.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TinkerbellMachineConfigHostOsConfigurationBottlerocketConfiguration {
    /// Boot defines the boot settings for bottlerocket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot: Option<TinkerbellMachineConfigHostOsConfigurationBottlerocketConfigurationBoot>,
    /// Kernel defines the kernel settings for bottlerocket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<TinkerbellMachineConfigHostOsConfigurationBottlerocketConfigurationKernel>,
    /// Kubernetes defines the Kubernetes settings on the host OS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes: Option<TinkerbellMachineConfigHostOsConfigurationBottlerocketConfigurationKubernetes>,
}

/// Boot defines the boot settings for bottlerocket.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TinkerbellMachineConfigHostOsConfigurationBottlerocketConfigurationBoot {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "bootKernelParameters")]
    pub boot_kernel_parameters: Option<BTreeMap<String, String>>,
}

/// Kernel defines the kernel settings for bottlerocket.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TinkerbellMachineConfigHostOsConfigurationBottlerocketConfigurationKernel {
    /// SysctlSettings defines the kernel sysctl settings to set for bottlerocket nodes.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sysctlSettings")]
    pub sysctl_settings: Option<BTreeMap<String, String>>,
}

/// Kubernetes defines the Kubernetes settings on the host OS.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TinkerbellMachineConfigHostOsConfigurationBottlerocketConfigurationKubernetes {
    /// AllowedUnsafeSysctls defines the list of unsafe sysctls that can be set on a node.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "allowedUnsafeSysctls")]
    pub allowed_unsafe_sysctls: Option<Vec<String>>,
    /// ClusterDNSIPs defines IP addresses of the DNS servers.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clusterDNSIPs")]
    pub cluster_dnsi_ps: Option<Vec<String>>,
    /// MaxPods defines the maximum number of pods that can run on a node.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxPods")]
    pub max_pods: Option<i64>,
}

/// Cert defines additional trusted cert bundles on the host OS.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TinkerbellMachineConfigHostOsConfigurationCertBundles {
    /// Data defines the cert bundle data.
    pub data: String,
    /// Name defines the cert bundle name.
    pub name: String,
}

/// NTPConfiguration defines the NTP configuration on the host OS.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TinkerbellMachineConfigHostOsConfigurationNtpConfiguration {
    /// Servers defines a list of NTP servers to be configured on the host OS.
    pub servers: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TinkerbellMachineConfigTemplateRef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// UserConfiguration defines the configuration of the user to be added to the VM.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TinkerbellMachineConfigUsers {
    pub name: String,
    #[serde(rename = "sshAuthorizedKeys")]
    pub ssh_authorized_keys: Vec<String>,
}

/// TinkerbellMachineConfigStatus defines the observed state of TinkerbellMachineConfig.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TinkerbellMachineConfigStatus {
}

