// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/openshift/api/samples.operator.openshift.io/v1/configs.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// ConfigSpec contains the desired configuration and state for the Samples Operator, controlling various behavior around the imagestreams and templates it creates/updates in the openshift namespace.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "samples.operator.openshift.io", version = "v1", kind = "Config", plural = "configs")]
#[kube(status = "ConfigStatus")]
#[kube(schema = "disabled")]
pub struct ConfigSpec {
    /// architectures determine which hardware architecture(s) to install, where x86_64, ppc64le, and s390x are the only supported choices currently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architectures: Option<Vec<String>>,
    /// managementState is top level on/off type of switch for all operators. When "Managed", this operator processes config and manipulates the samples accordingly. When "Unmanaged", this operator ignores any updates to the resources it watches. When "Removed", it reacts that same wasy as it does if the Config object is deleted, meaning any ImageStreams or Templates it manages (i.e. it honors the skipped lists) and the registry secret are deleted, along with the ConfigMap in the operator's namespace that represents the last config used to manipulate the samples,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "managementState")]
    pub management_state: Option<String>,
    /// samplesRegistry allows for the specification of which registry is accessed by the ImageStreams for their image content.  Defaults on the content in https://github.com/openshift/library that are pulled into this github repository, but based on our pulling only ocp content it typically defaults to registry.redhat.io.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "samplesRegistry")]
    pub samples_registry: Option<String>,
    /// skippedHelmCharts specifies names of helm charts that should NOT be managed. Admins can use this to allow them to delete content they don’t want. They will still have to MANUALLY DELETE the content but the operator will not recreate(or update) anything listed here. Few examples of the name of helmcharts which can be skipped are 'redhat-redhat-perl-imagestreams','redhat-redhat-nodejs-imagestreams','redhat-nginx-imagestreams', 'redhat-redhat-ruby-imagestreams','redhat-redhat-python-imagestreams','redhat-redhat-php-imagestreams', 'redhat-httpd-imagestreams','redhat-redhat-dotnet-imagestreams'. Rest of the names can be obtained from openshift console --> helmcharts -->installed helmcharts. This will display the list of all the 12 helmcharts(of imagestreams)being installed by Samples Operator. The skippedHelmCharts must be a valid Kubernetes resource name. May contain only lowercase alphanumeric characters, hyphens and periods, and each period separated segment must begin and end with an alphanumeric character. It must be non-empty and at most 253 characters in length
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "skippedHelmCharts")]
    pub skipped_helm_charts: Option<Vec<String>>,
    /// skippedImagestreams specifies names of image streams that should NOT be created/updated.  Admins can use this to allow them to delete content they don’t want.  They will still have to manually delete the content but the operator will not recreate(or update) anything listed here.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "skippedImagestreams")]
    pub skipped_imagestreams: Option<Vec<String>>,
    /// skippedTemplates specifies names of templates that should NOT be created/updated.  Admins can use this to allow them to delete content they don’t want.  They will still have to manually delete the content but the operator will not recreate(or update) anything listed here.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "skippedTemplates")]
    pub skipped_templates: Option<Vec<String>>,
}

/// ConfigStatus contains the actual configuration in effect, as well as various details that describe the state of the Samples Operator.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ConfigStatus {
    /// architectures determine which hardware architecture(s) to install, where x86_64 and ppc64le are the supported choices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architectures: Option<Vec<String>>,
    /// conditions represents the available maintenance status of the sample imagestreams and templates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// managementState reflects the current operational status of the on/off switch for the operator.  This operator compares the ManagementState as part of determining that we are turning the operator back on (i.e. "Managed") when it was previously "Unmanaged".
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "managementState")]
    pub management_state: Option<String>,
    /// samplesRegistry allows for the specification of which registry is accessed by the ImageStreams for their image content.  Defaults on the content in https://github.com/openshift/library that are pulled into this github repository, but based on our pulling only ocp content it typically defaults to registry.redhat.io.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "samplesRegistry")]
    pub samples_registry: Option<String>,
    /// skippedImagestreams specifies names of image streams that should NOT be created/updated.  Admins can use this to allow them to delete content they don’t want.  They will still have to manually delete the content but the operator will not recreate(or update) anything listed here.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "skippedImagestreams")]
    pub skipped_imagestreams: Option<Vec<String>>,
    /// skippedTemplates specifies names of templates that should NOT be created/updated.  Admins can use this to allow them to delete content they don’t want.  They will still have to manually delete the content but the operator will not recreate(or update) anything listed here.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "skippedTemplates")]
    pub skipped_templates: Option<Vec<String>>,
    /// version is the value of the operator's payload based version indicator when it was last successfully processed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

