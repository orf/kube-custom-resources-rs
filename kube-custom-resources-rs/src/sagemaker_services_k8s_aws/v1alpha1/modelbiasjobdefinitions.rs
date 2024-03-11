// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/sagemaker-controller/sagemaker.services.k8s.aws/v1alpha1/modelbiasjobdefinitions.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// ModelBiasJobDefinitionSpec defines the desired state of ModelBiasJobDefinition.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "sagemaker.services.k8s.aws", version = "v1alpha1", kind = "ModelBiasJobDefinition", plural = "modelbiasjobdefinitions")]
#[kube(namespaced)]
#[kube(status = "ModelBiasJobDefinitionStatus")]
#[kube(schema = "disabled")]
pub struct ModelBiasJobDefinitionSpec {
    /// The name of the bias job definition. The name must be unique within an Amazon
    /// Web Services Region in the Amazon Web Services account.
    #[serde(rename = "jobDefinitionName")]
    pub job_definition_name: String,
    /// Identifies the resources to deploy for a monitoring job.
    #[serde(rename = "jobResources")]
    pub job_resources: ModelBiasJobDefinitionJobResources,
    /// Configures the model bias job to run a specified Docker container image.
    #[serde(rename = "modelBiasAppSpecification")]
    pub model_bias_app_specification: ModelBiasJobDefinitionModelBiasAppSpecification,
    /// The baseline configuration for a model bias job.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "modelBiasBaselineConfig")]
    pub model_bias_baseline_config: Option<ModelBiasJobDefinitionModelBiasBaselineConfig>,
    /// Inputs for the model bias job.
    #[serde(rename = "modelBiasJobInput")]
    pub model_bias_job_input: ModelBiasJobDefinitionModelBiasJobInput,
    /// The output configuration for monitoring jobs.
    #[serde(rename = "modelBiasJobOutputConfig")]
    pub model_bias_job_output_config: ModelBiasJobDefinitionModelBiasJobOutputConfig,
    /// Networking options for a model bias job.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "networkConfig")]
    pub network_config: Option<ModelBiasJobDefinitionNetworkConfig>,
    /// The Amazon Resource Name (ARN) of an IAM role that Amazon SageMaker can assume
    /// to perform tasks on your behalf.
    #[serde(rename = "roleARN")]
    pub role_arn: String,
    /// A time limit for how long the monitoring job is allowed to run before stopping.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "stoppingCondition")]
    pub stopping_condition: Option<ModelBiasJobDefinitionStoppingCondition>,
    /// (Optional) An array of key-value pairs. For more information, see Using Cost
    /// Allocation Tags (https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/cost-alloc-tags.html#allocation-whatURL)
    /// in the Amazon Web Services Billing and Cost Management User Guide.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<ModelBiasJobDefinitionTags>>,
}

/// Identifies the resources to deploy for a monitoring job.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModelBiasJobDefinitionJobResources {
    /// Configuration for the cluster used to run model monitoring jobs.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "clusterConfig")]
    pub cluster_config: Option<ModelBiasJobDefinitionJobResourcesClusterConfig>,
}

/// Configuration for the cluster used to run model monitoring jobs.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModelBiasJobDefinitionJobResourcesClusterConfig {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "instanceCount")]
    pub instance_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "instanceType")]
    pub instance_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "volumeKMSKeyID")]
    pub volume_kms_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "volumeSizeInGB")]
    pub volume_size_in_gb: Option<i64>,
}

/// Configures the model bias job to run a specified Docker container image.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModelBiasJobDefinitionModelBiasAppSpecification {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "configURI")]
    pub config_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "imageURI")]
    pub image_uri: Option<String>,
}

/// The baseline configuration for a model bias job.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModelBiasJobDefinitionModelBiasBaselineConfig {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "baseliningJobName")]
    pub baselining_job_name: Option<String>,
    /// The constraints resource for a monitoring job.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "constraintsResource")]
    pub constraints_resource: Option<ModelBiasJobDefinitionModelBiasBaselineConfigConstraintsResource>,
}

/// The constraints resource for a monitoring job.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModelBiasJobDefinitionModelBiasBaselineConfigConstraintsResource {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "s3URI")]
    pub s3_uri: Option<String>,
}

/// Inputs for the model bias job.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModelBiasJobDefinitionModelBiasJobInput {
    /// Input object for the endpoint
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "endpointInput")]
    pub endpoint_input: Option<ModelBiasJobDefinitionModelBiasJobInputEndpointInput>,
    /// The ground truth labels for the dataset used for the monitoring job.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "groundTruthS3Input")]
    pub ground_truth_s3_input: Option<ModelBiasJobDefinitionModelBiasJobInputGroundTruthS3Input>,
}

/// Input object for the endpoint
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModelBiasJobDefinitionModelBiasJobInputEndpointInput {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "endTimeOffset")]
    pub end_time_offset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "endpointName")]
    pub endpoint_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "excludeFeaturesAttribute")]
    pub exclude_features_attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "featuresAttribute")]
    pub features_attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "inferenceAttribute")]
    pub inference_attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "localPath")]
    pub local_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "probabilityAttribute")]
    pub probability_attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "probabilityThresholdAttribute")]
    pub probability_threshold_attribute: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "s3DataDistributionType")]
    pub s3_data_distribution_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "s3InputMode")]
    pub s3_input_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "startTimeOffset")]
    pub start_time_offset: Option<String>,
}

/// The ground truth labels for the dataset used for the monitoring job.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModelBiasJobDefinitionModelBiasJobInputGroundTruthS3Input {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "s3URI")]
    pub s3_uri: Option<String>,
}

/// The output configuration for monitoring jobs.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModelBiasJobDefinitionModelBiasJobOutputConfig {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "kmsKeyID")]
    pub kms_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "monitoringOutputs")]
    pub monitoring_outputs: Option<Vec<ModelBiasJobDefinitionModelBiasJobOutputConfigMonitoringOutputs>>,
}

/// The output object for a monitoring job.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModelBiasJobDefinitionModelBiasJobOutputConfigMonitoringOutputs {
    /// Information about where and how you want to store the results of a monitoring
    /// job.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "s3Output")]
    pub s3_output: Option<ModelBiasJobDefinitionModelBiasJobOutputConfigMonitoringOutputsS3Output>,
}

/// Information about where and how you want to store the results of a monitoring
/// job.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModelBiasJobDefinitionModelBiasJobOutputConfigMonitoringOutputsS3Output {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "localPath")]
    pub local_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "s3URI")]
    pub s3_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "s3UploadMode")]
    pub s3_upload_mode: Option<String>,
}

/// Networking options for a model bias job.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModelBiasJobDefinitionNetworkConfig {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "enableInterContainerTrafficEncryption")]
    pub enable_inter_container_traffic_encryption: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "enableNetworkIsolation")]
    pub enable_network_isolation: Option<bool>,
    /// Specifies an Amazon Virtual Private Cloud (VPC) that your SageMaker jobs,
    /// hosted models, and compute resources have access to. You can control access
    /// to and from your resources by configuring a VPC. For more information, see
    /// Give SageMaker Access to Resources in your Amazon VPC (https://docs.aws.amazon.com/sagemaker/latest/dg/infrastructure-give-access.html).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vpcConfig")]
    pub vpc_config: Option<ModelBiasJobDefinitionNetworkConfigVpcConfig>,
}

/// Specifies an Amazon Virtual Private Cloud (VPC) that your SageMaker jobs,
/// hosted models, and compute resources have access to. You can control access
/// to and from your resources by configuring a VPC. For more information, see
/// Give SageMaker Access to Resources in your Amazon VPC (https://docs.aws.amazon.com/sagemaker/latest/dg/infrastructure-give-access.html).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModelBiasJobDefinitionNetworkConfigVpcConfig {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "securityGroupIDs")]
    pub security_group_i_ds: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subnets: Option<Vec<String>>,
}

/// A time limit for how long the monitoring job is allowed to run before stopping.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModelBiasJobDefinitionStoppingCondition {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxRuntimeInSeconds")]
    pub max_runtime_in_seconds: Option<i64>,
}

/// A tag object that consists of a key and an optional value, used to manage
/// metadata for SageMaker Amazon Web Services resources.
/// 
/// 
/// You can add tags to notebook instances, training jobs, hyperparameter tuning
/// jobs, batch transform jobs, models, labeling jobs, work teams, endpoint configurations,
/// and endpoints. For more information on adding tags to SageMaker resources,
/// see AddTags (https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_AddTags.html).
/// 
/// 
/// For more information on adding metadata to your Amazon Web Services resources
/// with tagging, see Tagging Amazon Web Services resources (https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html).
/// For advice on best practices for managing Amazon Web Services resources with
/// tagging, see Tagging Best Practices: Implement an Effective Amazon Web Services
/// Resource Tagging Strategy (https://d1.awsstatic.com/whitepapers/aws-tagging-best-practices.pdf).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModelBiasJobDefinitionTags {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// ModelBiasJobDefinitionStatus defines the observed state of ModelBiasJobDefinition
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ModelBiasJobDefinitionStatus {
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
    /// that is used to contain resource sync state, account ownership,
    /// constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<ModelBiasJobDefinitionStatusAckResourceMetadata>,
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
pub struct ModelBiasJobDefinitionStatusAckResourceMetadata {
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

