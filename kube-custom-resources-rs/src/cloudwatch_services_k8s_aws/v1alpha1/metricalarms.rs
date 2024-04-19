// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/cloudwatch-controller/cloudwatch.services.k8s.aws/v1alpha1/metricalarms.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// MetricAlarmSpec defines the desired state of MetricAlarm.
/// 
/// 
/// The details about a metric alarm.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "cloudwatch.services.k8s.aws", version = "v1alpha1", kind = "MetricAlarm", plural = "metricalarms")]
#[kube(namespaced)]
#[kube(status = "MetricAlarmStatus")]
#[kube(schema = "disabled")]
pub struct MetricAlarmSpec {
    /// Indicates whether actions should be executed during any changes to the alarm
    /// state. The default is TRUE.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "actionsEnabled")]
    pub actions_enabled: Option<bool>,
    /// The actions to execute when this alarm transitions to the ALARM state from
    /// any other state. Each action is specified as an Amazon Resource Name (ARN).
    /// Valid values:
    /// 
    /// 
    /// EC2 actions:
    /// 
    /// 
    ///    * arn:aws:automate:region:ec2:stop
    /// 
    /// 
    ///    * arn:aws:automate:region:ec2:terminate
    /// 
    /// 
    ///    * arn:aws:automate:region:ec2:reboot
    /// 
    /// 
    ///    * arn:aws:automate:region:ec2:recover
    /// 
    /// 
    ///    * arn:aws:swf:region:account-id:action/actions/AWS_EC2.InstanceId.Stop/1.0
    /// 
    /// 
    ///    * arn:aws:swf:region:account-id:action/actions/AWS_EC2.InstanceId.Terminate/1.0
    /// 
    /// 
    ///    * arn:aws:swf:region:account-id:action/actions/AWS_EC2.InstanceId.Reboot/1.0
    /// 
    /// 
    ///    * arn:aws:swf:region:account-id:action/actions/AWS_EC2.InstanceId.Recover/1.0
    /// 
    /// 
    /// Autoscaling action:
    /// 
    /// 
    ///    * arn:aws:autoscaling:region:account-id:scalingPolicy:policy-id:autoScalingGroupName/group-friendly-name:policyName/policy-friendly-name
    /// 
    /// 
    /// SNS notification action:
    /// 
    /// 
    ///    * arn:aws:sns:region:account-id:sns-topic-name:autoScalingGroupName/group-friendly-name:policyName/policy-friendly-name
    /// 
    /// 
    /// SSM integration actions:
    /// 
    /// 
    ///    * arn:aws:ssm:region:account-id:opsitem:severity#CATEGORY=category-name
    /// 
    /// 
    ///    * arn:aws:ssm-incidents::account-id:responseplan/response-plan-name
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "alarmActions")]
    pub alarm_actions: Option<Vec<String>>,
    /// The description for the alarm.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "alarmDescription")]
    pub alarm_description: Option<String>,
    /// The arithmetic operation to use when comparing the specified statistic and
    /// threshold. The specified statistic value is used as the first operand.
    /// 
    /// 
    /// The values LessThanLowerOrGreaterThanUpperThreshold, LessThanLowerThreshold,
    /// and GreaterThanUpperThreshold are used only for alarms based on anomaly detection
    /// models.
    #[serde(rename = "comparisonOperator")]
    pub comparison_operator: String,
    /// The number of data points that must be breaching to trigger the alarm. This
    /// is used only if you are setting an "M out of N" alarm. In that case, this
    /// value is the M. For more information, see Evaluating an Alarm (https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html#alarm-evaluation)
    /// in the Amazon CloudWatch User Guide.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "datapointsToAlarm")]
    pub datapoints_to_alarm: Option<i64>,
    /// The dimensions for the metric specified in MetricName.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dimensions: Option<Vec<MetricAlarmDimensions>>,
    /// Used only for alarms based on percentiles. If you specify ignore, the alarm
    /// state does not change during periods with too few data points to be statistically
    /// significant. If you specify evaluate or omit this parameter, the alarm is
    /// always evaluated and possibly changes state no matter how many data points
    /// are available. For more information, see Percentile-Based CloudWatch Alarms
    /// and Low Data Samples (https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html#percentiles-with-low-samples).
    /// 
    /// 
    /// Valid Values: evaluate | ignore
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "evaluateLowSampleCountPercentile")]
    pub evaluate_low_sample_count_percentile: Option<String>,
    /// The number of periods over which data is compared to the specified threshold.
    /// If you are setting an alarm that requires that a number of consecutive data
    /// points be breaching to trigger the alarm, this value specifies that number.
    /// If you are setting an "M out of N" alarm, this value is the N.
    /// 
    /// 
    /// An alarm's total current evaluation period can be no longer than one day,
    /// so this number multiplied by Period cannot be more than 86,400 seconds.
    #[serde(rename = "evaluationPeriods")]
    pub evaluation_periods: i64,
    /// The extended statistic for the metric specified in MetricName. When you call
    /// PutMetricAlarm and specify a MetricName, you must specify either Statistic
    /// or ExtendedStatistic but not both.
    /// 
    /// 
    /// If you specify ExtendedStatistic, the following are valid values:
    /// 
    /// 
    ///    * p90
    /// 
    /// 
    ///    * tm90
    /// 
    /// 
    ///    * tc90
    /// 
    /// 
    ///    * ts90
    /// 
    /// 
    ///    * wm90
    /// 
    /// 
    ///    * IQM
    /// 
    /// 
    ///    * PR(n:m) where n and m are values of the metric
    /// 
    /// 
    ///    * TC(X%:X%) where X is between 10 and 90 inclusive.
    /// 
    /// 
    ///    * TM(X%:X%) where X is between 10 and 90 inclusive.
    /// 
    /// 
    ///    * TS(X%:X%) where X is between 10 and 90 inclusive.
    /// 
    /// 
    ///    * WM(X%:X%) where X is between 10 and 90 inclusive.
    /// 
    /// 
    /// For more information about these extended statistics, see CloudWatch statistics
    /// definitions (https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Statistics-definitions.html).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "extendedStatistic")]
    pub extended_statistic: Option<String>,
    /// The actions to execute when this alarm transitions to the INSUFFICIENT_DATA
    /// state from any other state. Each action is specified as an Amazon Resource
    /// Name (ARN). Valid values:
    /// 
    /// 
    /// EC2 actions:
    /// 
    /// 
    ///    * arn:aws:automate:region:ec2:stop
    /// 
    /// 
    ///    * arn:aws:automate:region:ec2:terminate
    /// 
    /// 
    ///    * arn:aws:automate:region:ec2:reboot
    /// 
    /// 
    ///    * arn:aws:automate:region:ec2:recover
    /// 
    /// 
    ///    * arn:aws:swf:region:account-id:action/actions/AWS_EC2.InstanceId.Stop/1.0
    /// 
    /// 
    ///    * arn:aws:swf:region:account-id:action/actions/AWS_EC2.InstanceId.Terminate/1.0
    /// 
    /// 
    ///    * arn:aws:swf:region:account-id:action/actions/AWS_EC2.InstanceId.Reboot/1.0
    /// 
    /// 
    ///    * arn:aws:swf:region:account-id:action/actions/AWS_EC2.InstanceId.Recover/1.0
    /// 
    /// 
    /// Autoscaling action:
    /// 
    /// 
    ///    * arn:aws:autoscaling:region:account-id:scalingPolicy:policy-id:autoScalingGroupName/group-friendly-name:policyName/policy-friendly-name
    /// 
    /// 
    /// SNS notification action:
    /// 
    /// 
    ///    * arn:aws:sns:region:account-id:sns-topic-name:autoScalingGroupName/group-friendly-name:policyName/policy-friendly-name
    /// 
    /// 
    /// SSM integration actions:
    /// 
    /// 
    ///    * arn:aws:ssm:region:account-id:opsitem:severity#CATEGORY=category-name
    /// 
    /// 
    ///    * arn:aws:ssm-incidents::account-id:responseplan/response-plan-name
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "insufficientDataActions")]
    pub insufficient_data_actions: Option<Vec<String>>,
    /// The name for the metric associated with the alarm. For each PutMetricAlarm
    /// operation, you must specify either MetricName or a Metrics array.
    /// 
    /// 
    /// If you are creating an alarm based on a math expression, you cannot specify
    /// this parameter, or any of the Namespace, Dimensions, Period, Unit, Statistic,
    /// or ExtendedStatistic parameters. Instead, you specify all this information
    /// in the Metrics array.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "metricName")]
    pub metric_name: Option<String>,
    /// An array of MetricDataQuery structures that enable you to create an alarm
    /// based on the result of a metric math expression. For each PutMetricAlarm
    /// operation, you must specify either MetricName or a Metrics array.
    /// 
    /// 
    /// Each item in the Metrics array either retrieves a metric or performs a math
    /// expression.
    /// 
    /// 
    /// One item in the Metrics array is the expression that the alarm watches. You
    /// designate this expression by setting ReturnData to true for this object in
    /// the array. For more information, see MetricDataQuery (https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_MetricDataQuery.html).
    /// 
    /// 
    /// If you use the Metrics parameter, you cannot include the Namespace, MetricName,
    /// Dimensions, Period, Unit, Statistic, or ExtendedStatistic parameters of PutMetricAlarm
    /// in the same operation. Instead, you retrieve the metrics you are using in
    /// your math expression as part of the Metrics array.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<Vec<MetricAlarmMetrics>>,
    /// The name for the alarm. This name must be unique within the Region.
    /// 
    /// 
    /// The name must contain only UTF-8 characters, and can't contain ASCII control
    /// characters
    pub name: String,
    /// The namespace for the metric associated specified in MetricName.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// The actions to execute when this alarm transitions to an OK state from any
    /// other state. Each action is specified as an Amazon Resource Name (ARN). Valid
    /// values:
    /// 
    /// 
    /// EC2 actions:
    /// 
    /// 
    ///    * arn:aws:automate:region:ec2:stop
    /// 
    /// 
    ///    * arn:aws:automate:region:ec2:terminate
    /// 
    /// 
    ///    * arn:aws:automate:region:ec2:reboot
    /// 
    /// 
    ///    * arn:aws:automate:region:ec2:recover
    /// 
    /// 
    ///    * arn:aws:swf:region:account-id:action/actions/AWS_EC2.InstanceId.Stop/1.0
    /// 
    /// 
    ///    * arn:aws:swf:region:account-id:action/actions/AWS_EC2.InstanceId.Terminate/1.0
    /// 
    /// 
    ///    * arn:aws:swf:region:account-id:action/actions/AWS_EC2.InstanceId.Reboot/1.0
    /// 
    /// 
    ///    * arn:aws:swf:region:account-id:action/actions/AWS_EC2.InstanceId.Recover/1.0
    /// 
    /// 
    /// Autoscaling action:
    /// 
    /// 
    ///    * arn:aws:autoscaling:region:account-id:scalingPolicy:policy-id:autoScalingGroupName/group-friendly-name:policyName/policy-friendly-name
    /// 
    /// 
    /// SNS notification action:
    /// 
    /// 
    ///    * arn:aws:sns:region:account-id:sns-topic-name:autoScalingGroupName/group-friendly-name:policyName/policy-friendly-name
    /// 
    /// 
    /// SSM integration actions:
    /// 
    /// 
    ///    * arn:aws:ssm:region:account-id:opsitem:severity#CATEGORY=category-name
    /// 
    /// 
    ///    * arn:aws:ssm-incidents::account-id:responseplan/response-plan-name
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "oKActions")]
    pub o_k_actions: Option<Vec<String>>,
    /// The length, in seconds, used each time the metric specified in MetricName
    /// is evaluated. Valid values are 10, 30, and any multiple of 60.
    /// 
    /// 
    /// Period is required for alarms based on static thresholds. If you are creating
    /// an alarm based on a metric math expression, you specify the period for each
    /// metric within the objects in the Metrics array.
    /// 
    /// 
    /// Be sure to specify 10 or 30 only for metrics that are stored by a PutMetricData
    /// call with a StorageResolution of 1. If you specify a period of 10 or 30 for
    /// a metric that does not have sub-minute resolution, the alarm still attempts
    /// to gather data at the period rate that you specify. In this case, it does
    /// not receive data for the attempts that do not correspond to a one-minute
    /// data resolution, and the alarm might often lapse into INSUFFICENT_DATA status.
    /// Specifying 10 or 30 also sets this alarm as a high-resolution alarm, which
    /// has a higher charge than other alarms. For more information about pricing,
    /// see Amazon CloudWatch Pricing (https://aws.amazon.com/cloudwatch/pricing/).
    /// 
    /// 
    /// An alarm's total current evaluation period can be no longer than one day,
    /// so Period multiplied by EvaluationPeriods cannot be more than 86,400 seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<i64>,
    /// The statistic for the metric specified in MetricName, other than percentile.
    /// For percentile statistics, use ExtendedStatistic. When you call PutMetricAlarm
    /// and specify a MetricName, you must specify either Statistic or ExtendedStatistic,
    /// but not both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statistic: Option<String>,
    /// A list of key-value pairs to associate with the alarm. You can associate
    /// as many as 50 tags with an alarm. To be able to associate tags with the alarm
    /// when you create the alarm, you must have the cloudwatch:TagResource permission.
    /// 
    /// 
    /// Tags can help you organize and categorize your resources. You can also use
    /// them to scope user permissions by granting a user permission to access or
    /// change only resources with certain tag values.
    /// 
    /// 
    /// If you are using this operation to update an existing alarm, any tags you
    /// specify in this parameter are ignored. To change the tags of an existing
    /// alarm, use TagResource (https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_TagResource.html)
    /// or UntagResource (https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_UntagResource.html).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<MetricAlarmTags>>,
    /// The value against which the specified statistic is compared.
    /// 
    /// 
    /// This parameter is required for alarms based on static thresholds, but should
    /// not be used for alarms based on anomaly detection models.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
    /// If this is an alarm based on an anomaly detection model, make this value
    /// match the ID of the ANOMALY_DETECTION_BAND function.
    /// 
    /// 
    /// For an example of how to use this parameter, see the Anomaly Detection Model
    /// Alarm example on this page.
    /// 
    /// 
    /// If your alarm uses this parameter, it cannot have Auto Scaling actions.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "thresholdMetricID")]
    pub threshold_metric_id: Option<String>,
    /// Sets how this alarm is to handle missing data points. If TreatMissingData
    /// is omitted, the default behavior of missing is used. For more information,
    /// see Configuring How CloudWatch Alarms Treats Missing Data (https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html#alarms-and-missing-data).
    /// 
    /// 
    /// Valid Values: breaching | notBreaching | ignore | missing
    /// 
    /// 
    /// Alarms that evaluate metrics in the AWS/DynamoDB namespace always ignore
    /// missing data even if you choose a different option for TreatMissingData.
    /// When an AWS/DynamoDB metric has missing data, alarms that evaluate that metric
    /// remain in their current state.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "treatMissingData")]
    pub treat_missing_data: Option<String>,
    /// The unit of measure for the statistic. For example, the units for the Amazon
    /// EC2 NetworkIn metric are Bytes because NetworkIn tracks the number of bytes
    /// that an instance receives on all network interfaces. You can also specify
    /// a unit when you create a custom metric. Units help provide conceptual meaning
    /// to your data. Metric data points that specify a unit of measure, such as
    /// Percent, are aggregated separately. If you are creating an alarm based on
    /// a metric math expression, you can specify the unit for each metric (if needed)
    /// within the objects in the Metrics array.
    /// 
    /// 
    /// If you don't specify Unit, CloudWatch retrieves all unit types that have
    /// been published for the metric and attempts to evaluate the alarm. Usually,
    /// metrics are published with only one unit, so the alarm works as intended.
    /// 
    /// 
    /// However, if the metric is published with multiple types of units and you
    /// don't specify a unit, the alarm's behavior is not defined and it behaves
    /// unpredictably.
    /// 
    /// 
    /// We recommend omitting Unit so that you don't inadvertently specify an incorrect
    /// unit that is not published for this metric. Doing so causes the alarm to
    /// be stuck in the INSUFFICIENT DATA state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

/// A dimension is a name/value pair that is part of the identity of a metric.
/// Because dimensions are part of the unique identifier for a metric, whenever
/// you add a unique name/value pair to one of your metrics, you are creating
/// a new variation of that metric. For example, many Amazon EC2 metrics publish
/// InstanceId as a dimension name, and the actual instance ID as the value for
/// that dimension.
/// 
/// 
/// You can assign up to 30 dimensions to a metric.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MetricAlarmDimensions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// This structure is used in both GetMetricData and PutMetricAlarm. The supported
/// use of this structure is different for those two operations.
/// 
/// 
/// When used in GetMetricData, it indicates the metric data to return, and whether
/// this call is just retrieving a batch set of data for one metric, or is performing
/// a Metrics Insights query or a math expression. A single GetMetricData call
/// can include up to 500 MetricDataQuery structures.
/// 
/// 
/// When used in PutMetricAlarm, it enables you to create an alarm based on a
/// metric math expression. Each MetricDataQuery in the array specifies either
/// a metric to retrieve, or a math expression to be performed on retrieved metrics.
/// A single PutMetricAlarm call can include up to 20 MetricDataQuery structures
/// in the array. The 20 structures can include as many as 10 structures that
/// contain a MetricStat parameter to retrieve a metric, and as many as 10 structures
/// that contain the Expression parameter to perform a math expression. Of those
/// Expression structures, one must have true as the value for ReturnData. The
/// result of this expression is the value the alarm watches.
/// 
/// 
/// Any expression used in a PutMetricAlarm operation must return a single time
/// series. For more information, see Metric Math Syntax and Functions (https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/using-metric-math.html#metric-math-syntax)
/// in the Amazon CloudWatch User Guide.
/// 
/// 
/// Some of the parameters of this structure also have different uses whether
/// you are using this structure in a GetMetricData operation or a PutMetricAlarm
/// operation. These differences are explained in the following parameter list.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MetricAlarmMetrics {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "accountID")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// This structure defines the metric to be returned, along with the statistics,
    /// period, and units.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "metricStat")]
    pub metric_stat: Option<MetricAlarmMetricsMetricStat>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "returnData")]
    pub return_data: Option<bool>,
}

/// This structure defines the metric to be returned, along with the statistics,
/// period, and units.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MetricAlarmMetricsMetricStat {
    /// Represents a specific metric.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metric: Option<MetricAlarmMetricsMetricStatMetric>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stat: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

/// Represents a specific metric.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MetricAlarmMetricsMetricStatMetric {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dimensions: Option<Vec<MetricAlarmMetricsMetricStatMetricDimensions>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "metricName")]
    pub metric_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// A dimension is a name/value pair that is part of the identity of a metric.
/// Because dimensions are part of the unique identifier for a metric, whenever
/// you add a unique name/value pair to one of your metrics, you are creating
/// a new variation of that metric. For example, many Amazon EC2 metrics publish
/// InstanceId as a dimension name, and the actual instance ID as the value for
/// that dimension.
/// 
/// 
/// You can assign up to 30 dimensions to a metric.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MetricAlarmMetricsMetricStatMetricDimensions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// A key-value pair associated with a CloudWatch resource.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MetricAlarmTags {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// MetricAlarmStatus defines the observed state of MetricAlarm
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MetricAlarmStatus {
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
    /// that is used to contain resource sync state, account ownership,
    /// constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<MetricAlarmStatusAckResourceMetadata>,
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
pub struct MetricAlarmStatusAckResourceMetadata {
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

