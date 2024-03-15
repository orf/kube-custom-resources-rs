// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/tigera/operator/operator.tigera.io/v1/monitors.yaml --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// MonitorSpec defines the desired state of Tigera monitor.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "operator.tigera.io", version = "v1", kind = "Monitor", plural = "monitors")]
#[kube(status = "MonitorStatus")]
#[kube(schema = "disabled")]
pub struct MonitorSpec {
    /// AlertManager is the configuration for the AlertManager.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "alertManager")]
    pub alert_manager: Option<MonitorAlertManager>,
    /// ExternalPrometheus optionally configures integration with an external Prometheus for scraping Calico metrics. When specified, the operator will render resources in the defined namespace. This option can be useful for configuring scraping from git-ops tools without the need of post-installation steps.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "externalPrometheus")]
    pub external_prometheus: Option<MonitorExternalPrometheus>,
    /// Prometheus is the configuration for the Prometheus.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prometheus: Option<MonitorPrometheus>,
}

/// AlertManager is the configuration for the AlertManager.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MonitorAlertManager {
    /// Spec is the specification of the Alertmanager.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<MonitorAlertManagerSpec>,
}

/// Spec is the specification of the Alertmanager.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MonitorAlertManagerSpec {
    /// Define resources requests and limits for single Pods.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<MonitorAlertManagerSpecResources>,
}

/// Define resources requests and limits for single Pods.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MonitorAlertManagerSpecResources {
    /// Claims lists the names of resources, defined in spec.resourceClaims, that are used by this container. 
    ///  This is an alpha field and requires enabling the DynamicResourceAllocation feature gate. 
    ///  This field is immutable. It can only be set for containers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<MonitorAlertManagerSpecResourcesClaims>>,
    /// Limits describes the maximum amount of compute resources allowed. More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<BTreeMap<String, IntOrString>>,
    /// Requests describes the minimum amount of compute resources required. If Requests is omitted for a container, it defaults to Limits if that is explicitly specified, otherwise to an implementation-defined value. Requests cannot exceed Limits. More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<BTreeMap<String, IntOrString>>,
}

/// ResourceClaim references one entry in PodSpec.ResourceClaims.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MonitorAlertManagerSpecResourcesClaims {
    /// Name must match the name of one entry in pod.spec.resourceClaims of the Pod where this field is used. It makes that resource available inside a container.
    pub name: String,
}

/// ExternalPrometheus optionally configures integration with an external Prometheus for scraping Calico metrics. When specified, the operator will render resources in the defined namespace. This option can be useful for configuring scraping from git-ops tools without the need of post-installation steps.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MonitorExternalPrometheus {
    /// Namespace is the namespace where the operator will create resources for your Prometheus instance. The namespace must be created before the operator will create Prometheus resources.
    pub namespace: String,
    /// ServiceMonitor when specified, the operator will create a ServiceMonitor object in the namespace. It is recommended that you configure labels if you want your prometheus instance to pick up the configuration automatically. The operator will configure 1 endpoint by default: - Params to scrape all metrics available in Calico Enterprise. - BearerTokenSecret (If not overridden, the operator will also create corresponding RBAC that allows authz to the metrics.) - TLSConfig, containing the caFile and serverName.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "serviceMonitor")]
    pub service_monitor: Option<MonitorExternalPrometheusServiceMonitor>,
}

/// ServiceMonitor when specified, the operator will create a ServiceMonitor object in the namespace. It is recommended that you configure labels if you want your prometheus instance to pick up the configuration automatically. The operator will configure 1 endpoint by default: - Params to scrape all metrics available in Calico Enterprise. - BearerTokenSecret (If not overridden, the operator will also create corresponding RBAC that allows authz to the metrics.) - TLSConfig, containing the caFile and serverName.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MonitorExternalPrometheusServiceMonitor {
    /// The endpoints to scrape. This struct contains a subset of the Endpoint as defined in the prometheus docs. Fields related to connecting to our Prometheus server are automatically set by the operator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Vec<MonitorExternalPrometheusServiceMonitorEndpoints>>,
    /// Labels are the metadata.labels of the ServiceMonitor. When combined with spec.serviceMonitorSelector.matchLabels on your prometheus instance, the service monitor will automatically be picked up. Default: k8s-app=tigera-prometheus
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
}

/// Endpoint contains a subset of relevant fields from the Prometheus Endpoint struct.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MonitorExternalPrometheusServiceMonitorEndpoints {
    /// Secret to mount to read bearer token for scraping targets. Recommended: when unset, the operator will create a Secret, a ClusterRole and a ClusterRoleBinding.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "bearerTokenSecret")]
    pub bearer_token_secret: Option<MonitorExternalPrometheusServiceMonitorEndpointsBearerTokenSecret>,
    /// HonorLabels chooses the metric's labels on collisions with target labels.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "honorLabels")]
    pub honor_labels: Option<bool>,
    /// HonorTimestamps controls whether Prometheus respects the timestamps present in scraped data.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "honorTimestamps")]
    pub honor_timestamps: Option<bool>,
    /// Interval at which metrics should be scraped. If not specified Prometheus' global scrape interval is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,
    /// MetricRelabelConfigs to apply to samples before ingestion.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "metricRelabelings")]
    pub metric_relabelings: Option<Vec<MonitorExternalPrometheusServiceMonitorEndpointsMetricRelabelings>>,
    /// Optional HTTP URL parameters Default: scrape all metrics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<BTreeMap<String, String>>,
    /// RelabelConfigs to apply to samples before scraping. Prometheus Operator automatically adds relabelings for a few standard Kubernetes fields. The original scrape job's name is available via the `__tmp_prometheus_job_name` label. More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#relabel_config
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relabelings: Option<Vec<MonitorExternalPrometheusServiceMonitorEndpointsRelabelings>>,
    /// Timeout after which the scrape is ended. If not specified, the Prometheus global scrape timeout is used unless it is less than `Interval` in which the latter is used.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "scrapeTimeout")]
    pub scrape_timeout: Option<String>,
}

/// Secret to mount to read bearer token for scraping targets. Recommended: when unset, the operator will create a Secret, a ClusterRole and a ClusterRoleBinding.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MonitorExternalPrometheusServiceMonitorEndpointsBearerTokenSecret {
    /// The key of the secret to select from.  Must be a valid secret key.
    pub key: String,
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Specify whether the Secret or its key must be defined
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// RelabelConfig allows dynamic rewriting of the label set, being applied to samples before ingestion. It defines `<metric_relabel_configs>`-section of Prometheus configuration. More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#metric_relabel_configs
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MonitorExternalPrometheusServiceMonitorEndpointsMetricRelabelings {
    /// Action to perform based on regex matching. Default is 'replace'. uppercase and lowercase actions require Prometheus >= 2.36.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<MonitorExternalPrometheusServiceMonitorEndpointsMetricRelabelingsAction>,
    /// Modulus to take of the hash of the source label values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modulus: Option<i64>,
    /// Regular expression against which the extracted value is matched. Default is '(.*)'
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    /// Replacement value against which a regex replace is performed if the regular expression matches. Regex capture groups are available. Default is '$1'
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement: Option<String>,
    /// Separator placed between concatenated source label values. default is ';'.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub separator: Option<String>,
    /// The source labels select values from existing labels. Their content is concatenated using the configured separator and matched against the configured regular expression for the replace, keep, and drop actions.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sourceLabels")]
    pub source_labels: Option<Vec<String>>,
    /// Label to which the resulting value is written in a replace action. It is mandatory for replace actions. Regex capture groups are available.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "targetLabel")]
    pub target_label: Option<String>,
}

/// RelabelConfig allows dynamic rewriting of the label set, being applied to samples before ingestion. It defines `<metric_relabel_configs>`-section of Prometheus configuration. More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#metric_relabel_configs
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum MonitorExternalPrometheusServiceMonitorEndpointsMetricRelabelingsAction {
    #[serde(rename = "replace")]
    Replace,
    #[serde(rename = "Replace")]
    ReplaceX,
    #[serde(rename = "keep")]
    Keep,
    #[serde(rename = "Keep")]
    KeepX,
    #[serde(rename = "drop")]
    Drop,
    #[serde(rename = "Drop")]
    DropX,
    #[serde(rename = "hashmod")]
    Hashmod,
    HashMod,
    #[serde(rename = "labelmap")]
    Labelmap,
    LabelMap,
    #[serde(rename = "labeldrop")]
    Labeldrop,
    LabelDrop,
    #[serde(rename = "labelkeep")]
    Labelkeep,
    LabelKeep,
    #[serde(rename = "lowercase")]
    Lowercase,
    #[serde(rename = "Lowercase")]
    LowercaseX,
    #[serde(rename = "uppercase")]
    Uppercase,
    #[serde(rename = "Uppercase")]
    UppercaseX,
}

/// RelabelConfig allows dynamic rewriting of the label set, being applied to samples before ingestion. It defines `<metric_relabel_configs>`-section of Prometheus configuration. More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#metric_relabel_configs
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MonitorExternalPrometheusServiceMonitorEndpointsRelabelings {
    /// Action to perform based on regex matching. Default is 'replace'. uppercase and lowercase actions require Prometheus >= 2.36.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<MonitorExternalPrometheusServiceMonitorEndpointsRelabelingsAction>,
    /// Modulus to take of the hash of the source label values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modulus: Option<i64>,
    /// Regular expression against which the extracted value is matched. Default is '(.*)'
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    /// Replacement value against which a regex replace is performed if the regular expression matches. Regex capture groups are available. Default is '$1'
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement: Option<String>,
    /// Separator placed between concatenated source label values. default is ';'.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub separator: Option<String>,
    /// The source labels select values from existing labels. Their content is concatenated using the configured separator and matched against the configured regular expression for the replace, keep, and drop actions.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sourceLabels")]
    pub source_labels: Option<Vec<String>>,
    /// Label to which the resulting value is written in a replace action. It is mandatory for replace actions. Regex capture groups are available.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "targetLabel")]
    pub target_label: Option<String>,
}

/// RelabelConfig allows dynamic rewriting of the label set, being applied to samples before ingestion. It defines `<metric_relabel_configs>`-section of Prometheus configuration. More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#metric_relabel_configs
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum MonitorExternalPrometheusServiceMonitorEndpointsRelabelingsAction {
    #[serde(rename = "replace")]
    Replace,
    #[serde(rename = "Replace")]
    ReplaceX,
    #[serde(rename = "keep")]
    Keep,
    #[serde(rename = "Keep")]
    KeepX,
    #[serde(rename = "drop")]
    Drop,
    #[serde(rename = "Drop")]
    DropX,
    #[serde(rename = "hashmod")]
    Hashmod,
    HashMod,
    #[serde(rename = "labelmap")]
    Labelmap,
    LabelMap,
    #[serde(rename = "labeldrop")]
    Labeldrop,
    LabelDrop,
    #[serde(rename = "labelkeep")]
    Labelkeep,
    LabelKeep,
    #[serde(rename = "lowercase")]
    Lowercase,
    #[serde(rename = "Lowercase")]
    LowercaseX,
    #[serde(rename = "uppercase")]
    Uppercase,
    #[serde(rename = "Uppercase")]
    UppercaseX,
}

/// Prometheus is the configuration for the Prometheus.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MonitorPrometheus {
    /// Spec is the specification of the Prometheus.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<MonitorPrometheusSpec>,
}

/// Spec is the specification of the Prometheus.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MonitorPrometheusSpec {
    /// CommonPrometheusFields are the options available to both the Prometheus server and agent.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "commonPrometheusFields")]
    pub common_prometheus_fields: Option<MonitorPrometheusSpecCommonPrometheusFields>,
}

/// CommonPrometheusFields are the options available to both the Prometheus server and agent.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MonitorPrometheusSpecCommonPrometheusFields {
    /// Containers is a list of Prometheus containers. If specified, this overrides the specified Prometheus Deployment containers. If omitted, the Prometheus Deployment will use its default values for its containers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub containers: Option<Vec<MonitorPrometheusSpecCommonPrometheusFieldsContainers>>,
    /// Define resources requests and limits for single Pods.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<MonitorPrometheusSpecCommonPrometheusFieldsResources>,
}

/// PrometheusContainer is a Prometheus container.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MonitorPrometheusSpecCommonPrometheusFieldsContainers {
    /// Name is an enum which identifies the Prometheus Deployment container by name.
    pub name: MonitorPrometheusSpecCommonPrometheusFieldsContainersName,
    /// Resources allows customization of limits and requests for compute resources such as cpu and memory. If specified, this overrides the named Prometheus container's resources. If omitted, the Prometheus will use its default value for this container's resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<MonitorPrometheusSpecCommonPrometheusFieldsContainersResources>,
}

/// PrometheusContainer is a Prometheus container.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum MonitorPrometheusSpecCommonPrometheusFieldsContainersName {
    #[serde(rename = "authn-proxy")]
    AuthnProxy,
}

/// Resources allows customization of limits and requests for compute resources such as cpu and memory. If specified, this overrides the named Prometheus container's resources. If omitted, the Prometheus will use its default value for this container's resources.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MonitorPrometheusSpecCommonPrometheusFieldsContainersResources {
    /// Claims lists the names of resources, defined in spec.resourceClaims, that are used by this container. 
    ///  This is an alpha field and requires enabling the DynamicResourceAllocation feature gate. 
    ///  This field is immutable. It can only be set for containers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<MonitorPrometheusSpecCommonPrometheusFieldsContainersResourcesClaims>>,
    /// Limits describes the maximum amount of compute resources allowed. More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<BTreeMap<String, IntOrString>>,
    /// Requests describes the minimum amount of compute resources required. If Requests is omitted for a container, it defaults to Limits if that is explicitly specified, otherwise to an implementation-defined value. Requests cannot exceed Limits. More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<BTreeMap<String, IntOrString>>,
}

/// ResourceClaim references one entry in PodSpec.ResourceClaims.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MonitorPrometheusSpecCommonPrometheusFieldsContainersResourcesClaims {
    /// Name must match the name of one entry in pod.spec.resourceClaims of the Pod where this field is used. It makes that resource available inside a container.
    pub name: String,
}

/// Define resources requests and limits for single Pods.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MonitorPrometheusSpecCommonPrometheusFieldsResources {
    /// Claims lists the names of resources, defined in spec.resourceClaims, that are used by this container. 
    ///  This is an alpha field and requires enabling the DynamicResourceAllocation feature gate. 
    ///  This field is immutable. It can only be set for containers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<MonitorPrometheusSpecCommonPrometheusFieldsResourcesClaims>>,
    /// Limits describes the maximum amount of compute resources allowed. More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<BTreeMap<String, IntOrString>>,
    /// Requests describes the minimum amount of compute resources required. If Requests is omitted for a container, it defaults to Limits if that is explicitly specified, otherwise to an implementation-defined value. Requests cannot exceed Limits. More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<BTreeMap<String, IntOrString>>,
}

/// ResourceClaim references one entry in PodSpec.ResourceClaims.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MonitorPrometheusSpecCommonPrometheusFieldsResourcesClaims {
    /// Name must match the name of one entry in pod.spec.resourceClaims of the Pod where this field is used. It makes that resource available inside a container.
    pub name: String,
}

/// MonitorStatus defines the observed state of Tigera monitor.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MonitorStatus {
    /// Conditions represents the latest observed set of conditions for the component. A component may be one or more of Ready, Progressing, Degraded or other customer types.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// State provides user-readable status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

