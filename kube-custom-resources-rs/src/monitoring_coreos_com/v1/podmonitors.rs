// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/prometheus-operator/prometheus-operator/monitoring.coreos.com/v1/podmonitors.yaml --derive=Default --derive=PartialEq
// kopium version: 0.16.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

/// Specification of desired Pod selection for target discovery by Prometheus.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "monitoring.coreos.com", version = "v1", kind = "PodMonitor", plural = "podmonitors")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct PodMonitorSpec {
    /// `attachMetadata` defines additional metadata which is added to the discovered targets. 
    ///  It requires Prometheus >= v2.37.0.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "attachMetadata")]
    pub attach_metadata: Option<PodMonitorAttachMetadata>,
    /// The label to use to retrieve the job name from. `jobLabel` selects the label from the associated Kubernetes `Pod` object which will be used as the `job` label for all metrics. 
    ///  For example if `jobLabel` is set to `foo` and the Kubernetes `Pod` object is labeled with `foo: bar`, then Prometheus adds the `job="bar"` label to all ingested metrics. 
    ///  If the value of this field is empty, the `job` label of the metrics defaults to the namespace and name of the PodMonitor object (e.g. `<namespace>/<name>`).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "jobLabel")]
    pub job_label: Option<String>,
    /// Per-scrape limit on the number of targets dropped by relabeling that will be kept in memory. 0 means no limit. 
    ///  It requires Prometheus >= v2.47.0.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "keepDroppedTargets")]
    pub keep_dropped_targets: Option<i64>,
    /// Per-scrape limit on number of labels that will be accepted for a sample. 
    ///  It requires Prometheus >= v2.27.0.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "labelLimit")]
    pub label_limit: Option<i64>,
    /// Per-scrape limit on length of labels name that will be accepted for a sample. 
    ///  It requires Prometheus >= v2.27.0.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "labelNameLengthLimit")]
    pub label_name_length_limit: Option<i64>,
    /// Per-scrape limit on length of labels value that will be accepted for a sample. 
    ///  It requires Prometheus >= v2.27.0.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "labelValueLengthLimit")]
    pub label_value_length_limit: Option<i64>,
    /// Selector to select which namespaces the Kubernetes `Pods` objects are discovered from.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "namespaceSelector")]
    pub namespace_selector: Option<PodMonitorNamespaceSelector>,
    /// List of endpoints part of this PodMonitor.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "podMetricsEndpoints")]
    pub pod_metrics_endpoints: Option<Vec<PodMonitorPodMetricsEndpoints>>,
    /// `podTargetLabels` defines the labels which are transferred from the associated Kubernetes `Pod` object onto the ingested metrics.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "podTargetLabels")]
    pub pod_target_labels: Option<Vec<String>>,
    /// `sampleLimit` defines a per-scrape limit on the number of scraped samples that will be accepted.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sampleLimit")]
    pub sample_limit: Option<i64>,
    /// Label selector to select the Kubernetes `Pod` objects.
    pub selector: PodMonitorSelector,
    /// `targetLimit` defines a limit on the number of scraped targets that will be accepted.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "targetLimit")]
    pub target_limit: Option<i64>,
}

/// `attachMetadata` defines additional metadata which is added to the discovered targets. 
///  It requires Prometheus >= v2.37.0.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorAttachMetadata {
    /// When set to true, Prometheus must have the `get` permission on the `Nodes` objects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<bool>,
}

/// Selector to select which namespaces the Kubernetes `Pods` objects are discovered from.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorNamespaceSelector {
    /// Boolean describing whether all namespaces are selected in contrast to a list restricting them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub any: Option<bool>,
    /// List of namespace names to select from.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchNames")]
    pub match_names: Option<Vec<String>>,
}

/// PodMetricsEndpoint defines an endpoint serving Prometheus metrics to be scraped by Prometheus.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorPodMetricsEndpoints {
    /// `authorization` configures the Authorization header credentials to use when scraping the target. 
    ///  Cannot be set at the same time as `basicAuth`, or `oauth2`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<PodMonitorPodMetricsEndpointsAuthorization>,
    /// `basicAuth` configures the Basic Authentication credentials to use when scraping the target. 
    ///  Cannot be set at the same time as `authorization`, or `oauth2`.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "basicAuth")]
    pub basic_auth: Option<PodMonitorPodMetricsEndpointsBasicAuth>,
    /// `bearerTokenSecret` specifies a key of a Secret containing the bearer token for scraping targets. The secret needs to be in the same namespace as the PodMonitor object and readable by the Prometheus Operator. 
    ///  Deprecated: use `authorization` instead.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "bearerTokenSecret")]
    pub bearer_token_secret: Option<PodMonitorPodMetricsEndpointsBearerTokenSecret>,
    /// `enableHttp2` can be used to disable HTTP2 when scraping the target.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "enableHttp2")]
    pub enable_http2: Option<bool>,
    /// When true, the pods which are not running (e.g. either in Failed or Succeeded state) are dropped during the target discovery. 
    ///  If unset, the filtering is enabled. 
    ///  More info: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-phase
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "filterRunning")]
    pub filter_running: Option<bool>,
    /// `followRedirects` defines whether the scrape requests should follow HTTP 3xx redirects.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "followRedirects")]
    pub follow_redirects: Option<bool>,
    /// When true, `honorLabels` preserves the metric's labels when they collide with the target's labels.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "honorLabels")]
    pub honor_labels: Option<bool>,
    /// `honorTimestamps` controls whether Prometheus preserves the timestamps when exposed by the target.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "honorTimestamps")]
    pub honor_timestamps: Option<bool>,
    /// Interval at which Prometheus scrapes the metrics from the target. 
    ///  If empty, Prometheus uses the global scrape interval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,
    /// `metricRelabelings` configures the relabeling rules to apply to the samples before ingestion.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "metricRelabelings")]
    pub metric_relabelings: Option<Vec<PodMonitorPodMetricsEndpointsMetricRelabelings>>,
    /// `oauth2` configures the OAuth2 settings to use when scraping the target. 
    ///  It requires Prometheus >= 2.27.0. 
    ///  Cannot be set at the same time as `authorization`, or `basicAuth`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth2: Option<PodMonitorPodMetricsEndpointsOauth2>,
    /// `params` define optional HTTP URL parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<BTreeMap<String, String>>,
    /// HTTP path from which to scrape for metrics. 
    ///  If empty, Prometheus uses the default value (e.g. `/metrics`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Name of the Pod port which this endpoint refers to. 
    ///  It takes precedence over `targetPort`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
    /// `proxyURL` configures the HTTP Proxy URL (e.g. "http://proxyserver:2195") to go through when scraping the target.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "proxyUrl")]
    pub proxy_url: Option<String>,
    /// `relabelings` configures the relabeling rules to apply the target's metadata labels. 
    ///  The Operator automatically adds relabelings for a few standard Kubernetes fields. 
    ///  The original scrape job's name is available via the `__tmp_prometheus_job_name` label. 
    ///  More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#relabel_config
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relabelings: Option<Vec<PodMonitorPodMetricsEndpointsRelabelings>>,
    /// HTTP scheme to use for scraping. 
    ///  `http` and `https` are the expected values unless you rewrite the `__scheme__` label via relabeling. 
    ///  If empty, Prometheus uses the default value `http`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<PodMonitorPodMetricsEndpointsScheme>,
    /// Timeout after which Prometheus considers the scrape to be failed. 
    ///  If empty, Prometheus uses the global scrape timeout unless it is less than the target's scrape interval value in which the latter is used.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "scrapeTimeout")]
    pub scrape_timeout: Option<String>,
    /// Name or number of the target port of the `Pod` object behind the Service, the port must be specified with container port property. 
    ///  Deprecated: use 'port' instead.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "targetPort")]
    pub target_port: Option<IntOrString>,
    /// TLS configuration to use when scraping the target.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "tlsConfig")]
    pub tls_config: Option<PodMonitorPodMetricsEndpointsTlsConfig>,
    /// TrackTimestampsStaleness whether Prometheus tracks staleness of the metrics that have an explicit timestamps present in scraped data. Has no effect if `honorTimestamps` is false. 
    ///  It requires Prometheus >= v2.48.0.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "trackTimestampsStaleness")]
    pub track_timestamps_staleness: Option<bool>,
}

/// `authorization` configures the Authorization header credentials to use when scraping the target. 
///  Cannot be set at the same time as `basicAuth`, or `oauth2`.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorPodMetricsEndpointsAuthorization {
    /// Selects a key of a Secret in the namespace that contains the credentials for authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<PodMonitorPodMetricsEndpointsAuthorizationCredentials>,
    /// Defines the authentication type. The value is case-insensitive. 
    ///  "Basic" is not a supported value. 
    ///  Default: "Bearer"
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
}

/// Selects a key of a Secret in the namespace that contains the credentials for authentication.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorPodMetricsEndpointsAuthorizationCredentials {
    /// The key of the secret to select from.  Must be a valid secret key.
    pub key: String,
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Specify whether the Secret or its key must be defined
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// `basicAuth` configures the Basic Authentication credentials to use when scraping the target. 
///  Cannot be set at the same time as `authorization`, or `oauth2`.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorPodMetricsEndpointsBasicAuth {
    /// `password` specifies a key of a Secret containing the password for authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<PodMonitorPodMetricsEndpointsBasicAuthPassword>,
    /// `username` specifies a key of a Secret containing the username for authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<PodMonitorPodMetricsEndpointsBasicAuthUsername>,
}

/// `password` specifies a key of a Secret containing the password for authentication.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorPodMetricsEndpointsBasicAuthPassword {
    /// The key of the secret to select from.  Must be a valid secret key.
    pub key: String,
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Specify whether the Secret or its key must be defined
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// `username` specifies a key of a Secret containing the username for authentication.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorPodMetricsEndpointsBasicAuthUsername {
    /// The key of the secret to select from.  Must be a valid secret key.
    pub key: String,
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Specify whether the Secret or its key must be defined
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// `bearerTokenSecret` specifies a key of a Secret containing the bearer token for scraping targets. The secret needs to be in the same namespace as the PodMonitor object and readable by the Prometheus Operator. 
///  Deprecated: use `authorization` instead.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorPodMetricsEndpointsBearerTokenSecret {
    /// The key of the secret to select from.  Must be a valid secret key.
    pub key: String,
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Specify whether the Secret or its key must be defined
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// RelabelConfig allows dynamic rewriting of the label set for targets, alerts, scraped samples and remote write samples. 
///  More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#relabel_config
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorPodMetricsEndpointsMetricRelabelings {
    /// Action to perform based on the regex matching. 
    ///  `Uppercase` and `Lowercase` actions require Prometheus >= v2.36.0. `DropEqual` and `KeepEqual` actions require Prometheus >= v2.41.0. 
    ///  Default: "Replace"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<PodMonitorPodMetricsEndpointsMetricRelabelingsAction>,
    /// Modulus to take of the hash of the source label values. 
    ///  Only applicable when the action is `HashMod`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modulus: Option<i64>,
    /// Regular expression against which the extracted value is matched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    /// Replacement value against which a Replace action is performed if the regular expression matches. 
    ///  Regex capture groups are available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement: Option<String>,
    /// Separator is the string between concatenated SourceLabels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub separator: Option<String>,
    /// The source labels select values from existing labels. Their content is concatenated using the configured Separator and matched against the configured regular expression.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sourceLabels")]
    pub source_labels: Option<Vec<String>>,
    /// Label to which the resulting string is written in a replacement. 
    ///  It is mandatory for `Replace`, `HashMod`, `Lowercase`, `Uppercase`, `KeepEqual` and `DropEqual` actions. 
    ///  Regex capture groups are available.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "targetLabel")]
    pub target_label: Option<String>,
}

/// RelabelConfig allows dynamic rewriting of the label set for targets, alerts, scraped samples and remote write samples. 
///  More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#relabel_config
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum PodMonitorPodMetricsEndpointsMetricRelabelingsAction {
    Replace,
    Keep,
    Drop,
    HashMod,
    LabelMap,
    LabelDrop,
    LabelKeep,
    Lowercase,
    Uppercase,
    KeepEqual,
    DropEqual,
}

/// `oauth2` configures the OAuth2 settings to use when scraping the target. 
///  It requires Prometheus >= 2.27.0. 
///  Cannot be set at the same time as `authorization`, or `basicAuth`.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorPodMetricsEndpointsOauth2 {
    /// `clientId` specifies a key of a Secret or ConfigMap containing the OAuth2 client's ID.
    #[serde(rename = "clientId")]
    pub client_id: PodMonitorPodMetricsEndpointsOauth2ClientId,
    /// `clientSecret` specifies a key of a Secret containing the OAuth2 client's secret.
    #[serde(rename = "clientSecret")]
    pub client_secret: PodMonitorPodMetricsEndpointsOauth2ClientSecret,
    /// `endpointParams` configures the HTTP parameters to append to the token URL.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "endpointParams")]
    pub endpoint_params: Option<BTreeMap<String, String>>,
    /// `scopes` defines the OAuth2 scopes used for the token request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    /// `tokenURL` configures the URL to fetch the token from.
    #[serde(rename = "tokenUrl")]
    pub token_url: String,
}

/// `clientId` specifies a key of a Secret or ConfigMap containing the OAuth2 client's ID.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorPodMetricsEndpointsOauth2ClientId {
    /// ConfigMap containing data to use for the targets.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "configMap")]
    pub config_map: Option<PodMonitorPodMetricsEndpointsOauth2ClientIdConfigMap>,
    /// Secret containing data to use for the targets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<PodMonitorPodMetricsEndpointsOauth2ClientIdSecret>,
}

/// ConfigMap containing data to use for the targets.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorPodMetricsEndpointsOauth2ClientIdConfigMap {
    /// The key to select.
    pub key: String,
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Specify whether the ConfigMap or its key must be defined
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// Secret containing data to use for the targets.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorPodMetricsEndpointsOauth2ClientIdSecret {
    /// The key of the secret to select from.  Must be a valid secret key.
    pub key: String,
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Specify whether the Secret or its key must be defined
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// `clientSecret` specifies a key of a Secret containing the OAuth2 client's secret.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorPodMetricsEndpointsOauth2ClientSecret {
    /// The key of the secret to select from.  Must be a valid secret key.
    pub key: String,
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Specify whether the Secret or its key must be defined
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// RelabelConfig allows dynamic rewriting of the label set for targets, alerts, scraped samples and remote write samples. 
///  More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#relabel_config
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorPodMetricsEndpointsRelabelings {
    /// Action to perform based on the regex matching. 
    ///  `Uppercase` and `Lowercase` actions require Prometheus >= v2.36.0. `DropEqual` and `KeepEqual` actions require Prometheus >= v2.41.0. 
    ///  Default: "Replace"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<PodMonitorPodMetricsEndpointsRelabelingsAction>,
    /// Modulus to take of the hash of the source label values. 
    ///  Only applicable when the action is `HashMod`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modulus: Option<i64>,
    /// Regular expression against which the extracted value is matched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    /// Replacement value against which a Replace action is performed if the regular expression matches. 
    ///  Regex capture groups are available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement: Option<String>,
    /// Separator is the string between concatenated SourceLabels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub separator: Option<String>,
    /// The source labels select values from existing labels. Their content is concatenated using the configured Separator and matched against the configured regular expression.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sourceLabels")]
    pub source_labels: Option<Vec<String>>,
    /// Label to which the resulting string is written in a replacement. 
    ///  It is mandatory for `Replace`, `HashMod`, `Lowercase`, `Uppercase`, `KeepEqual` and `DropEqual` actions. 
    ///  Regex capture groups are available.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "targetLabel")]
    pub target_label: Option<String>,
}

/// RelabelConfig allows dynamic rewriting of the label set for targets, alerts, scraped samples and remote write samples. 
///  More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#relabel_config
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum PodMonitorPodMetricsEndpointsRelabelingsAction {
    Replace,
    Keep,
    Drop,
    HashMod,
    LabelMap,
    LabelDrop,
    LabelKeep,
    Lowercase,
    Uppercase,
    KeepEqual,
    DropEqual,
}

/// PodMetricsEndpoint defines an endpoint serving Prometheus metrics to be scraped by Prometheus.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum PodMonitorPodMetricsEndpointsScheme {
    #[serde(rename = "http")]
    Http,
    #[serde(rename = "https")]
    Https,
}

/// TLS configuration to use when scraping the target.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorPodMetricsEndpointsTlsConfig {
    /// Certificate authority used when verifying server certificates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<PodMonitorPodMetricsEndpointsTlsConfigCa>,
    /// Client certificate to present when doing client-authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<PodMonitorPodMetricsEndpointsTlsConfigCert>,
    /// Disable target certificate validation.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "insecureSkipVerify")]
    pub insecure_skip_verify: Option<bool>,
    /// Secret containing the client key file for the targets.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "keySecret")]
    pub key_secret: Option<PodMonitorPodMetricsEndpointsTlsConfigKeySecret>,
    /// Used to verify the hostname for the targets.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "serverName")]
    pub server_name: Option<String>,
}

/// Certificate authority used when verifying server certificates.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorPodMetricsEndpointsTlsConfigCa {
    /// ConfigMap containing data to use for the targets.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "configMap")]
    pub config_map: Option<PodMonitorPodMetricsEndpointsTlsConfigCaConfigMap>,
    /// Secret containing data to use for the targets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<PodMonitorPodMetricsEndpointsTlsConfigCaSecret>,
}

/// ConfigMap containing data to use for the targets.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorPodMetricsEndpointsTlsConfigCaConfigMap {
    /// The key to select.
    pub key: String,
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Specify whether the ConfigMap or its key must be defined
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// Secret containing data to use for the targets.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorPodMetricsEndpointsTlsConfigCaSecret {
    /// The key of the secret to select from.  Must be a valid secret key.
    pub key: String,
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Specify whether the Secret or its key must be defined
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// Client certificate to present when doing client-authentication.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorPodMetricsEndpointsTlsConfigCert {
    /// ConfigMap containing data to use for the targets.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "configMap")]
    pub config_map: Option<PodMonitorPodMetricsEndpointsTlsConfigCertConfigMap>,
    /// Secret containing data to use for the targets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<PodMonitorPodMetricsEndpointsTlsConfigCertSecret>,
}

/// ConfigMap containing data to use for the targets.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorPodMetricsEndpointsTlsConfigCertConfigMap {
    /// The key to select.
    pub key: String,
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Specify whether the ConfigMap or its key must be defined
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// Secret containing data to use for the targets.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorPodMetricsEndpointsTlsConfigCertSecret {
    /// The key of the secret to select from.  Must be a valid secret key.
    pub key: String,
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Specify whether the Secret or its key must be defined
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// Secret containing the client key file for the targets.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorPodMetricsEndpointsTlsConfigKeySecret {
    /// The key of the secret to select from.  Must be a valid secret key.
    pub key: String,
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Specify whether the Secret or its key must be defined
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// Label selector to select the Kubernetes `Pod` objects.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorSelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchExpressions")]
    pub match_expressions: Option<Vec<PodMonitorSelectorMatchExpressions>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchLabels")]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PodMonitorSelectorMatchExpressions {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

