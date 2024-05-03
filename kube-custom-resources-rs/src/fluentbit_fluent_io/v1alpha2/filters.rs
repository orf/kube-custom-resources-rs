// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/fluent/fluent-operator/fluentbit.fluent.io/v1alpha2/filters.yaml --derive=Default --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use std::collections::BTreeMap;
}
use self::prelude::*;

/// FilterSpec defines the desired state of ClusterFilter
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "fluentbit.fluent.io", version = "v1alpha2", kind = "Filter", plural = "filters")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
#[kube(derive="Default")]
#[kube(derive="PartialEq")]
pub struct FilterSpec {
    /// A set of filter plugins in order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filters: Option<Vec<FilterFilters>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "logLevel")]
    pub log_level: Option<FilterLogLevel>,
    /// A pattern to match against the tags of incoming records. It's case-sensitive and support the star (*) character as a wildcard.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "match")]
    pub r#match: Option<String>,
    /// A regular expression to match against the tags of incoming records. Use this option if you want to use the full regex syntax.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchRegex")]
    pub match_regex: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FilterFilters {
    /// Aws defines a Aws configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws: Option<FilterFiltersAws>,
    /// CustomPlugin defines a Custom plugin configuration.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "customPlugin")]
    pub custom_plugin: Option<FilterFiltersCustomPlugin>,
    /// Grep defines Grep Filter configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grep: Option<FilterFiltersGrep>,
    /// Kubernetes defines Kubernetes Filter configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes: Option<FilterFiltersKubernetes>,
    /// Lua defines Lua Filter configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lua: Option<FilterFiltersLua>,
    /// Modify defines Modify Filter configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modify: Option<FilterFiltersModify>,
    /// Multiline defines a Multiline configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiline: Option<FilterFiltersMultiline>,
    /// Nest defines Nest Filter configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nest: Option<FilterFiltersNest>,
    /// Parser defines Parser Filter configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parser: Option<FilterFiltersParser>,
    /// RecordModifier defines Record Modifier Filter configuration.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "recordModifier")]
    pub record_modifier: Option<FilterFiltersRecordModifier>,
    /// RewriteTag defines a RewriteTag configuration.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "rewriteTag")]
    pub rewrite_tag: Option<FilterFiltersRewriteTag>,
    /// Throttle defines a Throttle configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub throttle: Option<FilterFiltersThrottle>,
}

/// Aws defines a Aws configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FilterFiltersAws {
    /// The account ID for current EC2 instance.Default is false.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "accountID")]
    pub account_id: Option<bool>,
    /// Alias for the plugin
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// The EC2 instance image id.Default is false.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "amiID")]
    pub ami_id: Option<bool>,
    /// The availability zone; for example, "us-east-1a". Default is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub az: Option<bool>,
    /// The EC2 instance ID.Default is true.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ec2InstanceID")]
    pub ec2_instance_id: Option<bool>,
    /// The EC2 instance type.Default is false.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ec2InstanceType")]
    pub ec2_instance_type: Option<bool>,
    /// The hostname for current EC2 instance.Default is false.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "hostName")]
    pub host_name: Option<bool>,
    /// Specify which version of the instance metadata service to use. Valid values are 'v1' or 'v2'.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "imdsVersion")]
    pub imds_version: Option<FilterFiltersAwsImdsVersion>,
    /// The EC2 instance private ip.Default is false.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "privateIP")]
    pub private_ip: Option<bool>,
    /// RetryLimit describes how many times fluent-bit should retry to send data to a specific output. If set to false fluent-bit will try indefinetly. If set to any integer N>0 it will try at most N+1 times. Leading zeros are not allowed (values such as 007, 0150, 01 do not work). If this property is not defined fluent-bit will use the default value: 1.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "retryLimit")]
    pub retry_limit: Option<String>,
    /// The VPC ID for current EC2 instance.Default is false.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vpcID")]
    pub vpc_id: Option<bool>,
}

/// Aws defines a Aws configuration.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum FilterFiltersAwsImdsVersion {
    #[serde(rename = "v1")]
    V1,
    #[serde(rename = "v2")]
    V2,
}

/// CustomPlugin defines a Custom plugin configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FilterFiltersCustomPlugin {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<String>,
}

/// Grep defines Grep Filter configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FilterFiltersGrep {
    /// Alias for the plugin
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// Exclude records which field matches the regular expression. Value Format: FIELD REGEX
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<String>,
    /// Keep records which field matches the regular expression. Value Format: FIELD REGEX
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    /// RetryLimit describes how many times fluent-bit should retry to send data to a specific output. If set to false fluent-bit will try indefinetly. If set to any integer N>0 it will try at most N+1 times. Leading zeros are not allowed (values such as 007, 0150, 01 do not work). If this property is not defined fluent-bit will use the default value: 1.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "retryLimit")]
    pub retry_limit: Option<String>,
}

/// Kubernetes defines Kubernetes Filter configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FilterFiltersKubernetes {
    /// Alias for the plugin
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// Include Kubernetes resource annotations in the extra metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<bool>,
    /// Set the buffer size for HTTP client when reading responses from Kubernetes API server.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "bufferSize")]
    pub buffer_size: Option<String>,
    /// When enabled, metadata will be fetched from K8s when docker_id is changed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "cacheUseDockerId")]
    pub cache_use_docker_id: Option<bool>,
    /// DNS lookup retries N times until the network start working
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dnsRetries")]
    pub dns_retries: Option<i32>,
    /// DNS lookup interval between network status checks
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dnsWaitTime")]
    pub dns_wait_time: Option<i32>,
    /// If set, use dummy-meta data (for test/dev purposes)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dummyMeta")]
    pub dummy_meta: Option<bool>,
    /// Allow Kubernetes Pods to exclude their logs from the log processor (read more about it in Kubernetes Annotations section).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "k8sLoggingExclude")]
    pub k8s_logging_exclude: Option<bool>,
    /// Allow Kubernetes Pods to suggest a pre-defined Parser (read more about it in Kubernetes Annotations section)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "k8sLoggingParser")]
    pub k8s_logging_parser: Option<bool>,
    /// When Keep_Log is disabled, the log field is removed from the incoming message once it has been successfully merged (Merge_Log must be enabled as well).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "keepLog")]
    pub keep_log: Option<bool>,
    /// CA certificate file
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "kubeCAFile")]
    pub kube_ca_file: Option<String>,
    /// Absolute path to scan for certificate files
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "kubeCAPath")]
    pub kube_ca_path: Option<String>,
    /// configurable TTL for K8s cached metadata. By default, it is set to 0 which means TTL for cache entries is disabled and cache entries are evicted at random when capacity is reached. In order to enable this option, you should set the number to a time interval. For example, set this value to 60 or 60s and cache entries which have been created more than 60s will be evicted.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "kubeMetaCacheTTL")]
    pub kube_meta_cache_ttl: Option<String>,
    /// If set, Kubernetes meta-data can be cached/pre-loaded from files in JSON format in this directory, named as namespace-pod.meta
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "kubeMetaPreloadCacheDir")]
    pub kube_meta_preload_cache_dir: Option<String>,
    /// When the source records comes from Tail input plugin, this option allows to specify what's the prefix used in Tail configuration.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "kubeTagPrefix")]
    pub kube_tag_prefix: Option<String>,
    /// Token file
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "kubeTokenFile")]
    pub kube_token_file: Option<String>,
    /// configurable 'time to live' for the K8s token. By default, it is set to 600 seconds. After this time, the token is reloaded from Kube_Token_File or the Kube_Token_Command.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "kubeTokenTTL")]
    pub kube_token_ttl: Option<String>,
    /// API Server end-point
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "kubeURL")]
    pub kube_url: Option<String>,
    /// kubelet host using for HTTP request, this only works when Use_Kubelet set to On.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "kubeletHost")]
    pub kubelet_host: Option<String>,
    /// kubelet port using for HTTP request, this only works when useKubelet is set to On.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "kubeletPort")]
    pub kubelet_port: Option<i32>,
    /// Include Kubernetes resource labels in the extra metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<bool>,
    /// When enabled, it checks if the log field content is a JSON string map, if so, it append the map fields as part of the log structure.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "mergeLog")]
    pub merge_log: Option<bool>,
    /// When Merge_Log is enabled, the filter tries to assume the log field from the incoming message is a JSON string message and make a structured representation of it at the same level of the log field in the map. Now if Merge_Log_Key is set (a string name), all the new structured fields taken from the original log content are inserted under the new key.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "mergeLogKey")]
    pub merge_log_key: Option<String>,
    /// When Merge_Log is enabled, trim (remove possible \n or \r) field values.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "mergeLogTrim")]
    pub merge_log_trim: Option<bool>,
    /// Optional parser name to specify how to parse the data contained in the log key. Recommended use is for developers or testing only.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "mergeParser")]
    pub merge_parser: Option<String>,
    /// Set an alternative Parser to process record Tag and extract pod_name, namespace_name, container_name and docker_id. The parser must be registered in a parsers file (refer to parser filter-kube-test as an example).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "regexParser")]
    pub regex_parser: Option<String>,
    /// RetryLimit describes how many times fluent-bit should retry to send data to a specific output. If set to false fluent-bit will try indefinetly. If set to any integer N>0 it will try at most N+1 times. Leading zeros are not allowed (values such as 007, 0150, 01 do not work). If this property is not defined fluent-bit will use the default value: 1.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "retryLimit")]
    pub retry_limit: Option<String>,
    /// Debug level between 0 (nothing) and 4 (every detail).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "tlsDebug")]
    pub tls_debug: Option<i32>,
    /// When enabled, turns on certificate validation when connecting to the Kubernetes API server.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "tlsVerify")]
    pub tls_verify: Option<bool>,
    /// When enabled, the filter reads logs coming in Journald format.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "useJournal")]
    pub use_journal: Option<bool>,
    /// This is an optional feature flag to get metadata information from kubelet instead of calling Kube Server API to enhance the log. This could mitigate the Kube API heavy traffic issue for large cluster.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "useKubelet")]
    pub use_kubelet: Option<bool>,
}

/// Lua defines Lua Filter configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FilterFiltersLua {
    /// Alias for the plugin
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// Lua function name that will be triggered to do filtering. It's assumed that the function is declared inside the Script defined above.
    pub call: String,
    /// Inline LUA code instead of loading from a path via script.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// If enabled, Lua script will be executed in protected mode. It prevents to crash when invalid Lua script is executed. Default is true.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "protectedMode")]
    pub protected_mode: Option<bool>,
    /// RetryLimit describes how many times fluent-bit should retry to send data to a specific output. If set to false fluent-bit will try indefinetly. If set to any integer N>0 it will try at most N+1 times. Leading zeros are not allowed (values such as 007, 0150, 01 do not work). If this property is not defined fluent-bit will use the default value: 1.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "retryLimit")]
    pub retry_limit: Option<String>,
    /// Path to the Lua script that will be used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<FilterFiltersLuaScript>,
    /// By default when the Lua script is invoked, the record timestamp is passed as a Floating number which might lead to loss precision when the data is converted back. If you desire timestamp precision enabling this option will pass the timestamp as a Lua table with keys sec for seconds since epoch and nsec for nanoseconds.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "timeAsTable")]
    pub time_as_table: Option<bool>,
    /// If these keys are matched, the fields are converted to integer. If more than one key, delimit by space. Note that starting from Fluent Bit v1.6 integer data types are preserved and not converted to double as in previous versions.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "typeIntKey")]
    pub type_int_key: Option<Vec<String>>,
}

/// Path to the Lua script that will be used.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FilterFiltersLuaScript {
    /// The key to select.
    pub key: String,
    /// Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Specify whether the ConfigMap or its key must be defined
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// Modify defines Modify Filter configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FilterFiltersModify {
    /// Alias for the plugin
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// All conditions have to be true for the rules to be applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<FilterFiltersModifyConditions>>,
    /// RetryLimit describes how many times fluent-bit should retry to send data to a specific output. If set to false fluent-bit will try indefinetly. If set to any integer N>0 it will try at most N+1 times. Leading zeros are not allowed (values such as 007, 0150, 01 do not work). If this property is not defined fluent-bit will use the default value: 1.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "retryLimit")]
    pub retry_limit: Option<String>,
    /// Rules are applied in the order they appear, with each rule operating on the result of the previous rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<FilterFiltersModifyRules>>,
}

/// The plugin supports the following conditions
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FilterFiltersModifyConditions {
    /// Is true if a key matches regex KEY
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "aKeyMatches")]
    pub a_key_matches: Option<String>,
    /// Is true if KEY does not exist
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "keyDoesNotExist")]
    pub key_does_not_exist: Option<BTreeMap<String, String>>,
    /// Is true if KEY exists
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "keyExists")]
    pub key_exists: Option<String>,
    /// Is true if KEY exists and its value is not VALUE
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "keyValueDoesNotEqual")]
    pub key_value_does_not_equal: Option<BTreeMap<String, String>>,
    /// Is true if key KEY exists and its value does not match VALUE
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "keyValueDoesNotMatch")]
    pub key_value_does_not_match: Option<BTreeMap<String, String>>,
    /// Is true if KEY exists and its value is VALUE
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "keyValueEquals")]
    pub key_value_equals: Option<BTreeMap<String, String>>,
    /// Is true if key KEY exists and its value matches VALUE
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "keyValueMatches")]
    pub key_value_matches: Option<BTreeMap<String, String>>,
    /// Is true if all keys matching KEY have values that do not match VALUE
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchingKeysDoNotHaveMatchingValues")]
    pub matching_keys_do_not_have_matching_values: Option<BTreeMap<String, String>>,
    /// Is true if all keys matching KEY have values that match VALUE
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "matchingKeysHaveMatchingValues")]
    pub matching_keys_have_matching_values: Option<BTreeMap<String, String>>,
    /// Is true if no key matches regex KEY
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "noKeyMatches")]
    pub no_key_matches: Option<String>,
}

/// The plugin supports the following rules
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FilterFiltersModifyRules {
    /// Add a key/value pair with key KEY and value VALUE if KEY does not exist
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add: Option<BTreeMap<String, String>>,
    /// Copy a key/value pair with key KEY to COPIED_KEY if KEY exists AND COPIED_KEY does not exist
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy: Option<BTreeMap<String, String>>,
    /// Copy a key/value pair with key KEY to COPIED_KEY if KEY exists. If COPIED_KEY already exists, this field is overwritten
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "hardCopy")]
    pub hard_copy: Option<BTreeMap<String, String>>,
    /// Rename a key/value pair with key KEY to RENAMED_KEY if KEY exists. If RENAMED_KEY already exists, this field is overwritten
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "hardRename")]
    pub hard_rename: Option<BTreeMap<String, String>>,
    /// Remove a key/value pair with key KEY if it exists
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove: Option<String>,
    /// Remove all key/value pairs with key matching regexp KEY
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "removeRegex")]
    pub remove_regex: Option<String>,
    /// Remove all key/value pairs with key matching wildcard KEY
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "removeWildcard")]
    pub remove_wildcard: Option<String>,
    /// Rename a key/value pair with key KEY to RENAMED_KEY if KEY exists AND RENAMED_KEY does not exist
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rename: Option<BTreeMap<String, String>>,
    /// Add a key/value pair with key KEY and value VALUE. If KEY already exists, this field is overwritten
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set: Option<BTreeMap<String, String>>,
}

/// Multiline defines a Multiline configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FilterFiltersMultiline {
    /// Alias for the plugin
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buffer: Option<bool>,
    /// Set a limit on the amount of memory in MB the emitter can consume if the outputs provide backpressure. The default for this limit is 10M. The pipeline will pause once the buffer exceeds the value of this setting. For example, if the value is set to 10MB then the pipeline will pause if the buffer exceeds 10M. The pipeline will remain paused until the output drains the buffer below the 10M limit.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "emitterMemBufLimit")]
    pub emitter_mem_buf_limit: Option<i64>,
    /// Name for the emitter input instance which re-emits the completed records at the beginning of the pipeline.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "emitterName")]
    pub emitter_name: Option<String>,
    /// The storage type for the emitter input instance. This option supports the values memory (default) and filesystem.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "emitterType")]
    pub emitter_type: Option<FilterFiltersMultilineEmitterType>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "flushMs")]
    pub flush_ms: Option<i64>,
    /// Key name that holds the content to process. Note that a Multiline Parser definition can already specify the key_content to use, but this option allows to overwrite that value for the purpose of the filter.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "keyContent")]
    pub key_content: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<FilterFiltersMultilineMode>,
    /// Specify one or multiple Multiline Parsing definitions to apply to the content. You can specify multiple multiline parsers to detect different formats by separating them with a comma.
    pub parser: String,
    /// RetryLimit describes how many times fluent-bit should retry to send data to a specific output. If set to false fluent-bit will try indefinetly. If set to any integer N>0 it will try at most N+1 times. Leading zeros are not allowed (values such as 007, 0150, 01 do not work). If this property is not defined fluent-bit will use the default value: 1.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "retryLimit")]
    pub retry_limit: Option<String>,
}

/// Multiline defines a Multiline configuration.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum FilterFiltersMultilineEmitterType {
    #[serde(rename = "memory")]
    Memory,
    #[serde(rename = "filesystem")]
    Filesystem,
}

/// Multiline defines a Multiline configuration.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum FilterFiltersMultilineMode {
    #[serde(rename = "parser")]
    Parser,
    #[serde(rename = "partial_message")]
    PartialMessage,
}

/// Nest defines Nest Filter configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FilterFiltersNest {
    /// Prefix affected keys with this string
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "addPrefix")]
    pub add_prefix: Option<String>,
    /// Alias for the plugin
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// Nest records matching the Wildcard under this key
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nestUnder")]
    pub nest_under: Option<String>,
    /// Lift records nested under the Nested_under key
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nestedUnder")]
    pub nested_under: Option<String>,
    /// Select the operation nest or lift
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<FilterFiltersNestOperation>,
    /// Remove prefix from affected keys if it matches this string
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "removePrefix")]
    pub remove_prefix: Option<String>,
    /// RetryLimit describes how many times fluent-bit should retry to send data to a specific output. If set to false fluent-bit will try indefinetly. If set to any integer N>0 it will try at most N+1 times. Leading zeros are not allowed (values such as 007, 0150, 01 do not work). If this property is not defined fluent-bit will use the default value: 1.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "retryLimit")]
    pub retry_limit: Option<String>,
    /// Nest records which field matches the wildcard
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wildcard: Option<Vec<String>>,
}

/// Nest defines Nest Filter configuration.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum FilterFiltersNestOperation {
    #[serde(rename = "nest")]
    Nest,
    #[serde(rename = "lift")]
    Lift,
}

/// Parser defines Parser Filter configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FilterFiltersParser {
    /// Alias for the plugin
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// Specify field name in record to parse.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "keyName")]
    pub key_name: Option<String>,
    /// Specify the parser name to interpret the field. Multiple Parser entries are allowed (split by comma).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parser: Option<String>,
    /// Keep original Key_Name field in the parsed result. If false, the field will be removed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "preserveKey")]
    pub preserve_key: Option<bool>,
    /// Keep all other original fields in the parsed result. If false, all other original fields will be removed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "reserveData")]
    pub reserve_data: Option<bool>,
    /// RetryLimit describes how many times fluent-bit should retry to send data to a specific output. If set to false fluent-bit will try indefinetly. If set to any integer N>0 it will try at most N+1 times. Leading zeros are not allowed (values such as 007, 0150, 01 do not work). If this property is not defined fluent-bit will use the default value: 1.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "retryLimit")]
    pub retry_limit: Option<String>,
    /// If the key is a escaped string (e.g: stringify JSON), unescape the string before to apply the parser.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "unescapeKey")]
    pub unescape_key: Option<bool>,
}

/// RecordModifier defines Record Modifier Filter configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FilterFiltersRecordModifier {
    /// Alias for the plugin
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// If the key is not matched, that field is removed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "allowlistKeys")]
    pub allowlist_keys: Option<Vec<String>>,
    /// Append fields. This parameter needs key and value pair.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub records: Option<Vec<String>>,
    /// If the key is matched, that field is removed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "removeKeys")]
    pub remove_keys: Option<Vec<String>>,
    /// RetryLimit describes how many times fluent-bit should retry to send data to a specific output. If set to false fluent-bit will try indefinetly. If set to any integer N>0 it will try at most N+1 times. Leading zeros are not allowed (values such as 007, 0150, 01 do not work). If this property is not defined fluent-bit will use the default value: 1.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "retryLimit")]
    pub retry_limit: Option<String>,
    /// If set, the plugin appends uuid to each record. The value assigned becomes the key in the map.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "uuidKeys")]
    pub uuid_keys: Option<Vec<String>>,
    /// An alias of allowlistKeys for backwards compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "whitelistKeys")]
    pub whitelist_keys: Option<Vec<String>>,
}

/// RewriteTag defines a RewriteTag configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FilterFiltersRewriteTag {
    /// Alias for the plugin
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "emitterMemBufLimit")]
    pub emitter_mem_buf_limit: Option<String>,
    /// When the filter emits a record under the new Tag, there is an internal emitter plugin that takes care of the job. Since this emitter expose metrics as any other component of the pipeline, you can use this property to configure an optional name for it.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "emitterName")]
    pub emitter_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "emitterStorageType")]
    pub emitter_storage_type: Option<String>,
    /// RetryLimit describes how many times fluent-bit should retry to send data to a specific output. If set to false fluent-bit will try indefinetly. If set to any integer N>0 it will try at most N+1 times. Leading zeros are not allowed (values such as 007, 0150, 01 do not work). If this property is not defined fluent-bit will use the default value: 1.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "retryLimit")]
    pub retry_limit: Option<String>,
    /// Defines the matching criteria and the format of the Tag for the matching record. The Rule format have four components: KEY REGEX NEW_TAG KEEP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<String>>,
}

/// Throttle defines a Throttle configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FilterFiltersThrottle {
    /// Alias for the plugin
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// Interval is the time interval expressed in "sleep" format. e.g. 3s, 1.5m, 0.5h, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,
    /// PrintStatus represents whether to print status messages with current rate and the limits to information logs.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "printStatus")]
    pub print_status: Option<bool>,
    /// Rate is the amount of messages for the time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<i64>,
    /// RetryLimit describes how many times fluent-bit should retry to send data to a specific output. If set to false fluent-bit will try indefinetly. If set to any integer N>0 it will try at most N+1 times. Leading zeros are not allowed (values such as 007, 0150, 01 do not work). If this property is not defined fluent-bit will use the default value: 1.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "retryLimit")]
    pub retry_limit: Option<String>,
    /// Window is the amount of intervals to calculate average over.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<i64>,
}

/// FilterSpec defines the desired state of ClusterFilter
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum FilterLogLevel {
    #[serde(rename = "off")]
    Off,
    #[serde(rename = "error")]
    Error,
    #[serde(rename = "warning")]
    Warning,
    #[serde(rename = "info")]
    Info,
    #[serde(rename = "debug")]
    Debug,
    #[serde(rename = "trace")]
    Trace,
}

