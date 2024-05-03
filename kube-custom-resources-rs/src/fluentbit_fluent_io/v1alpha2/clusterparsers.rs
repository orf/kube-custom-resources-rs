// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/fluent/fluent-operator/fluentbit.fluent.io/v1alpha2/clusterparsers.yaml --derive=Default --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
}
use self::prelude::*;

/// ParserSpec defines the desired state of ClusterParser
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "fluentbit.fluent.io", version = "v1alpha2", kind = "ClusterParser", plural = "clusterparsers")]
#[kube(schema = "disabled")]
#[kube(derive="Default")]
#[kube(derive="PartialEq")]
pub struct ClusterParserSpec {
    /// Decoders are a built-in feature available through the Parsers file, each Parser definition can optionally set one or multiple decoders. There are two type of decoders type: Decode_Field and Decode_Field_As.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoders: Option<Vec<ClusterParserDecoders>>,
    /// JSON defines json parser configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<ClusterParserJson>,
    /// Logfmt defines logfmt parser configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logfmt: Option<ClusterParserLogfmt>,
    /// LTSV defines ltsv parser configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ltsv: Option<ClusterParserLtsv>,
    /// Regex defines regex parser configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<ClusterParserRegex>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterParserDecoders {
    /// If the content can be decoded in a structured message, append that structure message (keys and values) to the original log message.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "decodeField")]
    pub decode_field: Option<String>,
    /// Any content decoded (unstructured or structured) will be replaced in the same key/value, no extra keys are added.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "decodeFieldAs")]
    pub decode_field_as: Option<String>,
}

/// JSON defines json parser configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterParserJson {
    /// Time_Format, eg. %Y-%m-%dT%H:%M:%S %z
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "timeFormat")]
    pub time_format: Option<String>,
    /// Time_Keep
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "timeKeep")]
    pub time_keep: Option<bool>,
    /// Time_Key
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "timeKey")]
    pub time_key: Option<String>,
}

/// Logfmt defines logfmt parser configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterParserLogfmt {
}

/// LTSV defines ltsv parser configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterParserLtsv {
    /// Time_Format, eg. %Y-%m-%dT%H:%M:%S %z
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "timeFormat")]
    pub time_format: Option<String>,
    /// Time_Keep
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "timeKeep")]
    pub time_keep: Option<bool>,
    /// Time_Key
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "timeKey")]
    pub time_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<String>,
}

/// Regex defines regex parser configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ClusterParserRegex {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    /// Time_Format, eg. %Y-%m-%dT%H:%M:%S %z
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "timeFormat")]
    pub time_format: Option<String>,
    /// Time_Keep
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "timeKeep")]
    pub time_keep: Option<bool>,
    /// Time_Key
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "timeKey")]
    pub time_key: Option<String>,
    /// Time_Offset, eg. +0200
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "timeOffset")]
    pub time_offset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<String>,
}

