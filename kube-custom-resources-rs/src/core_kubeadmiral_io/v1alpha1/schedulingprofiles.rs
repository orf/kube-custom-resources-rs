// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kubewharf/kubeadmiral/core.kubeadmiral.io/v1alpha1/schedulingprofiles.yaml --derive=Default --derive=PartialEq
// kopium version: 0.18.0

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "core.kubeadmiral.io", version = "v1alpha1", kind = "SchedulingProfile", plural = "schedulingprofiles")]
#[kube(schema = "disabled")]
pub struct SchedulingProfileSpec {
    /// PluginConfig is an optional set of custom plugin arguments for each plugin. Omitting config args for a plugin is equivalent to using the default config for that plugin.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "pluginConfig")]
    pub plugin_config: Option<Vec<SchedulingProfilePluginConfig>>,
    /// Plugins specify the set of plugins that should be enabled or disabled. Enabled plugins are the ones that should be enabled in addition to the default plugins. Disabled plugins are any of the default plugins that should be disabled. When no enabled or disabled plugin is specified for an extension point, default plugins for that extension point will be used if there is any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugins: Option<SchedulingProfilePlugins>,
}

/// PluginConfig specifies arguments that should be passed to a plugin at the time of initialization. A plugin that is invoked at multiple extension points is initialized once. Args can have arbitrary structure. It is up to the plugin to process these Args.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SchedulingProfilePluginConfig {
    /// Args defines the arguments passed to the plugins at the time of initialization. Args can have arbitrary structure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<BTreeMap<String, serde_json::Value>>,
    /// Name defines the name of plugin being configured.
    pub name: String,
}

/// Plugins specify the set of plugins that should be enabled or disabled. Enabled plugins are the ones that should be enabled in addition to the default plugins. Disabled plugins are any of the default plugins that should be disabled. When no enabled or disabled plugin is specified for an extension point, default plugins for that extension point will be used if there is any.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SchedulingProfilePlugins {
    /// Filter is the list of plugins that should be invoked during the filter phase.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<SchedulingProfilePluginsFilter>,
    /// Score is the list of plugins that should be invoked during the score phase.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<SchedulingProfilePluginsScore>,
    /// Select is the list of plugins that should be invoked during the select phase.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub select: Option<SchedulingProfilePluginsSelect>,
}

/// Filter is the list of plugins that should be invoked during the filter phase.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SchedulingProfilePluginsFilter {
    /// Disabled specifies default plugins that should be disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<Vec<SchedulingProfilePluginsFilterDisabled>>,
    /// Enabled specifies plugins that should be enabled in addition to the default plugins. Enabled plugins are called in the order specified here, after default plugins. If they need to be invoked before default plugins, default plugins must be disabled and re-enabled here in desired order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<Vec<SchedulingProfilePluginsFilterEnabled>>,
}

/// Plugin specifies a plugin type, name and its weight when applicable. Weight is used only for Score plugins.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SchedulingProfilePluginsFilterDisabled {
    /// Name defines the name of the plugin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Type defines the type of the plugin. Type should be omitted when referencing in-tree plugins.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<SchedulingProfilePluginsFilterDisabledType>,
    /// Weight defines the weight of the plugin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait: Option<i64>,
}

/// Plugin specifies a plugin type, name and its weight when applicable. Weight is used only for Score plugins.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum SchedulingProfilePluginsFilterDisabledType {
    Webhook,
}

/// Plugin specifies a plugin type, name and its weight when applicable. Weight is used only for Score plugins.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SchedulingProfilePluginsFilterEnabled {
    /// Name defines the name of the plugin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Type defines the type of the plugin. Type should be omitted when referencing in-tree plugins.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<SchedulingProfilePluginsFilterEnabledType>,
    /// Weight defines the weight of the plugin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait: Option<i64>,
}

/// Plugin specifies a plugin type, name and its weight when applicable. Weight is used only for Score plugins.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum SchedulingProfilePluginsFilterEnabledType {
    Webhook,
}

/// Score is the list of plugins that should be invoked during the score phase.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SchedulingProfilePluginsScore {
    /// Disabled specifies default plugins that should be disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<Vec<SchedulingProfilePluginsScoreDisabled>>,
    /// Enabled specifies plugins that should be enabled in addition to the default plugins. Enabled plugins are called in the order specified here, after default plugins. If they need to be invoked before default plugins, default plugins must be disabled and re-enabled here in desired order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<Vec<SchedulingProfilePluginsScoreEnabled>>,
}

/// Plugin specifies a plugin type, name and its weight when applicable. Weight is used only for Score plugins.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SchedulingProfilePluginsScoreDisabled {
    /// Name defines the name of the plugin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Type defines the type of the plugin. Type should be omitted when referencing in-tree plugins.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<SchedulingProfilePluginsScoreDisabledType>,
    /// Weight defines the weight of the plugin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait: Option<i64>,
}

/// Plugin specifies a plugin type, name and its weight when applicable. Weight is used only for Score plugins.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum SchedulingProfilePluginsScoreDisabledType {
    Webhook,
}

/// Plugin specifies a plugin type, name and its weight when applicable. Weight is used only for Score plugins.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SchedulingProfilePluginsScoreEnabled {
    /// Name defines the name of the plugin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Type defines the type of the plugin. Type should be omitted when referencing in-tree plugins.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<SchedulingProfilePluginsScoreEnabledType>,
    /// Weight defines the weight of the plugin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait: Option<i64>,
}

/// Plugin specifies a plugin type, name and its weight when applicable. Weight is used only for Score plugins.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum SchedulingProfilePluginsScoreEnabledType {
    Webhook,
}

/// Select is the list of plugins that should be invoked during the select phase.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SchedulingProfilePluginsSelect {
    /// Disabled specifies default plugins that should be disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<Vec<SchedulingProfilePluginsSelectDisabled>>,
    /// Enabled specifies plugins that should be enabled in addition to the default plugins. Enabled plugins are called in the order specified here, after default plugins. If they need to be invoked before default plugins, default plugins must be disabled and re-enabled here in desired order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<Vec<SchedulingProfilePluginsSelectEnabled>>,
}

/// Plugin specifies a plugin type, name and its weight when applicable. Weight is used only for Score plugins.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SchedulingProfilePluginsSelectDisabled {
    /// Name defines the name of the plugin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Type defines the type of the plugin. Type should be omitted when referencing in-tree plugins.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<SchedulingProfilePluginsSelectDisabledType>,
    /// Weight defines the weight of the plugin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait: Option<i64>,
}

/// Plugin specifies a plugin type, name and its weight when applicable. Weight is used only for Score plugins.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum SchedulingProfilePluginsSelectDisabledType {
    Webhook,
}

/// Plugin specifies a plugin type, name and its weight when applicable. Weight is used only for Score plugins.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SchedulingProfilePluginsSelectEnabled {
    /// Name defines the name of the plugin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Type defines the type of the plugin. Type should be omitted when referencing in-tree plugins.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<SchedulingProfilePluginsSelectEnabledType>,
    /// Weight defines the weight of the plugin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait: Option<i64>,
}

/// Plugin specifies a plugin type, name and its weight when applicable. Weight is used only for Score plugins.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum SchedulingProfilePluginsSelectEnabledType {
    Webhook,
}

