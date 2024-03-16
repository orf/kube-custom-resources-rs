// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kubedl-io/kubedl/apps.kubedl.io/v1alpha1/crons.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "apps.kubedl.io", version = "v1alpha1", kind = "Cron", plural = "crons")]
#[kube(namespaced)]
#[kube(status = "CronStatus")]
#[kube(schema = "disabled")]
pub struct CronSpec {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "concurrencyPolicy")]
    pub concurrency_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "historyLimit")]
    pub history_limit: Option<i32>,
    pub schedule: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspend: Option<bool>,
    pub template: CronTemplate,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CronTemplate {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiVersion")]
    pub api_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload: Option<BTreeMap<String, serde_json::Value>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CronStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<Vec<CronStatusActive>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<Vec<CronStatusHistory>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastScheduleTime")]
    pub last_schedule_time: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CronStatusActive {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiVersion")]
    pub api_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "fieldPath")]
    pub field_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "resourceVersion")]
    pub resource_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CronStatusHistory {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished: Option<String>,
    pub object: CronStatusHistoryObject,
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CronStatusHistoryObject {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "apiGroup")]
    pub api_group: Option<String>,
    pub kind: String,
    pub name: String,
}

