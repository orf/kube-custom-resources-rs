// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kubernetes-sigs/kueue/kueue.x-k8s.io/v1beta1/admissionchecks.yaml --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// AdmissionCheckSpec defines the desired state of AdmissionCheck
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "kueue.x-k8s.io", version = "v1beta1", kind = "AdmissionCheck", plural = "admissionchecks")]
#[kube(status = "AdmissionCheckStatus")]
#[kube(schema = "disabled")]
pub struct AdmissionCheckSpec {
    /// controllerName is name of the controller which will actually perform
    /// the checks. This is the name with which controller identifies with,
    /// not necessarily a K8S Pod or Deployment name. Cannot be empty.
    #[serde(rename = "controllerName")]
    pub controller_name: String,
    /// Parameters identifies the resource providing additional check parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<AdmissionCheckParameters>,
    /// RetryDelayMinutes specifies how long to keep the workload suspended
    /// after a failed check (after it transitioned to False).
    /// After that the check state goes to "Unknown".
    /// The default is 15 min.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "retryDelayMinutes")]
    pub retry_delay_minutes: Option<i64>,
}

/// Parameters identifies the resource providing additional check parameters.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AdmissionCheckParameters {
    /// ApiGroup is the group for the resource being referenced.
    #[serde(rename = "apiGroup")]
    pub api_group: String,
    /// Kind is the type of the resource being referenced.
    pub kind: String,
    /// Name is the name of the resource being referenced.
    pub name: String,
}

/// AdmissionCheckStatus defines the observed state of AdmissionCheck
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AdmissionCheckStatus {
    /// conditions hold the latest available observations of the AdmissionCheck
    /// current state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
}

