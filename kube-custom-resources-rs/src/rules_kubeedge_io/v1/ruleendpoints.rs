// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kubeedge/kubeedge/rules.kubeedge.io/v1/ruleendpoints.yaml --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[kube(group = "rules.kubeedge.io", version = "v1", kind = "RuleEndpoint", plural = "ruleendpoints")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct RuleEndpointSpec {
    /// properties is not required except for servicebus rule-endpoint type. It is a map
    /// value representing rule-endpoint properties. When ruleEndpointType is servicebus,
    /// its value is {"service_port":"8080"}.
    /// 
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<BTreeMap<String, String>>,
    /// ruleEndpointType is a string value representing rule-endpoint type. its value is
    /// one of rest/eventbus/servicebus.
    /// 
    #[serde(rename = "ruleEndpointType")]
    pub rule_endpoint_type: RuleEndpointRuleEndpointType,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum RuleEndpointRuleEndpointType {
    #[serde(rename = "rest")]
    Rest,
    #[serde(rename = "eventbus")]
    Eventbus,
    #[serde(rename = "servicebus")]
    Servicebus,
}

