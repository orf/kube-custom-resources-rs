// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/emissary-ingress/emissary/getambassador.io/v3alpha1/modules.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "getambassador.io", version = "v3alpha1", kind = "Module", plural = "modules")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct ModuleSpec {
    /// AmbassadorID declares which Ambassador instances should pay attention to this resource. If no value is provided, the default is: 
    ///  ambassador_id: - "default"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ambassador_id: Option<Vec<String>>,
    pub config: BTreeMap<String, serde_json::Value>,
}

