// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/Lerentis/bitwarden-crd-operator/lerentis.uploadfilter24.eu/v1beta4/bitwarden-templates.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.2

use kube::CustomResource;
use serde::{Serialize, Deserialize};

#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "lerentis.uploadfilter24.eu", version = "v1beta4", kind = "BitwardenTemplate", plural = "bitwarden-templates")]
#[kube(namespaced)]
#[kube(schema = "disabled")]
pub struct BitwardenTemplateSpec {
    pub filename: String,
    pub name: String,
    pub namespace: String,
    pub template: String,
}

