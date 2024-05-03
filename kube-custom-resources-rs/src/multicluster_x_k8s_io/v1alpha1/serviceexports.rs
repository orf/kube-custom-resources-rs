// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/kubernetes-sigs/mcs-api/multicluster.x-k8s.io/v1alpha1/serviceexports.yaml --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
    pub use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
}
use self::prelude::*;

/// status describes the current state of an exported service. Service configuration comes from the Service that had the same name and namespace as this ServiceExport. Populated by the multi-cluster service implementation's controller.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ServiceExportStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
}

