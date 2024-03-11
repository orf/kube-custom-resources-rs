// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/cloudtrail-controller/cloudtrail.services.k8s.aws/v1alpha1/eventdatastores.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// EventDataStoreSpec defines the desired state of EventDataStore.
/// 
/// 
/// A storage lake of event data against which you can run complex SQL-based
/// queries. An event data store can include events that you have logged on your
/// account from the last 90 to 2555 days (about three months to up to seven
/// years). To select events for an event data store, use advanced event selectors
/// (https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html#creating-data-event-selectors-advanced).
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "cloudtrail.services.k8s.aws", version = "v1alpha1", kind = "EventDataStore", plural = "eventdatastores")]
#[kube(namespaced)]
#[kube(status = "EventDataStoreStatus")]
#[kube(schema = "disabled")]
pub struct EventDataStoreSpec {
    /// The advanced event selectors to use to select the events for the data store.
    /// For more information about how to use advanced event selectors, see Log events
    /// by using advanced event selectors (https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html#creating-data-event-selectors-advanced)
    /// in the CloudTrail User Guide.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "advancedEventSelectors")]
    pub advanced_event_selectors: Option<Vec<EventDataStoreAdvancedEventSelectors>>,
    /// Specifies whether the event data store includes events from all regions,
    /// or only from the region in which the event data store is created.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "multiRegionEnabled")]
    pub multi_region_enabled: Option<bool>,
    /// The name of the event data store.
    pub name: String,
    /// Specifies whether an event data store collects events logged for an organization
    /// in Organizations.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "organizationEnabled")]
    pub organization_enabled: Option<bool>,
    /// The retention period of the event data store, in days. You can set a retention
    /// period of up to 2555 days, the equivalent of seven years.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "retentionPeriod")]
    pub retention_period: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<EventDataStoreTags>>,
    /// Specifies whether termination protection is enabled for the event data store.
    /// If termination protection is enabled, you cannot delete the event data store
    /// until termination protection is disabled.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "terminationProtectionEnabled")]
    pub termination_protection_enabled: Option<bool>,
}

/// Advanced event selectors let you create fine-grained selectors for the following
/// CloudTrail event record ﬁelds. They help you control costs by logging only
/// those events that are important to you. For more information about advanced
/// event selectors, see Logging data events for trails (https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)
/// in the CloudTrail User Guide.
/// 
/// 
///    * readOnly
/// 
/// 
///    * eventSource
/// 
/// 
///    * eventName
/// 
/// 
///    * eventCategory
/// 
/// 
///    * resources.type
/// 
/// 
///    * resources.ARN
/// 
/// 
/// You cannot apply both event selectors and advanced event selectors to a trail.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct EventDataStoreAdvancedEventSelectors {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "fieldSelectors")]
    pub field_selectors: Option<Vec<EventDataStoreAdvancedEventSelectorsFieldSelectors>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// A single selector statement in an advanced event selector.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct EventDataStoreAdvancedEventSelectorsFieldSelectors {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "endsWith")]
    pub ends_with: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equals: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "notEndsWith")]
    pub not_ends_with: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "notEquals")]
    pub not_equals: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "notStartsWith")]
    pub not_starts_with: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "startsWith")]
    pub starts_with: Option<Vec<String>>,
}

/// A custom key-value pair associated with a resource such as a CloudTrail trail.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct EventDataStoreTags {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// EventDataStoreStatus defines the observed state of EventDataStore
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct EventDataStoreStatus {
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
    /// that is used to contain resource sync state, account ownership,
    /// constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<EventDataStoreStatusAckResourceMetadata>,
    /// All CRS managed by ACK have a common `Status.Conditions` member that
    /// contains a collection of `ackv1alpha1.Condition` objects that describe
    /// the various terminal states of the CR and its backend AWS service API
    /// resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// The timestamp that shows when the event data store was created.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "createdTimestamp")]
    pub created_timestamp: Option<String>,
    /// The status of event data store creation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// The timestamp that shows when an event data store was updated, if applicable.
    /// UpdatedTimestamp is always either the same or newer than the time shown in
    /// CreatedTimestamp.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "updatedTimestamp")]
    pub updated_timestamp: Option<String>,
}

/// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
/// that is used to contain resource sync state, account ownership,
/// constructed ARN for the resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct EventDataStoreStatusAckResourceMetadata {
    /// ARN is the Amazon Resource Name for the resource. This is a
    /// globally-unique identifier and is set only by the ACK service controller
    /// once the controller has orchestrated the creation of the resource OR
    /// when it has verified that an "adopted" resource (a resource where the
    /// ARN annotation was set by the Kubernetes user on the CR) exists and
    /// matches the supplied CR's Spec field values.
    /// TODO(vijat@): Find a better strategy for resources that do not have ARN in CreateOutputResponse
    /// https://github.com/aws/aws-controllers-k8s/issues/270
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arn: Option<String>,
    /// OwnerAccountID is the AWS Account ID of the account that owns the
    /// backend AWS service API resource.
    #[serde(rename = "ownerAccountID")]
    pub owner_account_id: String,
    /// Region is the AWS region in which the resource exists or will exist.
    pub region: String,
}

