// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/aws-controllers-k8s/sns-controller/sns.services.k8s.aws/v1alpha1/subscriptions.yaml --derive=Default --derive=PartialEq
// kopium version: 0.17.1

use kube::CustomResource;
use serde::{Serialize, Deserialize};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// SubscriptionSpec defines the desired state of Subscription.
/// 
/// 
/// A wrapper type for the attributes of an Amazon SNS subscription.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "sns.services.k8s.aws", version = "v1alpha1", kind = "Subscription", plural = "subscriptions")]
#[kube(namespaced)]
#[kube(status = "SubscriptionStatus")]
#[kube(schema = "disabled")]
pub struct SubscriptionSpec {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "deliveryPolicy")]
    pub delivery_policy: Option<String>,
    /// The endpoint that you want to receive notifications. Endpoints vary by protocol:
    /// 
    /// 
    ///    * For the http protocol, the (public) endpoint is a URL beginning with
    ///    http://.
    /// 
    /// 
    ///    * For the https protocol, the (public) endpoint is a URL beginning with
    ///    https://.
    /// 
    /// 
    ///    * For the email protocol, the endpoint is an email address.
    /// 
    /// 
    ///    * For the email-json protocol, the endpoint is an email address.
    /// 
    /// 
    ///    * For the sms protocol, the endpoint is a phone number of an SMS-enabled
    ///    device.
    /// 
    /// 
    ///    * For the sqs protocol, the endpoint is the ARN of an Amazon SQS queue.
    /// 
    /// 
    ///    * For the application protocol, the endpoint is the EndpointArn of a mobile
    ///    app and device.
    /// 
    /// 
    ///    * For the lambda protocol, the endpoint is the ARN of an Lambda function.
    /// 
    /// 
    ///    * For the firehose protocol, the endpoint is the ARN of an Amazon Kinesis
    ///    Data Firehose delivery stream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "filterPolicy")]
    pub filter_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "filterPolicyScope")]
    pub filter_policy_scope: Option<String>,
    /// The protocol that you want to use. Supported protocols include:
    /// 
    /// 
    ///    * http – delivery of JSON-encoded message via HTTP POST
    /// 
    /// 
    ///    * https – delivery of JSON-encoded message via HTTPS POST
    /// 
    /// 
    ///    * email – delivery of message via SMTP
    /// 
    /// 
    ///    * email-json – delivery of JSON-encoded message via SMTP
    /// 
    /// 
    ///    * sms – delivery of message via SMS
    /// 
    /// 
    ///    * sqs – delivery of JSON-encoded message to an Amazon SQS queue
    /// 
    /// 
    ///    * application – delivery of JSON-encoded message to an EndpointArn for
    ///    a mobile app and device
    /// 
    /// 
    ///    * lambda – delivery of JSON-encoded message to an Lambda function
    /// 
    /// 
    ///    * firehose – delivery of JSON-encoded message to an Amazon Kinesis Data
    ///    Firehose delivery stream.
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "rawMessageDelivery")]
    pub raw_message_delivery: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "redrivePolicy")]
    pub redrive_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "subscriptionRoleARN")]
    pub subscription_role_arn: Option<String>,
    /// The ARN of the topic you want to subscribe to.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "topicARN")]
    pub topic_arn: Option<String>,
    /// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference
    /// type to provide more user friendly syntax for references using 'from' field
    /// Ex:
    /// APIIDRef:
    /// 
    /// 
    /// 	from:
    /// 	  name: my-api
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "topicRef")]
    pub topic_ref: Option<SubscriptionTopicRef>,
}

/// AWSResourceReferenceWrapper provides a wrapper around *AWSResourceReference
/// type to provide more user friendly syntax for references using 'from' field
/// Ex:
/// APIIDRef:
/// 
/// 
/// 	from:
/// 	  name: my-api
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SubscriptionTopicRef {
    /// AWSResourceReference provides all the values necessary to reference another
    /// k8s resource for finding the identifier(Id/ARN/Name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<SubscriptionTopicRefFrom>,
}

/// AWSResourceReference provides all the values necessary to reference another
/// k8s resource for finding the identifier(Id/ARN/Name)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SubscriptionTopicRefFrom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// SubscriptionStatus defines the observed state of Subscription
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SubscriptionStatus {
    /// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
    /// that is used to contain resource sync state, account ownership,
    /// constructed ARN for the resource
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ackResourceMetadata")]
    pub ack_resource_metadata: Option<SubscriptionStatusAckResourceMetadata>,
    /// All CRS managed by ACK have a common `Status.Conditions` member that
    /// contains a collection of `ackv1alpha1.Condition` objects that describe
    /// the various terminal states of the CR and its backend AWS service API
    /// resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "confirmationWasAuthenticated")]
    pub confirmation_was_authenticated: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "effectiveDeliveryPolicy")]
    pub effective_delivery_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "pendingConfirmation")]
    pub pending_confirmation: Option<String>,
}

/// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
/// that is used to contain resource sync state, account ownership,
/// constructed ARN for the resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SubscriptionStatusAckResourceMetadata {
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

