// WARNING: generated by kopium - manual changes will be overwritten
// kopium command: kopium --docs --filename=./crd-catalog/actions/actions-runner-controller/actions.summerwind.dev/v1alpha1/horizontalrunnerautoscalers.yaml --derive=Default --derive=PartialEq
// kopium version: 0.19.0

#[allow(unused_imports)]
mod prelude {
    pub use kube::CustomResource;
    pub use serde::{Serialize, Deserialize};
}
use self::prelude::*;

/// HorizontalRunnerAutoscalerSpec defines the desired state of HorizontalRunnerAutoscaler
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(group = "actions.summerwind.dev", version = "v1alpha1", kind = "HorizontalRunnerAutoscaler", plural = "horizontalrunnerautoscalers")]
#[kube(namespaced)]
#[kube(status = "HorizontalRunnerAutoscalerStatus")]
#[kube(schema = "disabled")]
#[kube(derive="Default")]
#[kube(derive="PartialEq")]
pub struct HorizontalRunnerAutoscalerSpec {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "capacityReservations")]
    pub capacity_reservations: Option<Vec<HorizontalRunnerAutoscalerCapacityReservations>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "githubAPICredentialsFrom")]
    pub github_api_credentials_from: Option<HorizontalRunnerAutoscalerGithubApiCredentialsFrom>,
    /// MaxReplicas is the maximum number of replicas the deployment is allowed to scale
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxReplicas")]
    pub max_replicas: Option<i64>,
    /// Metrics is the collection of various metric targets to calculate desired number of runners
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<Vec<HorizontalRunnerAutoscalerMetrics>>,
    /// MinReplicas is the minimum number of replicas the deployment is allowed to scale
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "minReplicas")]
    pub min_replicas: Option<i64>,
    /// ScaleDownDelaySecondsAfterScaleUp is the approximate delay for a scale down followed by a scale up
    /// Used to prevent flapping (down->up->down->... loop)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "scaleDownDelaySecondsAfterScaleOut")]
    pub scale_down_delay_seconds_after_scale_out: Option<i64>,
    /// ScaleTargetRef is the reference to scaled resource like RunnerDeployment
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "scaleTargetRef")]
    pub scale_target_ref: Option<HorizontalRunnerAutoscalerScaleTargetRef>,
    /// ScaleUpTriggers is an experimental feature to increase the desired replicas by 1
    /// on each webhook requested received by the webhookBasedAutoscaler.
    /// 
    /// 
    /// This feature requires you to also enable and deploy the webhookBasedAutoscaler onto your cluster.
    /// 
    /// 
    /// Note that the added runners remain until the next sync period at least,
    /// and they may or may not be used by GitHub Actions depending on the timing.
    /// They are intended to be used to gain "resource slack" immediately after you
    /// receive a webhook from GitHub, so that you can loosely expect MinReplicas runners to be always available.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "scaleUpTriggers")]
    pub scale_up_triggers: Option<Vec<HorizontalRunnerAutoscalerScaleUpTriggers>>,
    /// ScheduledOverrides is the list of ScheduledOverride.
    /// It can be used to override a few fields of HorizontalRunnerAutoscalerSpec on schedule.
    /// The earlier a scheduled override is, the higher it is prioritized.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "scheduledOverrides")]
    pub scheduled_overrides: Option<Vec<HorizontalRunnerAutoscalerScheduledOverrides>>,
}

/// CapacityReservation specifies the number of replicas temporarily added
/// to the scale target until ExpirationTime.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct HorizontalRunnerAutoscalerCapacityReservations {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "effectiveTime")]
    pub effective_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "expirationTime")]
    pub expiration_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<i64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct HorizontalRunnerAutoscalerGithubApiCredentialsFrom {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "secretRef")]
    pub secret_ref: Option<HorizontalRunnerAutoscalerGithubApiCredentialsFromSecretRef>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct HorizontalRunnerAutoscalerGithubApiCredentialsFromSecretRef {
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct HorizontalRunnerAutoscalerMetrics {
    /// RepositoryNames is the list of repository names to be used for calculating the metric.
    /// For example, a repository name is the REPO part of `github.com/USER/REPO`.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "repositoryNames")]
    pub repository_names: Option<Vec<String>>,
    /// ScaleDownAdjustment is the number of runners removed on scale-down.
    /// You can only specify either ScaleDownFactor or ScaleDownAdjustment.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "scaleDownAdjustment")]
    pub scale_down_adjustment: Option<i64>,
    /// ScaleDownFactor is the multiplicative factor applied to the current number of runners used
    /// to determine how many pods should be removed.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "scaleDownFactor")]
    pub scale_down_factor: Option<String>,
    /// ScaleDownThreshold is the percentage of busy runners less than which will
    /// trigger the hpa to scale the runners down.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "scaleDownThreshold")]
    pub scale_down_threshold: Option<String>,
    /// ScaleUpAdjustment is the number of runners added on scale-up.
    /// You can only specify either ScaleUpFactor or ScaleUpAdjustment.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "scaleUpAdjustment")]
    pub scale_up_adjustment: Option<i64>,
    /// ScaleUpFactor is the multiplicative factor applied to the current number of runners used
    /// to determine how many pods should be added.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "scaleUpFactor")]
    pub scale_up_factor: Option<String>,
    /// ScaleUpThreshold is the percentage of busy runners greater than which will
    /// trigger the hpa to scale runners up.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "scaleUpThreshold")]
    pub scale_up_threshold: Option<String>,
    /// Type is the type of metric to be used for autoscaling.
    /// It can be TotalNumberOfQueuedAndInProgressWorkflowRuns or PercentageRunnersBusy.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
}

/// ScaleTargetRef is the reference to scaled resource like RunnerDeployment
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct HorizontalRunnerAutoscalerScaleTargetRef {
    /// Kind is the type of resource being referenced
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<HorizontalRunnerAutoscalerScaleTargetRefKind>,
    /// Name is the name of resource being referenced
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// ScaleTargetRef is the reference to scaled resource like RunnerDeployment
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum HorizontalRunnerAutoscalerScaleTargetRefKind {
    RunnerDeployment,
    RunnerSet,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct HorizontalRunnerAutoscalerScaleUpTriggers {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "githubEvent")]
    pub github_event: Option<HorizontalRunnerAutoscalerScaleUpTriggersGithubEvent>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct HorizontalRunnerAutoscalerScaleUpTriggersGithubEvent {
    /// https://docs.github.com/en/actions/reference/events-that-trigger-workflows#check_run
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "checkRun")]
    pub check_run: Option<HorizontalRunnerAutoscalerScaleUpTriggersGithubEventCheckRun>,
    /// https://docs.github.com/en/actions/reference/events-that-trigger-workflows#pull_request
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "pullRequest")]
    pub pull_request: Option<HorizontalRunnerAutoscalerScaleUpTriggersGithubEventPullRequest>,
    /// PushSpec is the condition for triggering scale-up on push event
    /// Also see https://docs.github.com/en/actions/reference/events-that-trigger-workflows#push
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push: Option<HorizontalRunnerAutoscalerScaleUpTriggersGithubEventPush>,
    /// https://docs.github.com/en/developers/webhooks-and-events/webhooks/webhook-events-and-payloads#workflow_job
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "workflowJob")]
    pub workflow_job: Option<HorizontalRunnerAutoscalerScaleUpTriggersGithubEventWorkflowJob>,
}

/// https://docs.github.com/en/actions/reference/events-that-trigger-workflows#check_run
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct HorizontalRunnerAutoscalerScaleUpTriggersGithubEventCheckRun {
    /// Names is a list of GitHub Actions glob patterns.
    /// Any check_run event whose name matches one of patterns in the list can trigger autoscaling.
    /// Note that check_run name seem to equal to the job name you've defined in your actions workflow yaml file.
    /// So it is very likely that you can utilize this to trigger depending on the job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
    /// Repositories is a list of GitHub repositories.
    /// Any check_run event whose repository matches one of repositories in the list can trigger autoscaling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repositories: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// One of: created, rerequested, or completed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<String>>,
}

/// https://docs.github.com/en/actions/reference/events-that-trigger-workflows#pull_request
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct HorizontalRunnerAutoscalerScaleUpTriggersGithubEventPullRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branches: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<String>>,
}

/// PushSpec is the condition for triggering scale-up on push event
/// Also see https://docs.github.com/en/actions/reference/events-that-trigger-workflows#push
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct HorizontalRunnerAutoscalerScaleUpTriggersGithubEventPush {
}

/// https://docs.github.com/en/developers/webhooks-and-events/webhooks/webhook-events-and-payloads#workflow_job
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct HorizontalRunnerAutoscalerScaleUpTriggersGithubEventWorkflowJob {
}

/// ScheduledOverride can be used to override a few fields of HorizontalRunnerAutoscalerSpec on schedule.
/// A schedule can optionally be recurring, so that the corresponding override happens every day, week, month, or year.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct HorizontalRunnerAutoscalerScheduledOverrides {
    /// EndTime is the time at which the first override ends.
    #[serde(rename = "endTime")]
    pub end_time: String,
    /// MinReplicas is the number of runners while overriding.
    /// If omitted, it doesn't override minReplicas.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "minReplicas")]
    pub min_replicas: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "recurrenceRule")]
    pub recurrence_rule: Option<HorizontalRunnerAutoscalerScheduledOverridesRecurrenceRule>,
    /// StartTime is the time at which the first override starts.
    #[serde(rename = "startTime")]
    pub start_time: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct HorizontalRunnerAutoscalerScheduledOverridesRecurrenceRule {
    /// Frequency is the name of a predefined interval of each recurrence.
    /// The valid values are "Daily", "Weekly", "Monthly", and "Yearly".
    /// If empty, the corresponding override happens only once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frequency: Option<HorizontalRunnerAutoscalerScheduledOverridesRecurrenceRuleFrequency>,
    /// UntilTime is the time of the final recurrence.
    /// If empty, the schedule recurs forever.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "untilTime")]
    pub until_time: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum HorizontalRunnerAutoscalerScheduledOverridesRecurrenceRuleFrequency {
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct HorizontalRunnerAutoscalerStatus {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "cacheEntries")]
    pub cache_entries: Option<Vec<HorizontalRunnerAutoscalerStatusCacheEntries>>,
    /// DesiredReplicas is the total number of desired, non-terminated and latest pods to be set for the primary RunnerSet
    /// This doesn't include outdated pods while upgrading the deployment and replacing the runnerset.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "desiredReplicas")]
    pub desired_replicas: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastSuccessfulScaleOutTime")]
    pub last_successful_scale_out_time: Option<String>,
    /// ObservedGeneration is the most recent generation observed for the target. It corresponds to e.g.
    /// RunnerDeployment's generation, which is updated on mutation by the API Server.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "observedGeneration")]
    pub observed_generation: Option<i64>,
    /// ScheduledOverridesSummary is the summary of active and upcoming scheduled overrides to be shown in e.g. a column of a `kubectl get hra` output
    /// for observability.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "scheduledOverridesSummary")]
    pub scheduled_overrides_summary: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct HorizontalRunnerAutoscalerStatusCacheEntries {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "expirationTime")]
    pub expiration_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<i64>,
}

