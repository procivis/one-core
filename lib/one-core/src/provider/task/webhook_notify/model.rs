use serde::Deserialize;
use serde_with::{DurationSeconds, serde_as};
use time::Duration;

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WebhookNotifyParams {
    pub allowed_hosts: Option<Vec<String>>,
    #[serde(default)]
    pub allow_insecure_http_transport: bool,
    #[serde_as(as = "DurationSeconds<i64>")]
    pub request_timeout: Duration,
    pub retries: Option<Retries>,
}

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Retries {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub interval: Duration,
    pub max_attempts: u32,
    pub exponential_factor: f32,
}
