use serde::{Deserialize, Serialize};
use shared_types::TrustListSubscriptionId;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UpdateResultDTO {
    pub updated_subscriptions: Vec<TrustListSubscriptionId>,
    pub total_checks: u64,
}
