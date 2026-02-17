use serde::{Deserialize, Serialize};
use shared_types::NotificationId;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct WebhookNotificationResultDTO {
    /// successfully delivered notifications
    pub delivered: Vec<NotificationId>,
    /// failed and removed notifications
    pub failed: Vec<NotificationId>,
    /// failed and rescheduled notifications
    pub rescheduled: Vec<NotificationId>,
}
