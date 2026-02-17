use shared_types::NotificationId;

use super::error::DataLayerError;
use crate::model::common::LockType;
use crate::model::notification::{
    Notification, NotificationList, NotificationListQuery, UpdateNotificationRequest,
};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait NotificationRepository: Send + Sync {
    async fn create(&self, request: Notification) -> Result<NotificationId, DataLayerError>;

    async fn list(
        &self,
        query_params: NotificationListQuery,
    ) -> Result<NotificationList, DataLayerError>;

    /// Loads a notification from the database, including the specified relations.
    /// If a lock type is specified, it will lock the given row. The lock only takes effect if
    /// loaded **within a transaction**.
    async fn get(
        &self,
        id: &NotificationId,
        lock: Option<LockType>,
    ) -> Result<Option<Notification>, DataLayerError>;

    async fn update(
        &self,
        id: &NotificationId,
        request: UpdateNotificationRequest,
    ) -> Result<(), DataLayerError>;

    async fn delete(&self, id: &NotificationId) -> Result<(), DataLayerError>;
}
