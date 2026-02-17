use autometrics::autometrics;
use one_core::model::common::LockType;
use one_core::model::notification::{
    Notification, NotificationList, NotificationListQuery, UpdateNotificationRequest,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::notification_repository::NotificationRepository;
use sea_orm::ActiveValue::Unchanged;
use sea_orm::{ActiveModelTrait, EntityTrait, QueryOrder, QuerySelect};
use shared_types::NotificationId;

use super::NotificationProvider;
use crate::common::list_query_with_base_model;
use crate::entity::notification;
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::{map_lock_type, to_data_layer_error, to_update_data_layer_error};

#[autometrics]
#[async_trait::async_trait]
impl NotificationRepository for NotificationProvider {
    async fn create(&self, request: Notification) -> Result<NotificationId, DataLayerError> {
        let id = request.id;
        notification::ActiveModel::from(request)
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(id)
    }

    async fn get(
        &self,
        id: &NotificationId,
        lock: Option<LockType>,
    ) -> Result<Option<Notification>, DataLayerError> {
        let select = notification::Entity::find_by_id(id);
        let select = match lock {
            None => select,
            Some(lock) => select.lock(map_lock_type(lock)),
        };
        let notification = select
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        let Some(notification) = notification else {
            return Ok(None);
        };

        Ok(Some(notification.into()))
    }

    async fn list(
        &self,
        query_params: NotificationListQuery,
    ) -> Result<NotificationList, DataLayerError> {
        let query = notification::Entity::find()
            .with_list_query(&query_params)
            .order_by_desc(notification::Column::CreatedDate)
            .order_by_desc(notification::Column::Id);

        list_query_with_base_model(query, query_params, &self.db).await
    }

    async fn update(
        &self,
        id: &NotificationId,
        request: UpdateNotificationRequest,
    ) -> Result<(), DataLayerError> {
        let mut model = notification::ActiveModel::from(request);
        model.id = Unchanged(*id);
        model
            .update(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;
        Ok(())
    }

    async fn delete(&self, id: &NotificationId) -> Result<(), DataLayerError> {
        notification::Entity::delete_by_id(*id)
            .exec(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;
        Ok(())
    }
}
