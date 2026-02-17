use one_core::model::list_filter::ListFilterCondition;
use one_core::model::notification::{
    Notification, NotificationFilterValue, SortableNotificationColumn, UpdateNotificationRequest,
};
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::{IntoCondition, SimpleExpr};
use sea_orm::{ColumnTrait, IntoSimpleExpr};

use crate::entity::notification;
use crate::list_query_generic::{IntoFilterCondition, IntoSortingColumn, get_comparison_condition};

impl IntoSortingColumn for SortableNotificationColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::CreatedDate => notification::Column::CreatedDate,
        }
        .into_simple_expr()
    }
}

impl IntoFilterCondition for NotificationFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> sea_orm::Condition {
        match self {
            Self::CreatedDate(value) => {
                get_comparison_condition(notification::Column::CreatedDate, value)
            }
            Self::NextTryDate(value) => {
                get_comparison_condition(notification::Column::CreatedDate, value)
            }
            Self::Types(types) => notification::Column::Type.is_in(types).into_condition(),
        }
    }
}

impl From<notification::Model> for Notification {
    fn from(value: notification::Model) -> Self {
        Self {
            id: value.id,
            url: value.url,
            payload: value.payload,
            created_date: value.created_date,
            next_try_date: value.next_try_date,
            tries_count: value.tries_count,
            r#type: value.r#type,
            history_target: value.history_target,
            organisation_id: value.organisation_id,
        }
    }
}

impl From<Notification> for notification::ActiveModel {
    fn from(request: Notification) -> Self {
        Self {
            id: Set(request.id),
            url: Set(request.url),
            payload: Set(request.payload),
            created_date: Set(request.created_date),
            next_try_date: Set(request.next_try_date),
            tries_count: Set(request.tries_count),
            r#type: Set(request.r#type),
            history_target: Set(request.history_target),
            organisation_id: Set(request.organisation_id),
        }
    }
}

impl From<UpdateNotificationRequest> for notification::ActiveModel {
    fn from(value: UpdateNotificationRequest) -> Self {
        Self {
            next_try_date: value.next_try_date.map(Set).unwrap_or_default(),
            tries_count: value.tries_count.map(Set).unwrap_or_default(),
            ..Default::default()
        }
    }
}
