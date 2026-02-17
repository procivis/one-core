use shared_types::{NotificationId, OrganisationId, TaskId};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::list_filter::{ListFilterValue, ValueComparison};
use crate::model::list_query::ListQuery;

#[derive(Clone, Debug)]
pub struct Notification {
    pub id: NotificationId,
    pub created_date: OffsetDateTime,
    pub url: String,
    pub payload: Vec<u8>,
    pub next_try_date: OffsetDateTime,
    pub tries_count: u32,
    pub r#type: TaskId,
    pub history_target: Option<String>,
    pub organisation_id: OrganisationId,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UpdateNotificationRequest {
    pub tries_count: Option<u32>,
    pub next_try_date: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableNotificationColumn {
    CreatedDate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NotificationFilterValue {
    CreatedDate(ValueComparison<OffsetDateTime>),
    NextTryDate(ValueComparison<OffsetDateTime>),
    Types(Vec<TaskId>),
}

impl ListFilterValue for NotificationFilterValue {}

pub type NotificationList = GetListResponse<Notification>;
pub type NotificationListQuery = ListQuery<SortableNotificationColumn, NotificationFilterValue>;
