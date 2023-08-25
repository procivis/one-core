use std::fmt;

use serde::{Serialize, Serializer};
use time::OffsetDateTime;

use crate::dto::common::GetListResponseRestDTO;

impl<T, K> From<one_core::model::common::GetListResponse<K>> for GetListResponseRestDTO<T>
where
    T: From<K> + Clone + fmt::Debug + Serialize,
{
    fn from(value: one_core::model::common::GetListResponse<K>) -> Self {
        Self {
            values: value.values.into_iter().map(|item| item.into()).collect(),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }
    }
}

pub fn front_time<S>(dt: &OffsetDateTime, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let formatted = format!(
        "{}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        dt.year(),
        dt.month() as i32,
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
        dt.millisecond()
    );
    formatted.serialize(s)
}

pub fn front_time_option<S>(dt: &Option<OffsetDateTime>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match dt {
        Some(dt) => front_time(dt, s),
        None => s.serialize_none(),
    }
}
