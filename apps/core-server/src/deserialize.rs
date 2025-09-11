use serde::Deserializer;
use time::OffsetDateTime;
use utoipa::ToSchema;
use utoipa::openapi::Schema;
use utoipa::openapi::schema::{ArrayBuilder, OneOfBuilder};

pub fn deserialize_timestamp<'de, D>(deserializer: D) -> Result<Option<OffsetDateTime>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Some(time::serde::rfc3339::deserialize(deserializer)?))
}

/// for use together with serde_as::OneOrMany
pub(crate) fn one_or_many<T: ToSchema>() -> Schema {
    OneOfBuilder::new()
        .item(T::schema())
        .item(ArrayBuilder::new().items(T::schema()).build())
        .build()
        .into()
}
