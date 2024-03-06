use serde::Deserializer;
use time::OffsetDateTime;

pub fn deserialize_timestamp<'de, D>(deserializer: D) -> Result<Option<OffsetDateTime>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Some(time::serde::rfc3339::deserialize(deserializer)?))
}
