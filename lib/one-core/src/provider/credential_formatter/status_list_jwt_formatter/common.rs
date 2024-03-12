use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub(super) fn into_timestamp<S>(dt: &OffsetDateTime, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let formatted = format!(
        "{}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        dt.year(),
        dt.month() as i32,
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    );
    formatted.serialize(s)
}

pub(super) fn from_timestamp<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    String::deserialize(deserializer).and_then(|string| {
        OffsetDateTime::parse(&string, &Rfc3339).map_err(|err| Error::custom(err.to_string()))
    })
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StatusPurpose {
    Revocation,
    Suspension,
}
