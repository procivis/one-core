use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

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

pub(super) fn into_timestamp_opt<S>(dt: &Option<OffsetDateTime>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match dt {
        Some(dt) => into_timestamp(dt, s),
        None => s.serialize_none(),
    }
}

pub(super) fn from_timestamp_opt<'de, D>(
    deserializer: D,
) -> Result<Option<OffsetDateTime>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    Option::<String>::deserialize(deserializer).and_then(|string| {
        string
            .map(|string| {
                OffsetDateTime::parse(&string, &Rfc3339)
                    .map_err(|err| Error::custom(err.to_string()))
            })
            .transpose()
    })
}
