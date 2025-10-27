use serde::{Deserialize, Deserializer, Serializer};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub(super) fn into_timestamp_opt<S>(dt: &Option<OffsetDateTime>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match dt {
        Some(dt) => crate::mapper::timestamp::into_timestamp(dt, s),
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
