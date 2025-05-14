use serde::{Serialize, Serializer};
use time::OffsetDateTime;

pub(crate) fn into_timestamp<S>(dt: &OffsetDateTime, s: S) -> Result<S::Ok, S::Error>
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

/// Copied from time::serde::timestamp::option, but with the modification to support fractional
/// unix timestamps, as is required by SWIYU.
///
/// Treat an `Option<OffsetDateTime>` as a [Unix timestamp] for the purposes of
/// serde.
///
/// Use this module in combination with serde's [`#[with]`][with] attribute.
///
/// When deserializing, the offset is assumed to be UTC.
///
/// [Unix timestamp]: https://en.wikipedia.org/wiki/Unix_time
/// [with]: https://serde.rs/field-attrs.html#with
pub mod option {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use time::OffsetDateTime;

    /// Serialize an `Option<OffsetDateTime>` as its Unix timestamp
    pub fn serialize<S: Serializer>(
        option: &Option<OffsetDateTime>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        option
            .map(OffsetDateTime::unix_timestamp)
            .serialize(serializer)
    }

    /// Deserialize an `Option<OffsetDateTime>` from its Unix timestamp
    pub fn deserialize<'a, D: Deserializer<'a>>(
        deserializer: D,
    ) -> Result<Option<OffsetDateTime>, D::Error> {
        Option::<f64>::deserialize(deserializer)?
            .map(|val| val as i64)
            .map(OffsetDateTime::from_unix_timestamp)
            .transpose()
            .map_err(|err| Error::custom(format!("failed to deserialize timestamp: {err}")))
    }
}
