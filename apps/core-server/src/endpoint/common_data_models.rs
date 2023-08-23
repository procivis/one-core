use serde::{Serialize, Serializer};
use time::OffsetDateTime;

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
