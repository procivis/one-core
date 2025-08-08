use similar_asserts::assert_eq;
use time::OffsetDateTime;
use time::macros::offset;

pub fn query_time_urlencoded(field: &str, dt: OffsetDateTime) -> String {
    assert_eq!(dt.offset(), offset!(UTC));
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
    serde_urlencoded::to_string(&[(field, formatted)]).unwrap()
}
