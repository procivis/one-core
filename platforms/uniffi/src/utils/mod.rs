use one_core::service::error::ServiceError;
use time::OffsetDateTime;
use uuid::Uuid;

pub(crate) mod native_key_storage;

/// Date-time formatting
pub trait TimestampFormat {
    fn format_timestamp(&self) -> String;
}

const TIMESTAMP_FORMAT: &[time::format_description::FormatItem<'static>] = time::macros::format_description!("[year]-[month]-[day padding:zero]T[hour padding:zero]:[minute padding:zero]:[second padding:zero].000Z");

impl TimestampFormat for OffsetDateTime {
    fn format_timestamp(&self) -> String {
        self.format(&TIMESTAMP_FORMAT).unwrap()
    }
}

pub fn into_uuid(input: &str) -> Result<Uuid, ServiceError> {
    Uuid::parse_str(input).map_err(Into::into)
}
