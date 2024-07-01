use one_core::service::error::ServiceError;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

pub(crate) mod native_ble_central;
pub(crate) mod native_ble_peripheral;
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

pub fn format_timestamp_opt(datetime: Option<OffsetDateTime>) -> Option<String> {
    datetime.as_ref().map(OffsetDateTime::format_timestamp)
}

pub fn into_id<T: From<Uuid>>(input: &str) -> Result<T, ServiceError> {
    Uuid::parse_str(input).map_err(Into::into).map(Into::into)
}

pub fn into_id_opt<T: From<Uuid>>(input: Option<String>) -> Result<Option<T>, ServiceError> {
    Ok(input
        .as_deref()
        .map(into_id::<T>)
        .transpose()?
        .map(Into::into))
}

pub fn into_timestamp(input: &str) -> Result<OffsetDateTime, ServiceError> {
    OffsetDateTime::parse(input, &Rfc3339).map_err(|e| ServiceError::MappingError(e.to_string()))
}
