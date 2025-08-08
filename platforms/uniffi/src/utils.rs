use one_core::service::error::ServiceError;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

/// Date-time formatting
pub trait TimestampFormat {
    fn format_timestamp(&self) -> String;
}

const TIMESTAMP_FORMAT: &[time::format_description::FormatItem<'static>] = time::macros::format_description!(
    "[year]-[month]-[day padding:zero]T[hour padding:zero]:[minute padding:zero]:[second padding:zero].000Z"
);

impl TimestampFormat for OffsetDateTime {
    fn format_timestamp(&self) -> String {
        self.format(&TIMESTAMP_FORMAT)
            .expect("Failed to compile timestamp format")
    }
}

pub(crate) fn format_timestamp_opt(datetime: Option<OffsetDateTime>) -> Option<String> {
    datetime.as_ref().map(OffsetDateTime::format_timestamp)
}

pub(crate) fn from_id_opt<T: Into<Uuid>>(input: Option<T>) -> Option<String> {
    input.map(|f| f.into().to_string())
}

pub(crate) fn into_id<T: From<Uuid>>(input: impl AsRef<str>) -> Result<T, ServiceError> {
    Uuid::parse_str(input.as_ref())
        .map_err(Into::into)
        .map(Into::into)
}

pub(crate) fn into_id_opt<T: From<Uuid>>(input: Option<String>) -> Result<Option<T>, ServiceError> {
    input.as_deref().map(into_id::<T>).transpose()
}

pub(crate) fn into_timestamp(input: &str) -> Result<OffsetDateTime, ServiceError> {
    OffsetDateTime::parse(input, &Rfc3339).map_err(|e| ServiceError::MappingError(e.to_string()))
}
