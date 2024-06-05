use one_core::service::error::ServiceError;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::error::BindingError;

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

pub fn try_into_url<T: AsRef<str>>(input: T) -> Result<Url, BindingError> {
    let url = input.as_ref();
    Url::parse(url).map_err(|err| BindingError::ValidationError(err.to_string()))
}
