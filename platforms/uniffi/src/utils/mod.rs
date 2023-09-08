use std::future::Future;
use time::OffsetDateTime;

pub mod dto;
pub mod mapper;

/// Run synchronously
pub fn run_sync<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

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
