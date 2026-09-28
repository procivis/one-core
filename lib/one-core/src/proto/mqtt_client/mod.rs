use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin};

pub mod rumqttc_client;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait MqttTopic: Send + Sync {
    async fn send(&self, bytes: Vec<u8>) -> Result<(), Error>;
    async fn recv(&mut self) -> Result<Vec<u8>, Error>;
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait MqttClient: Send + Sync {
    async fn subscribe(
        &self,
        url: String,
        port: u16,
        topic: String,
    ) -> Result<Box<dyn MqttTopic>, Error>;
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Sending error: {0}")]
    SendingError(anyhow::Error),
    #[error("Subscription error: {0}")]
    SubscriptionError(anyhow::Error),
}

impl ErrorCodeMixin for Error {
    fn error_code(&self) -> ErrorCode {
        ErrorCode::BR_0349
    }
}
