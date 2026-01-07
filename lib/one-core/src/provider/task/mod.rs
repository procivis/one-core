use serde_json::Value;

use crate::service::error::ServiceError;

pub mod certificate_check;
pub mod holder_check_credential_status;
pub mod interaction_expiration_check;
pub mod provider;
pub mod retain_proof_check;
pub mod suspend_check;

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait Task: Send + Sync {
    async fn run(&self) -> Result<Value, ServiceError>;
}
