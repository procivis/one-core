use std::sync::Arc;

use url::Url;

use super::VerificationProtocolImpl;

pub(crate) trait VerificationProtocol:
    VerificationProtocolImpl<InteractionContext = serde_json::Value>
{
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait VerificationProtocolProvider: Send + Sync {
    fn get_protocol(&self, protocol_id: &str) -> Option<Arc<dyn VerificationProtocol>>;
    fn detect_protocol(&self, url: &Url) -> Option<(String, Arc<dyn VerificationProtocol>)>;
}
