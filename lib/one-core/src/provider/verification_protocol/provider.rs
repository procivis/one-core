use std::collections::HashMap;
use std::sync::Arc;

use url::Url;

use crate::provider::verification_protocol::VerificationProtocol;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait VerificationProtocolProvider: Send + Sync {
    fn get_protocol(&self, protocol_id: &str) -> Option<Arc<dyn VerificationProtocol>>;
    fn detect_protocol(&self, url: &Url) -> Option<(String, Arc<dyn VerificationProtocol>)>;
}

pub(crate) struct VerificationProtocolProviderImpl {
    protocols: HashMap<String, Arc<dyn VerificationProtocol>>,
}

impl VerificationProtocolProviderImpl {
    pub(crate) fn new(protocols: HashMap<String, Arc<dyn VerificationProtocol>>) -> Self {
        Self { protocols }
    }
}

#[async_trait::async_trait]
impl VerificationProtocolProvider for VerificationProtocolProviderImpl {
    fn get_protocol(&self, protocol_id: &str) -> Option<Arc<dyn VerificationProtocol>> {
        self.protocols.get(protocol_id).cloned()
    }

    fn detect_protocol(&self, url: &Url) -> Option<(String, Arc<dyn VerificationProtocol>)> {
        self.protocols
            .iter()
            .find(|(_, protocol)| protocol.holder_can_handle(url))
            .map(|(id, protocol)| (id.to_owned(), protocol.to_owned()))
    }
}
