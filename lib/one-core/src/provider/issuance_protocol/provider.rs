use std::collections::HashMap;
use std::sync::Arc;

use url::Url;

use crate::provider::issuance_protocol::IssuanceProtocol;

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait IssuanceProtocolProvider: Send + Sync {
    fn get_protocol(&self, protocol_id: &str) -> Option<Arc<dyn IssuanceProtocol>>;
    fn detect_protocol(&self, url: &Url) -> Option<(String, Arc<dyn IssuanceProtocol>)>;
}

pub(crate) struct IssuanceProtocolProviderImpl {
    protocols: HashMap<String, Arc<dyn IssuanceProtocol>>,
}

#[async_trait::async_trait]
impl IssuanceProtocolProvider for IssuanceProtocolProviderImpl {
    fn get_protocol(&self, protocol_id: &str) -> Option<Arc<dyn IssuanceProtocol>> {
        self.protocols.get(protocol_id).cloned()
    }

    fn detect_protocol(&self, url: &Url) -> Option<(String, Arc<dyn IssuanceProtocol>)> {
        self.protocols
            .iter()
            .find(|(_, protocol)| protocol.holder_can_handle(url))
            .map(|(id, protocol)| (id.to_owned(), protocol.to_owned()))
    }
}

impl IssuanceProtocolProviderImpl {
    pub(crate) fn new(protocols: HashMap<String, Arc<dyn IssuanceProtocol>>) -> Self {
        Self { protocols }
    }
}
