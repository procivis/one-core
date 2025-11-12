use std::collections::HashMap;
use std::sync::Arc;

use itertools::Itertools;
use url::Url;

use crate::config::core_config::IssuanceProtocolConfig;
use crate::provider::issuance_protocol::IssuanceProtocol;

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait IssuanceProtocolProvider: Send + Sync {
    fn get_protocol(&self, protocol_id: &str) -> Option<Arc<dyn IssuanceProtocol>>;
    async fn detect_protocol(&self, url: &Url) -> Option<(String, Arc<dyn IssuanceProtocol>)>;
}

pub(crate) struct IssuanceProtocolProviderImpl {
    protocols: HashMap<String, Arc<dyn IssuanceProtocol>>,
    config: IssuanceProtocolConfig,
}

#[async_trait::async_trait]
impl IssuanceProtocolProvider for IssuanceProtocolProviderImpl {
    fn get_protocol(&self, protocol_id: &str) -> Option<Arc<dyn IssuanceProtocol>> {
        self.protocols.get(protocol_id).cloned()
    }

    async fn detect_protocol(&self, url: &Url) -> Option<(String, Arc<dyn IssuanceProtocol>)> {
        let get_order = |id: &str| {
            self.config
                .get_fields(id)
                .ok()
                .and_then(|entry| entry.order)
                .unwrap_or(0)
        };
        let sorted_protocols = self
            .protocols
            .iter()
            .sorted_by(|(a, _), (b, _)| Ord::cmp(&get_order(a), &get_order(b)));

        for (id, protocol) in sorted_protocols {
            if protocol.holder_can_handle(url).await {
                return Some((id.to_owned(), protocol.to_owned()));
            }
        }

        None
    }
}

impl IssuanceProtocolProviderImpl {
    pub(crate) fn new(
        protocols: HashMap<String, Arc<dyn IssuanceProtocol>>,
        config: IssuanceProtocolConfig,
    ) -> Self {
        Self { protocols, config }
    }
}
