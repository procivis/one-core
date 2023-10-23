use super::{dto::InvitationType, TransportProtocol};
use crate::service::error::ServiceError;
use std::{collections::HashMap, sync::Arc};

#[derive(Clone)]
pub struct DetectedProtocol {
    pub invitation_type: InvitationType,
    pub protocol: Arc<dyn TransportProtocol + Send + Sync>,
}

#[cfg_attr(test, mockall::automock)]
pub(crate) trait TransportProtocolProvider {
    fn get_protocol(
        &self,
        protocol_id: &str,
    ) -> Result<Arc<dyn TransportProtocol + Send + Sync>, ServiceError>;

    fn detect_protocol(&self, url: &str) -> Option<DetectedProtocol>;
}

pub(crate) struct TransportProtocolProviderImpl {
    protocols: HashMap<String, Arc<dyn TransportProtocol + Send + Sync>>,
}

impl TransportProtocolProviderImpl {
    pub fn new(protocols: Vec<(String, Arc<dyn TransportProtocol + Send + Sync>)>) -> Self {
        Self {
            protocols: protocols.into_iter().collect(),
        }
    }
}

impl TransportProtocolProvider for TransportProtocolProviderImpl {
    fn get_protocol(
        &self,
        protocol_id: &str,
    ) -> Result<Arc<dyn TransportProtocol + Send + Sync>, ServiceError> {
        Ok(self
            .protocols
            .get(protocol_id)
            .ok_or(ServiceError::NotFound)?
            .to_owned())
    }

    fn detect_protocol(&self, url: &str) -> Option<DetectedProtocol> {
        for protocol in self.protocols.values() {
            if let Some(invitation_type) = protocol.detect_invitation_type(url) {
                return Some(DetectedProtocol {
                    invitation_type,
                    protocol: protocol.to_owned(),
                });
            }
        }
        None
    }
}
