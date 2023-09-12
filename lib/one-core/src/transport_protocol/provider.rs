use super::TransportProtocol;
use crate::service::error::ServiceError;
use std::{collections::HashMap, sync::Arc};

pub(crate) trait TransportProtocolProvider {
    fn get_protocol(
        &self,
        protocol_id: &str,
    ) -> Result<Arc<dyn TransportProtocol + Send + Sync>, ServiceError>;
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
            .clone())
    }
}
