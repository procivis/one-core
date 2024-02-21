use super::{dto::DidDocumentDTO, AmountOfKeys, DidCapabilities, DidMethodError, Operation};
use crate::{
    config::core_config::{DidType, Fields},
    model::key::Key,
};

use async_trait::async_trait;
use serde_json::json;
use shared_types::{DidId, DidValue};

pub struct X509Method {}

impl X509Method {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl super::DidMethod for X509Method {
    fn get_method(&self) -> String {
        "x509".to_string()
    }

    async fn create(
        &self,
        _id: &DidId,
        _params: &Option<serde_json::Value>,
        _keys: &[Key],
    ) -> Result<DidValue, DidMethodError> {
        todo!()
    }

    fn check_authorization(&self) -> bool {
        todo!()
    }

    async fn resolve(&self, _did: &DidValue) -> Result<DidDocumentDTO, DidMethodError> {
        todo!()
    }

    fn update(&self) -> Result<(), DidMethodError> {
        Err(DidMethodError::NotSupported)
    }

    fn can_be_deactivated(&self) -> bool {
        false
    }

    fn get_capabilities(&self) -> DidCapabilities {
        DidCapabilities {
            operations: vec![Operation::RESOLVE, Operation::CREATE],
            key_algorithms: vec!["ES256".to_string(), "EDDSA".to_string()],
        }
    }

    fn validate_keys(&self, _keys: AmountOfKeys) -> bool {
        todo!()
    }

    fn visit_config_fields(&self, fields: &Fields<DidType>) -> Fields<DidType> {
        Fields {
            capabilities: Some(json!(self.get_capabilities())),
            ..fields.clone()
        }
    }
}
