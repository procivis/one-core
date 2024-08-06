use async_trait::async_trait;
use one_providers::common_models::did::{DidId, DidValue};
use one_providers::common_models::key::OpenKey;
use one_providers::did::error::DidMethodError;
use one_providers::did::keys::Keys;
use one_providers::did::model::{AmountOfKeys, DidCapabilities, DidDocument, Operation};
use one_providers::did::DidMethod;

pub struct X509Method {}

impl X509Method {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl DidMethod for X509Method {
    async fn create(
        &self,
        _id: &DidId,
        _params: &Option<serde_json::Value>,
        _keys: &[OpenKey],
    ) -> Result<DidValue, DidMethodError> {
        todo!()
    }

    async fn resolve(&self, _did: &DidValue) -> Result<DidDocument, DidMethodError> {
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

    fn get_keys(&self) -> Option<Keys> {
        None
    }
}
