use super::DidMethodError;
use crate::model::did::Did;
use crate::model::key::Key;
use crate::service::did::dto::CreateDidRequestDTO;
use async_trait::async_trait;
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
        _request: CreateDidRequestDTO,
        _key: Key,
    ) -> Result<DidId, DidMethodError> {
        todo!()
    }

    fn check_authorization(&self) -> bool {
        todo!()
    }

    async fn resolve(&self, _did: &DidValue) -> Result<Did, DidMethodError> {
        todo!()
    }

    fn update(&self) -> Result<(), DidMethodError> {
        Err(DidMethodError::NotSupported)
    }

    fn deactivate(&self) -> Result<(), DidMethodError> {
        Err(DidMethodError::NotSupported)
    }
}
