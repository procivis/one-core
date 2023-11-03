use super::DidMethodError;
use crate::model::did::{Did, DidId};
use crate::model::key::Key;
use crate::service::did::dto::CreateDidRequestDTO;
use async_trait::async_trait;

pub struct WebDidMethod {}

#[async_trait]
impl super::DidMethod for WebDidMethod {
    fn get_method(&self) -> String {
        "web".to_string()
    }

    async fn load(&self, _did_id: &DidId) -> Result<Did, DidMethodError> {
        todo!()
    }

    async fn create(
        &self,
        _request: CreateDidRequestDTO,
        _key: Key,
    ) -> Result<Did, DidMethodError> {
        todo!()
    }

    fn check_authorization(&self) -> bool {
        todo!()
    }

    async fn resolve(&self, _did: &str) -> Result<Did, DidMethodError> {
        todo!()
    }

    fn update(&self) -> Result<(), DidMethodError> {
        Err(DidMethodError::NotSupported)
    }

    fn deactivate(&self) -> Result<(), DidMethodError> {
        Err(DidMethodError::NotSupported)
    }
}
