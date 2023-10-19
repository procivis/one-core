use async_trait::async_trait;

use super::DidMethodError;
use crate::model;
use crate::model::did::{Did, DidId};
use crate::service::did::dto::CreateDidRequestDTO;

use mockall::*;

#[derive(Default)]
pub struct DidMethod;

mock! {
    pub DidMethod {
        pub fn get_method(&self) -> String;
        pub fn load(&self, did_id: &DidId) -> Result<Did, DidMethodError>;
        pub fn create(&self, request: CreateDidRequestDTO, key: model::key::Key) -> Result<Did, DidMethodError>;
        pub fn check_authorization(&self) -> bool;
        pub fn resolve(&self, did: &str) -> Result<Did, DidMethodError>;
        pub fn update(&self) -> Result<(), DidMethodError>;
        pub fn deactivate(&self) -> Result<(), DidMethodError>;
    }
}

#[async_trait]
impl super::DidMethod for MockDidMethod {
    fn get_method(&self) -> String {
        self.get_method()
    }

    async fn load(&self, did_id: &DidId) -> Result<Did, DidMethodError> {
        self.load(did_id)
    }

    async fn create(
        &self,
        request: CreateDidRequestDTO,
        key: model::key::Key,
    ) -> Result<Did, DidMethodError> {
        self.create(request, key)
    }

    fn check_authorization(&self) -> bool {
        self.check_authorization()
    }

    async fn resolve(&self, did: &str) -> Result<Did, DidMethodError> {
        self.resolve(did)
    }

    fn update(&self) -> Result<(), DidMethodError> {
        self.update()
    }

    fn deactivate(&self) -> Result<(), DidMethodError> {
        self.deactivate()
    }
}
