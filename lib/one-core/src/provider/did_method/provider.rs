use std::{collections::HashMap, sync::Arc};

use super::DidMethod;
use crate::{
    model::did::Did, provider::did_method::mapper::get_did_method_id, service::error::ServiceError,
};

#[async_trait::async_trait]
pub trait DidMethodProvider {
    fn get_did_method(
        &self,
        did_method_id: &str,
    ) -> Result<Arc<dyn DidMethod + Send + Sync>, ServiceError>;

    async fn resolve(&self, did: &str) -> Result<Did, ServiceError>;
}

pub struct DidMethodProviderImpl {
    did_methods: HashMap<String, Arc<dyn DidMethod + Send + Sync>>,
}

impl DidMethodProviderImpl {
    pub fn new(did_methods: HashMap<String, Arc<dyn DidMethod + Send + Sync>>) -> Self {
        Self { did_methods }
    }
}

#[async_trait::async_trait]
impl DidMethodProvider for DidMethodProviderImpl {
    fn get_did_method(
        &self,
        did_method_id: &str,
    ) -> Result<Arc<dyn DidMethod + Send + Sync>, ServiceError> {
        Ok(self
            .did_methods
            .get(did_method_id)
            .ok_or(ServiceError::NotFound)?
            .clone())
    }

    async fn resolve(&self, did: &str) -> Result<Did, ServiceError> {
        let parts = did.splitn(3, ':').collect::<Vec<_>>();
        let did_method = parts.get(1).ok_or(ServiceError::ValidationError(
            "Did method not found".to_string(),
        ))?;

        let did_method_id = get_did_method_id(did_method)?;
        let method = self.get_did_method(&did_method_id)?;

        Ok(method.resolve(did).await?)
    }
}
