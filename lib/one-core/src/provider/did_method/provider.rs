use std::{collections::HashMap, sync::Arc};

use shared_types::DidValue;

use super::{dto::DidDocumentDTO, DidMethod};
use crate::{common_mapper::did_method_id_from_value, service::error::ServiceError};

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait DidMethodProvider {
    fn get_did_method(
        &self,
        did_method_id: &str,
    ) -> Result<Arc<dyn DidMethod + Send + Sync>, ServiceError>;

    async fn resolve(&self, did: &DidValue) -> Result<DidDocumentDTO, ServiceError>;
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

    async fn resolve(&self, did: &DidValue) -> Result<DidDocumentDTO, ServiceError> {
        let did_method_id = did_method_id_from_value(did)?;

        let method = self.get_did_method(&did_method_id)?;

        Ok(method.resolve(did).await?)
    }
}
