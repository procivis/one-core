use std::{collections::HashMap, sync::Arc};

use shared_types::DidValue;

use super::{dto::DidDocumentDTO, DidMethod};
use crate::{
    common_mapper::did_method_id_from_value,
    service::error::{MissingProviderError, ServiceError},
};

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait DidMethodProvider {
    fn get_did_method(&self, did_method_id: &str) -> Option<Arc<dyn DidMethod>>;

    async fn resolve(&self, did: &DidValue) -> Result<DidDocumentDTO, ServiceError>;
}

pub struct DidMethodProviderImpl {
    did_methods: HashMap<String, Arc<dyn DidMethod>>,
}

impl DidMethodProviderImpl {
    pub fn new(did_methods: HashMap<String, Arc<dyn DidMethod>>) -> Self {
        Self { did_methods }
    }
}

#[async_trait::async_trait]
impl DidMethodProvider for DidMethodProviderImpl {
    fn get_did_method(&self, did_method_id: &str) -> Option<Arc<dyn DidMethod>> {
        self.did_methods.get(did_method_id).cloned()
    }

    async fn resolve(&self, did: &DidValue) -> Result<DidDocumentDTO, ServiceError> {
        let did_method_id = did_method_id_from_value(did)?;

        let method = self
            .get_did_method(&did_method_id)
            .ok_or(MissingProviderError::DidMethod(did_method_id))?;

        Ok(method.resolve(did).await?)
    }
}
