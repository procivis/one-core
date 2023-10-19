use std::{collections::HashMap, sync::Arc};

use super::DidMethod;
use crate::service::error::ServiceError;

pub trait DidMethodProvider {
    fn get_did_method(
        &self,
        did_method_id: &str,
    ) -> Result<Arc<dyn DidMethod + Send + Sync>, ServiceError>;
}

pub struct DidMethodProviderImpl {
    did_methods: HashMap<String, Arc<dyn DidMethod + Send + Sync>>,
}

impl DidMethodProviderImpl {
    pub fn new(did_methods: HashMap<String, Arc<dyn DidMethod + Send + Sync>>) -> Self {
        Self { did_methods }
    }
}

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

    // todo: add resolve - pick correct method and pass call
}
