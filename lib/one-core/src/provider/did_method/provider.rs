use std::{collections::HashMap, sync::Arc};

use super::DidMethod;
use crate::{
    model::{
        did::{Did, DidRelations},
        organisation::Organisation,
    },
    provider::did_method::mapper::get_did_method_id,
    repository::{did_repository::DidRepository, error::DataLayerError},
    service::error::ServiceError,
};

#[async_trait::async_trait]
pub trait DidMethodProvider {
    fn get_did_method(
        &self,
        did_method_id: &str,
    ) -> Result<Arc<dyn DidMethod + Send + Sync>, ServiceError>;

    async fn resolve(&self, did: &str, organisation: Organisation) -> Result<Did, ServiceError>;
}

pub struct DidMethodProviderImpl {
    did_methods: HashMap<String, Arc<dyn DidMethod + Send + Sync>>,
    did_repository: Arc<dyn DidRepository + Send + Sync>,
}

impl DidMethodProviderImpl {
    pub fn new(
        did_methods: HashMap<String, Arc<dyn DidMethod + Send + Sync>>,
        did_repository: Arc<dyn DidRepository + Send + Sync>,
    ) -> Self {
        Self {
            did_methods,
            did_repository,
        }
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

    async fn resolve(&self, did: &str, organisation: Organisation) -> Result<Did, ServiceError> {
        let parts = did.splitn(3, ':').collect::<Vec<_>>();
        let did_method = parts.get(1).ok_or(ServiceError::ValidationError(
            "Did method not found".to_string(),
        ))?;

        let did_method_id = get_did_method_id(did_method)?;
        let method = self.get_did_method(&did_method_id)?;

        let resolved_did = method.resolve(did).await?;

        // store into DB if not exists
        let existing_did_result = self
            .did_repository
            .get_did_by_value(&did.to_string(), &DidRelations::default())
            .await;

        match existing_did_result {
            Ok(_) => {} // did already exists in the database, no operation needed
            Err(DataLayerError::RecordNotFound) => {
                self.did_repository
                    .create_did(Did {
                        keys: None, // do not store (remote) keys
                        organisation: Some(organisation),
                        ..resolved_did.to_owned()
                    })
                    .await?;
            }
            Err(error) => Err(error)?,
        };

        Ok(resolved_did)
    }
}
