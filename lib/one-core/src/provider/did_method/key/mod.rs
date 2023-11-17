mod mapper;
mod validator;

use async_trait::async_trait;
use did_key::KeyMaterial;
use shared_types::{DidId, DidValue};
use std::collections::HashMap;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

use super::DidMethodError;
use crate::{
    config::data_structure::{DidKeyParams, KeyAlgorithmEntity},
    model::{
        did::{Did, DidRelations, DidType, KeyRole, RelatedKey},
        key::{Key, KeyRelations},
        organisation::OrganisationRelations,
    },
    provider::key_storage::provider::KeyProvider,
    repository::{
        did_repository::DidRepository, error::DataLayerError,
        organisation_repository::OrganisationRepository,
    },
    service::did::dto::CreateDidRequestDTO,
};

use mapper::{categorize_did, did_from_did_request};
use validator::{did_already_exists, validate_public_key_length};

pub struct KeyDidMethod {
    pub did_repository: Arc<dyn DidRepository + Send + Sync>,
    pub organisation_repository: Arc<dyn OrganisationRepository + Send + Sync>,
    pub key_provider: Arc<dyn KeyProvider + Send + Sync>,
    pub method_key: String,
    pub params: DidKeyParams,
    pub key_algorithm_config: HashMap<String, KeyAlgorithmEntity>,
}

#[async_trait]
impl super::DidMethod for KeyDidMethod {
    fn get_method(&self) -> String {
        "key".to_string()
    }

    async fn load(&self, did_id: &DidId) -> Result<Did, DidMethodError> {
        let result = self
            .did_repository
            .get_did(
                did_id,
                &DidRelations {
                    organisation: Some(OrganisationRelations::default()),
                    keys: Some(KeyRelations::default()),
                },
            )
            .await
            .map_err(DidMethodError::from)?;

        if result.did_method == self.method_key {
            Ok(result)
        } else {
            Err(DidMethodError::DataLayerError(
                DataLayerError::RecordNotFound,
            ))
        }
    }

    async fn create(&self, request: CreateDidRequestDTO, key: Key) -> Result<Did, DidMethodError> {
        let key_storage = self
            .key_provider
            .get_key_storage(&key.storage_type)
            .map_err(|_| DidMethodError::KeyStorageNotFound)?;
        let fingerprint = key_storage
            .fingerprint(&key.public_key, &key.key_type)
            .map_err(|e| DidMethodError::ResolutionError(e.to_string()))?;
        // todo(mite): add constructor for this
        let did_value: DidValue = match format!("did:key:{}", fingerprint).parse() {
            Ok(v) => v,
            Err(err) => match err {},
        };

        if did_already_exists(&self.did_repository, &did_value).await? {
            return Err(DidMethodError::AlreadyExists);
        }

        let now = OffsetDateTime::now_utc();
        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
            .await?;
        let request = did_from_did_request(request, organisation, did_value, key, now)?;

        let did_id = self
            .did_repository
            .create_did(request)
            .await
            .map_err(DidMethodError::from)?;

        self.load(&did_id).await
    }

    fn check_authorization(&self) -> bool {
        todo!()
    }

    async fn resolve(&self, did: &DidValue) -> Result<Did, DidMethodError> {
        let key_type = categorize_did(did)?;

        let resolved = did_key::resolve(did.as_str())
            .map_err(|_| DidMethodError::ResolutionError("Failed to resolve".to_string()))?;

        let public_key = resolved.public_key_bytes();

        validate_public_key_length(&public_key, key_type)?;

        let now = OffsetDateTime::now_utc();
        let key = Key {
            id: Uuid::new_v4(),
            created_date: now,
            last_modified: now,
            public_key,
            name: did.to_string(),
            private_key: vec![],
            storage_type: "EPHEMERAL".to_string(),
            key_type: "EDDSA".to_string(),
            organisation: None,
        };

        Ok(Did {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            name: did.to_string(),
            did: did.clone(),
            did_type: DidType::Remote,
            did_method: "KEY".to_string(),
            keys: Some(vec![
                RelatedKey {
                    role: KeyRole::Authentication,
                    key: key.clone(),
                },
                RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.clone(),
                },
                RelatedKey {
                    role: KeyRole::CapabilityInvocation,
                    key: key.clone(),
                },
                RelatedKey {
                    role: KeyRole::CapabilityDelegation,
                    key,
                },
                // skipping KeyAgreement (only supported using X25519 converted key)
            ]),
            organisation: None,
        })
    }

    fn update(&self) -> Result<(), DidMethodError> {
        Err(DidMethodError::NotSupported)
    }

    fn deactivate(&self) -> Result<(), DidMethodError> {
        Err(DidMethodError::NotSupported)
    }
}

#[cfg(test)]
mod test;
