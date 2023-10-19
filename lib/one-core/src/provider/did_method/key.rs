use async_trait::async_trait;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

use super::DidMethodError;
use crate::config::data_structure::DidKeyParams;
use crate::model::did::{Did, DidId, DidRelations, KeyRole, RelatedKey};
use crate::model::key::{Key, KeyId, KeyRelations};
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::provider::key_storage::provider::KeyProvider;
use crate::repository::did_repository::DidRepository;
use crate::repository::error::DataLayerError;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::service::did::dto::CreateDidRequestDTO;

pub struct KeyDidMethod {
    pub did_repository: Arc<dyn DidRepository + Send + Sync>,
    pub organisation_repository: Arc<dyn OrganisationRepository + Send + Sync>,
    pub key_provider: Arc<dyn KeyProvider + Send + Sync>,
    pub method_key: String,
    pub params: DidKeyParams,
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
        let fingerprint = key_storage.fingerprint(&key.public_key);
        let did_value = format!("did:key:{}", fingerprint);

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

    async fn resolve(&self, did: &str) -> Result<Did, DidMethodError> {
        let result = self
            .did_repository
            .get_did_by_value(
                &did.to_string(),
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

    fn update(&self) -> Result<(), DidMethodError> {
        Err(DidMethodError::NotSupported)
    }

    fn deactivate(&self) -> Result<(), DidMethodError> {
        Err(DidMethodError::NotSupported)
    }
}

async fn did_already_exists(
    repository: &Arc<dyn DidRepository + Send + Sync>,
    did_value: &str,
) -> Result<bool, DidMethodError> {
    let result = repository
        .get_did_by_value(&did_value.to_string(), &DidRelations::default())
        .await;

    match result {
        Ok(_) => Ok(true),
        Err(DataLayerError::RecordNotFound) => Ok(false),
        Err(e) => Err(DidMethodError::from(e)),
    }
}

fn did_from_did_request(
    request: CreateDidRequestDTO,
    organisation: Organisation,
    did_value: String,
    key: Key,
    now: OffsetDateTime,
) -> Result<Did, DidMethodError> {
    let mut keys: Vec<RelatedKey> = vec![];
    let mut add_keys = |key_ids: Vec<KeyId>, role: KeyRole| {
        for _ in key_ids {
            keys.push(RelatedKey {
                role: role.to_owned(),
                key: key.to_owned(),
            });
        }
    };

    add_keys(request.keys.authentication, KeyRole::Authentication);
    add_keys(request.keys.assertion, KeyRole::AssertionMethod);
    add_keys(request.keys.key_agreement, KeyRole::KeyAgreement);
    add_keys(
        request.keys.capability_invocation,
        KeyRole::CapabilityInvocation,
    );
    add_keys(
        request.keys.capability_delegation,
        KeyRole::CapabilityDelegation,
    );

    Ok(Did {
        id: Uuid::new_v4(),
        created_date: now,
        last_modified: now,
        name: request.name,
        organisation: Some(organisation),
        did: did_value,
        did_type: request.did_type,
        did_method: request.did_method,
        keys: Some(keys),
    })
}
