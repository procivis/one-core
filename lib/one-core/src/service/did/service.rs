use std::collections::{HashMap, HashSet};
use std::ops::Deref;

use shared_types::{DidId, DidValue, KeyId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::DidService;
use super::dto::{
    CreateDidRequestDTO, CreateDidRequestKeysDTO, DidPatchRequestDTO, DidResponseDTO,
    GetDidListResponseDTO,
};
use super::mapper::{
    did_from_did_request, did_update_to_update_request, identifier_from_did, map_did_to_did_keys,
};
use super::validator::validate_deactivation_request;
use crate::config::core_config::{KeyAlgorithmType, KeyStorageType};
use crate::config::validator::did::validate_did_method;
use crate::model::did::{Did, DidListQuery, DidRelations};
use crate::model::identifier::{IdentifierState, UpdateIdentifierRequest};
use crate::model::key::{Key, KeyRelations};
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::provider::did_method::DidKeys;
use crate::provider::did_method::dto::DidDocumentDTO;
use crate::provider::did_method::error::{DidMethodError, DidMethodProviderError};
use crate::provider::key_algorithm::error::KeyAlgorithmProviderError;
use crate::provider::key_storage::provider::KeyProvider;
use crate::repository::error::DataLayerError;
use crate::service::did::mapper::{
    map_did_model_to_did_web_response, map_key_to_verification_method,
};
use crate::service::did::validator::validate_request_amount_of_keys;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError, ValidationError,
};

impl DidService {
    /// Returns did document for did:web
    ///
    /// # Arguments
    ///
    /// * `id` - Did uuid
    pub async fn get_did_web_document(&self, id: &DidId) -> Result<DidDocumentDTO, ServiceError> {
        let did = self
            .did_repository
            .get_did(
                id,
                &DidRelations {
                    keys: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        let Some(did) = did else {
            return Err(EntityNotFoundError::Did(*id).into());
        };

        if did.did.method() != "web" {
            return Err(BusinessLogicError::InvalidDidMethod {
                method: did.did_method,
            }
            .into());
        }

        if did.deactivated {
            return Err(BusinessLogicError::DidIsDeactivated(did.id).into());
        }

        let mut grouped_key: HashMap<KeyId, Key> = HashMap::new();
        let keys = did
            .keys
            .as_ref()
            .ok_or(ServiceError::MappingError("No keys found".to_string()))?;
        for key in keys {
            grouped_key.insert(key.key.id, key.key.clone());
        }
        map_did_model_to_did_web_response(
            &did,
            keys,
            &grouped_key
                .iter()
                .map(|(key, value)| {
                    let key_type = value.key_algorithm_type().ok_or(
                        KeyAlgorithmProviderError::MissingAlgorithmImplementation(
                            value.key_type.to_string(),
                        ),
                    )?;

                    let public_key = self.key_algorithm_provider.reconstruct_key(
                        key_type,
                        &value.public_key,
                        None,
                        None,
                    )?;
                    Ok((
                        key.to_owned(),
                        map_key_to_verification_method(
                            &did.did,
                            key,
                            public_key.public_key_as_jwk()?.into(),
                        )?,
                    ))
                })
                .collect::<Result<HashMap<_, _>, ServiceError>>()?,
        )
    }

    /// Returns did log for did:webvh(did:tdw)
    ///
    /// # Arguments
    ///
    /// * `id` - Did uuid
    pub async fn get_did_webvh_log(&self, id: &DidId) -> Result<String, ServiceError> {
        let did = self
            .did_repository
            .get_did(id, &DidRelations::default())
            .await?;

        let Some(did) = did else {
            return Err(EntityNotFoundError::Did(*id).into());
        };

        let Some(log) = did.log else {
            return Err(BusinessLogicError::InvalidDidMethod {
                method: did.did_method,
            }
            .into());
        };
        Ok(log)
    }

    /// Returns details of a did
    ///
    /// # Arguments
    ///
    /// * `id` - Did uuid
    pub async fn get_did(&self, id: &DidId) -> Result<DidResponseDTO, ServiceError> {
        let did = self
            .did_repository
            .get_did(
                id,
                &DidRelations {
                    organisation: Some(OrganisationRelations::default()),
                    keys: Some(KeyRelations::default()),
                },
            )
            .await?;

        let Some(did) = did else {
            return Err(EntityNotFoundError::Did(*id).into());
        };

        did.try_into()
    }

    /// Returns list of dids according to query
    ///
    /// # Arguments
    ///
    /// * `query` - query parameters
    pub async fn get_did_list(
        &self,
        query: DidListQuery,
    ) -> Result<GetDidListResponseDTO, ServiceError> {
        let result = self.did_repository.get_did_list(query).await?;
        Ok(result.into())
    }

    /// Creates a new did with data provided in arguments
    ///
    /// # Arguments
    ///
    /// * `request` - did data
    pub async fn create_did(&self, request: CreateDidRequestDTO) -> Result<DidId, ServiceError> {
        let (did, now) = self.create_did_without_identifier(request).await?;
        let did_id = did.id;
        self.identifier_repository
            .create(identifier_from_did(did, now))
            .await?;

        Ok(did_id)
    }

    pub async fn create_did_without_identifier(
        &self,
        request: CreateDidRequestDTO,
    ) -> Result<(Did, OffsetDateTime), ServiceError> {
        validate_did_method(&request.did_method, &self.config.did)?;

        let did_method_key = &request.did_method;
        let did_method = self
            .did_method_provider
            .get_did_method(did_method_key)
            .ok_or(MissingProviderError::DidMethod(did_method_key.to_owned()))?;

        validate_request_amount_of_keys(did_method.deref(), request.keys.to_owned())?;

        let Some(organisation) = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
            .await?
        else {
            return Err(BusinessLogicError::MissingOrganisation(request.organisation_id).into());
        };

        if organisation.deactivated_at.is_some() {
            return Err(
                BusinessLogicError::OrganisationIsDeactivated(request.organisation_id).into(),
            );
        }

        let keys = request.keys.to_owned();

        let key_ids = HashSet::<KeyId>::from_iter(
            [
                keys.authentication,
                keys.assertion_method,
                keys.key_agreement,
                keys.capability_invocation,
                keys.capability_delegation,
            ]
            .concat(),
        );

        let key_ids = key_ids.into_iter().collect::<Vec<_>>();
        let keys = self.key_repository.get_keys(&key_ids).await?;

        let new_id = Uuid::new_v4();
        let new_did_id = DidId::from(new_id);

        let capabilities = did_method.get_capabilities();
        for key in &keys {
            if key.is_remote() {
                return Err(ValidationError::KeyMustNotBeRemote(key.name.clone()).into());
            }
            let key_algorithm = key
                .key_algorithm_type()
                .and_then(|alg| self.key_algorithm_provider.key_algorithm_from_type(alg))
                .ok_or(ValidationError::InvalidKeyAlgorithm(
                    key.key_type.to_owned(),
                ))?;

            if !capabilities
                .key_algorithms
                .contains(&key_algorithm.algorithm_type())
            {
                return Err(BusinessLogicError::DidMethodIncapableKeyAlgorithm {
                    key_algorithm: key.key_type.to_owned(),
                }
                .into());
            }
        }

        let mut keys = build_keys_request(&request.keys, keys)?;

        let mut update_keys = None;
        if let Some(update_key_type) = capabilities.supported_update_key_types.first() {
            let update_key = generate_update_key(
                &request.name,
                new_did_id,
                organisation.clone(),
                *update_key_type,
                &*self.key_provider,
            )
            .await?;

            update_keys = Some(vec![update_key]);
            keys.update_keys = update_keys.clone();
        }

        let did_value = did_method
            .create(Some(new_did_id), &request.params, Some(keys.clone()))
            .await?;

        if let Some(update_keys) = update_keys {
            for key in update_keys {
                self.key_repository.create_key(key).await?;
            }
        }

        let now = OffsetDateTime::now_utc();
        let did = did_from_did_request(new_did_id, request, organisation, did_value, keys, now);
        let did_value = did.did.clone();

        self.did_repository
            .create_did(did.to_owned())
            .await
            .map_err(|err| match err {
                DataLayerError::AlreadyExists => {
                    ServiceError::from(BusinessLogicError::DidValueAlreadyExists(did_value))
                }
                err => ServiceError::from(err),
            })?;

        Ok((did, now))
    }

    pub async fn update_did(
        &self,
        id: &DidId,
        request: DidPatchRequestDTO,
    ) -> Result<(), ServiceError> {
        let did = self
            .did_repository
            .get_did(
                id,
                &DidRelations {
                    organisation: Some(Default::default()),
                    keys: Some(Default::default()),
                },
            )
            .await?;

        let Some(did) = did else {
            return Err(EntityNotFoundError::Did(*id).into());
        };

        let did_method_key = &did.did_method;
        let did_method = self
            .did_method_provider
            .get_did_method(did_method_key)
            .ok_or(MissingProviderError::DidMethod(did_method_key.to_owned()))?;

        if let Some(deactivated) = request.deactivated {
            validate_deactivation_request(&did, did_method.as_ref(), deactivated)?;
            let keys = map_did_to_did_keys(&did)?;
            let update = did_method.deactivate(did.id, keys, did.log).await?;
            self.did_repository
                .update_did(did_update_to_update_request(did.id, update))
                .await?;

            let identifier = self
                .identifier_repository
                .get_from_did_id(did.id, &Default::default())
                .await?
                .ok_or(ServiceError::MappingError(
                    "No identifier for this did exists".to_string(),
                ))?;

            self.identifier_repository
                .update(
                    &identifier.id,
                    UpdateIdentifierRequest {
                        state: Some(if deactivated {
                            IdentifierState::Deactivated
                        } else {
                            IdentifierState::Active
                        }),
                        ..Default::default()
                    },
                )
                .await?;
        }

        Ok(())
    }

    pub async fn resolve_did(
        &self,
        did: &DidValue,
    ) -> Result<DidDocumentDTO, DidMethodProviderError> {
        self.did_method_provider.resolve(did).await.map(Into::into)
    }
}

fn build_keys_request(
    request: &CreateDidRequestKeysDTO,
    keys: Vec<Key>,
) -> Result<DidKeys, ServiceError> {
    let mut create_keys = DidKeys {
        authentication: vec![],
        assertion_method: vec![],
        key_agreement: vec![],
        capability_invocation: vec![],
        capability_delegation: vec![],
        update_keys: None,
    };

    for key in keys {
        let mut in_any = false;
        let key_id = key.id;
        if request.authentication.contains(&key_id) {
            create_keys.authentication.push(key.clone());
            in_any = true;
        }

        if request.assertion_method.contains(&key_id) {
            create_keys.assertion_method.push(key.clone());
            in_any = true;
        }

        if request.key_agreement.contains(&key_id) {
            create_keys.key_agreement.push(key.clone());
            in_any = true;
        }

        if request.capability_delegation.contains(&key_id) {
            create_keys.capability_delegation.push(key.clone());
            in_any = true;
        }

        if request.capability_invocation.contains(&key_id) {
            create_keys.capability_invocation.push(key);
            in_any = true;
        }

        if !in_any {
            return Err(ServiceError::EntityNotFound(EntityNotFoundError::Key(
                key_id,
            )));
        }
    }

    Ok(create_keys)
}

async fn generate_update_key(
    did_name: &str,
    did_id: DidId,
    organisation: Organisation,
    update_key_type: KeyAlgorithmType,
    key_provider: &dyn KeyProvider,
) -> Result<Key, ServiceError> {
    let key_storage_type = KeyStorageType::Internal;
    let key_storage = key_provider
        .get_key_storage(key_storage_type.as_ref())
        .ok_or_else(|| {
            DidMethodError::CouldNotCreate(format!(
                "Missing {key_storage_type} storage type for generating update keys"
            ))
        })?;

    let key_id = Uuid::new_v4().into();
    let key = key_storage
        .generate(key_id, update_key_type)
        .await
        .map_err(|err| {
            DidMethodError::CouldNotCreate(format!("Failed generating update keys: {err}"))
        })?;
    let key = Key {
        id: key_id,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        public_key: key.public_key,
        name: format!("{did_name}-{did_id}"),
        key_reference: key.key_reference,
        storage_type: key_storage_type.to_string(),
        key_type: update_key_type.to_string(),
        organisation: Some(organisation.clone()),
    };

    Ok(key)
}
