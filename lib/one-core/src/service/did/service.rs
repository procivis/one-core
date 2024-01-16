use std::collections::{HashMap, HashSet};

use shared_types::DidId;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    dto::{
        CreateDidRequestDTO, DidPatchRequestDTO, DidResponseDTO, DidWebResponseDTO,
        GetDidListResponseDTO,
    },
    mapper::did_from_did_request,
    validator::{did_already_exists, validate_deactivation_request},
    DidService,
};
use crate::service::{did::mapper::map_key_to_verification_method, error::MissingProviderError};
use crate::{
    config::validator::did::validate_did_method,
    model::{
        did::{DidListQuery, DidRelations, UpdateDidRequest},
        key::{KeyId, KeyRelations},
        organisation::OrganisationRelations,
    },
    service::{
        did::validator::validate_request_only_one_key_of_each_type,
        error::{ServiceError, ValidationError},
    },
};
use crate::{model::key::Key, service::error::EntityNotFoundError};
use crate::{
    repository::error::DataLayerError,
    service::{did::mapper::map_did_model_to_did_web_response, error::BusinessLogicError},
};

impl DidService {
    /// Returns did document for did:web
    ///
    /// # Arguments
    ///
    /// * `id` - Did uuid
    pub async fn get_did_web_document(
        &self,
        id: &DidId,
    ) -> Result<DidWebResponseDTO, ServiceError> {
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

        if did.did_method != "WEB" {
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
                .enumerate()
                .map(|(index, (key, value))| {
                    let key_algorithm = self
                        .key_algorithm_provider
                        .get_key_algorithm(&value.key_type)
                        .ok_or(MissingProviderError::KeyAlgorithm(
                            value.key_type.to_owned(),
                        ))?;
                    Ok((
                        key.to_owned(),
                        map_key_to_verification_method(
                            index,
                            &did.did,
                            key_algorithm.bytes_to_jwk(&value.public_key)?.try_into()?,
                        )?,
                    ))
                })
                .collect::<Result<HashMap<_, _>, ServiceError>>()?,
        )
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
    /// * `did_methods` -
    pub async fn create_did(&self, request: CreateDidRequestDTO) -> Result<DidId, ServiceError> {
        validate_did_method(&request.did_method, &self.config.did)?;
        validate_request_only_one_key_of_each_type(request.keys.to_owned())?;

        let did_method_key = &request.did_method;
        let did_method = self
            .did_method_provider
            .get_did_method(did_method_key)
            .ok_or(MissingProviderError::DidMethod(did_method_key.to_owned()))?;

        let keys = request.keys.to_owned();

        let key_ids = HashSet::<KeyId>::from_iter(
            [
                keys.authentication,
                keys.assertion,
                keys.key_agreement,
                keys.capability_invocation,
                keys.capability_delegation,
            ]
            .concat(),
        );

        let key_id = key_ids
            .into_iter()
            .collect::<Vec<_>>()
            .first()
            .ok_or(ValidationError::DidMissingKey)?
            .to_owned();
        let key = self
            .key_repository
            .get_key(&key_id, &KeyRelations::default())
            .await?;

        let Some(key) = key else {
            return Err(EntityNotFoundError::Key(key_id).into());
        };

        let new_did_id = DidId::from(Uuid::new_v4());

        if !did_method
            .get_capabilities()
            .key_algorithms
            .contains(&key.key_type)
        {
            return Err(BusinessLogicError::DidMethodIncapableKeyAlgorithm {
                key_algorithm: key.key_type.to_owned(),
            }
            .into());
        }

        let did_value = did_method
            .create(&new_did_id, &request.params, &Some(key.clone()))
            .await?;

        if did_already_exists(&self.did_repository, &did_value).await? {
            return Err(BusinessLogicError::DidValueAlreadyExists(did_value).into());
        }

        let now = OffsetDateTime::now_utc();
        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
            .await?;

        let Some(organisation) = organisation else {
            return Err(EntityNotFoundError::Organisation(request.organisation_id).into());
        };

        let did = did_from_did_request(new_did_id, request, organisation, did_value, key, now);
        let did_value = did.did.clone();

        let did_id = self
            .did_repository
            .create_did(did)
            .await
            .map_err(|err| match err {
                DataLayerError::AlreadyExists => {
                    ServiceError::from(BusinessLogicError::DidValueAlreadyExists(did_value))
                }
                err => ServiceError::from(err),
            })?;

        Ok(did_id)
    }

    pub async fn update_did(
        &self,
        id: &DidId,
        request: DidPatchRequestDTO,
    ) -> Result<(), ServiceError> {
        let did = self
            .did_repository
            .get_did(id, &DidRelations::default())
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
        }

        let update_did = UpdateDidRequest {
            id: did.id,
            deactivated: request.deactivated,
        };
        self.did_repository.update_did(update_did).await?;

        Ok(())
    }
}
