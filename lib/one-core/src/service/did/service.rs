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
    validator::did_already_exists,
    DidDeactivationError, DidService,
};
use crate::model::key::Key;
use crate::service::did::mapper::map_did_model_to_did_web_response;
use crate::service::did::mapper::map_key_to_verification_method;
use crate::service::did::validator::{throw_if_did_method_deactivated, throw_if_did_method_not_eq};
use crate::{
    config::validator::did::validate_did_method,
    model::{
        did::{DidListQuery, DidRelations, UpdateDidRequest},
        key::{KeyId, KeyRelations},
        organisation::OrganisationRelations,
    },
    service::{did::validator::validate_request_only_one_key_of_each_type, error::ServiceError},
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
        let result = self
            .did_repository
            .get_did(
                id,
                &DidRelations {
                    keys: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .map_err(ServiceError::from)?;

        throw_if_did_method_not_eq(&result, "WEB")?;
        throw_if_did_method_deactivated(&result)?;

        let mut grouped_key: HashMap<KeyId, Key> = HashMap::new();
        let keys = result
            .keys
            .as_ref()
            .ok_or(ServiceError::MappingError("No keys found".to_string()))?;
        for key in keys {
            grouped_key.insert(key.key.id, key.key.clone());
        }
        map_did_model_to_did_web_response(
            &result,
            keys,
            &grouped_key
                .iter()
                .enumerate()
                .map(|(index, (key, value))| {
                    let key_algorithm = self
                        .key_algorithm_provider
                        .get_key_algorithm(&value.key_type)
                        .map_err(|e| ServiceError::MappingError(e.to_string()))?;
                    Ok((
                        key.to_owned(),
                        map_key_to_verification_method(
                            index,
                            &result.did,
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
        let result = self
            .did_repository
            .get_did(
                id,
                &DidRelations {
                    organisation: Some(OrganisationRelations::default()),
                    keys: Some(KeyRelations::default()),
                },
            )
            .await
            .map_err(ServiceError::from)?;
        result.try_into()
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
        let result = self
            .did_repository
            .get_did_list(query)
            .await
            .map_err(ServiceError::from)?;
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

        let did_method = self
            .did_method_provider
            .get_did_method(&request.did_method)?;

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
            .ok_or(ServiceError::IncorrectParameters)?
            .to_owned();
        let key = self
            .key_repository
            .get_key(&key_id, &KeyRelations::default())
            .await?;

        let new_did_id = DidId::from(Uuid::new_v4());

        let did_value = did_method
            .create(&new_did_id, &request.params, &Some(key.clone()))
            .await
            .map_err(ServiceError::from)?;

        if did_already_exists(&self.did_repository, &did_value).await? {
            return Err(ServiceError::AlreadyExists);
        }

        let now = OffsetDateTime::now_utc();
        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
            .await?;
        let did = did_from_did_request(new_did_id, request, organisation, did_value, key, now)?;

        let did_id = self
            .did_repository
            .create_did(did)
            .await
            .map_err(ServiceError::from)?;

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
            .await
            .map_err(ServiceError::from)?;

        let did_method = self.did_method_provider.get_did_method(&did.did_method)?;

        if let Some(deactivated) = request.deactivated {
            if did.did_type.is_remote() {
                return Err(DidDeactivationError::RemoteDid.into());
            }

            if !did_method.can_be_deactivated() {
                return Err(DidDeactivationError::CannotBeDeactivated {
                    method: did.did_method,
                }
                .into());
            }

            if deactivated == did.deactivated {
                return Err(DidDeactivationError::DeactivatedSameValue {
                    value: did.deactivated,
                    method: did.did_method,
                }
                .into());
            }
        }

        let update_did = UpdateDidRequest {
            id: did.id,
            deactivated: request.deactivated,
        };
        self.did_repository.update_did(update_did).await?;

        Ok(())
    }
}
