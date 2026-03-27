use std::collections::HashMap;

use shared_types::{DidId, DidValue, KeyId, OrganisationId};
use uuid::Uuid;

use super::DidService;
use super::dto::{
    CreateDidRequestDTO, CreateDidRequestKeysDTO, DidPatchRequestDTO, DidResponseDTO,
    GetDidListResponseDTO,
};
use super::error::DidServiceError;
use super::mapper::{
    did_update_to_update_request, map_did_model_to_did_web_response, map_did_to_did_keys,
};
use super::validator::validate_deactivation_request;
use crate::config::core_config::{KeyAlgorithmType, KeyStorageType};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::did::{DidListQuery, DidRelations, RelatedKey};
use crate::model::identifier::{IdentifierState, UpdateIdentifierRequest};
use crate::model::key::{Key, KeyRelations};
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::proto::identifier_creator::CreateLocalIdentifierRequest;
use crate::provider::did_method::DidKeys;
use crate::provider::did_method::common::jwk_verification_method;
use crate::provider::did_method::dto::DidDocumentDTO;
use crate::provider::key_algorithm::error::KeyAlgorithmProviderError;
use crate::provider::key_storage::provider::KeyProvider;
use crate::validator::{
    throw_if_org_not_matching_session, throw_if_org_relation_not_matching_session,
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
    ) -> Result<DidDocumentDTO, DidServiceError> {
        let did = self
            .did_repository
            .get_did(
                id,
                &DidRelations {
                    keys: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .error_while("getting did")?;

        let Some(did) = did else {
            return Err(DidServiceError::NotFound(*id));
        };

        if did.did.method() != "web" {
            return Err(DidServiceError::InvalidMethod {
                method: did.did_method,
            });
        }

        if did.deactivated {
            return Err(DidServiceError::Deactivated(did.id));
        }

        let mut grouped_key: HashMap<KeyId, RelatedKey> = HashMap::new();
        let keys = did
            .keys
            .as_ref()
            .ok_or(DidServiceError::MappingError("No keys found".to_string()))?;
        for key in keys {
            grouped_key.insert(key.key.id, key.to_owned());
        }
        map_did_model_to_did_web_response(
            &did,
            keys,
            &grouped_key
                .into_iter()
                .map(|(key_id, key)| {
                    let Some(key_type) = key.key.key_algorithm_type() else {
                        return Err(KeyAlgorithmProviderError::MissingAlgorithmImplementation(
                            key.key.key_type,
                        )
                        .error_while("getting key algorithm")
                        .into());
                    };

                    let jwk = self
                        .key_algorithm_provider
                        .reconstruct_key(key_type, &key.key.public_key, None, None)
                        .error_while("reconstructing key")?
                        .public_key_as_jwk()
                        .error_while("creating JWK")?;
                    Ok((
                        key_id,
                        jwk_verification_method(did.verification_method_id(&key), &did.did, jwk)
                            .into(),
                    ))
                })
                .collect::<Result<HashMap<_, _>, DidServiceError>>()?,
        )
    }

    /// Returns did log for did:webvh(did:tdw)
    ///
    /// # Arguments
    ///
    /// * `id` - Did uuid
    pub async fn get_did_webvh_log(&self, id: &DidId) -> Result<String, DidServiceError> {
        let did = self
            .did_repository
            .get_did(id, &DidRelations::default())
            .await
            .error_while("getting did")?;

        let Some(did) = did else {
            return Err(DidServiceError::NotFound(*id));
        };

        let Some(log) = did.log else {
            return Err(DidServiceError::InvalidMethod {
                method: did.did_method,
            });
        };
        Ok(log)
    }

    /// Returns details of a did
    ///
    /// # Arguments
    ///
    /// * `id` - Did uuid
    pub async fn get_did(&self, id: &DidId) -> Result<DidResponseDTO, DidServiceError> {
        let did = self
            .did_repository
            .get_did(
                id,
                &DidRelations {
                    organisation: Some(OrganisationRelations::default()),
                    keys: Some(KeyRelations::default()),
                },
            )
            .await
            .error_while("getting did")?;
        let Some(did) = did else {
            return Err(DidServiceError::NotFound(*id));
        };
        throw_if_org_relation_not_matching_session(
            did.organisation.as_ref(),
            &*self.session_provider,
        )
        .error_while("checking session")?;

        did.try_into()
    }

    /// Returns list of dids according to query
    ///
    /// # Arguments
    ///
    /// * `query` - query parameters
    pub async fn get_did_list(
        &self,
        organisation_id: &OrganisationId,
        query: DidListQuery,
    ) -> Result<GetDidListResponseDTO, DidServiceError> {
        throw_if_org_not_matching_session(organisation_id, &*self.session_provider)
            .error_while("checking session")?;
        let result = self
            .did_repository
            .get_did_list(query)
            .await
            .error_while("getting dids")?;
        Ok(result.into())
    }

    /// Creates a new did with data provided in arguments
    ///
    /// # Arguments
    ///
    /// * `request` - did data
    pub async fn create_did(&self, request: CreateDidRequestDTO) -> Result<DidId, DidServiceError> {
        throw_if_org_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("checking session")?;
        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &Default::default())
            .await
            .error_while("getting organisation")?
            .ok_or(DidServiceError::MissingOrganisation(
                request.organisation_id,
            ))?;

        if organisation.deactivated_at.is_some() {
            return Err(DidServiceError::OrganisationDeactivated(
                request.organisation_id,
            ));
        }

        let identifier = self
            .identifier_creator
            .create_local_identifier(
                request.name.to_owned(),
                CreateLocalIdentifierRequest::Did(request),
                organisation,
            )
            .await
            .error_while("creating local did identifier")?;

        let did = identifier
            .did
            .ok_or(DidServiceError::MappingError("Did not found".to_string()))?;

        tracing::info!(
            "Created did `{}` ({}): did method `{}`",
            did.name,
            did.id,
            did.did_method
        );
        Ok(did.id)
    }

    pub async fn update_did(
        &self,
        id: &DidId,
        request: DidPatchRequestDTO,
    ) -> Result<(), DidServiceError> {
        let did = self
            .did_repository
            .get_did(
                id,
                &DidRelations {
                    organisation: Some(Default::default()),
                    keys: Some(Default::default()),
                },
            )
            .await
            .error_while("getting did")?;

        let Some(did) = did else {
            return Err(DidServiceError::NotFound(*id));
        };
        throw_if_org_relation_not_matching_session(
            did.organisation.as_ref(),
            &*self.session_provider,
        )
        .error_while("checking session")?;

        let did_method_key = &did.did_method;
        let did_method = self
            .did_method_provider
            .get_did_method(did_method_key)
            .ok_or(DidServiceError::InvalidMethod {
                method: did_method_key.to_owned(),
            })?;

        if let Some(deactivated) = request.deactivated {
            validate_deactivation_request(&did, did_method.as_ref(), deactivated)?;
            let keys = map_did_to_did_keys(&did)?;
            let update = did_method
                .deactivate(did.id, keys, did.log)
                .await
                .error_while("deactivating DID")?;
            self.did_repository
                .update_did(did_update_to_update_request(did.id, update))
                .await
                .error_while("updating did")?;

            let identifier = self
                .identifier_repository
                .get_from_did_id(did.id, &Default::default())
                .await
                .error_while("getting identifier")?
                .ok_or(DidServiceError::MappingError(
                    "No identifier for this did exists".to_string(),
                ))?;

            let new_state = if deactivated {
                IdentifierState::Deactivated
            } else {
                IdentifierState::Active
            };
            self.identifier_repository
                .update(
                    &identifier.id,
                    UpdateIdentifierRequest {
                        state: Some(new_state),
                        ..Default::default()
                    },
                )
                .await
                .error_while("updating identifier")?;

            // Success log is only written if update request was not empty
            tracing::info!(
                "Updated did `{}` ({}): new state `{:?}`",
                did.name,
                did.id,
                new_state
            );
        }
        Ok(())
    }

    pub async fn resolve_did(&self, did: &DidValue) -> Result<DidDocumentDTO, DidServiceError> {
        Ok(self
            .did_method_provider
            .resolve(did)
            .await
            .error_while("resolving DID")?
            .into())
    }
}

pub(crate) fn build_keys_request(
    request: &CreateDidRequestKeysDTO,
    keys: Vec<Key>,
) -> Result<DidKeys, DidServiceError> {
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
            return Err(DidServiceError::MissingKey(key_id));
        }
    }

    Ok(create_keys)
}

pub(crate) async fn generate_update_key(
    did_name: &str,
    did_id: DidId,
    organisation: Organisation,
    update_key_type: KeyAlgorithmType,
    key_provider: &dyn KeyProvider,
) -> Result<Key, DidServiceError> {
    let key_storage_type = KeyStorageType::Internal;
    let key_storage = key_provider
        .get_key_storage(key_storage_type.as_ref())
        .ok_or(DidServiceError::InvalidKeyStorage(
            key_storage_type.to_string(),
        ))?;

    let key_id = Uuid::new_v4().into();
    let key = key_storage
        .generate(key_id, update_key_type)
        .await
        .error_while("generating key")?;
    let key = Key {
        id: key_id,
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        public_key: key.public_key,
        name: format!("{did_name}-{did_id}"),
        key_reference: key.key_reference,
        storage_type: key_storage_type.to_string(),
        key_type: update_key_type.to_string(),
        organisation: Some(organisation.clone()),
    };

    Ok(key)
}
