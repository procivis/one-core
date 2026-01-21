use std::str::FromStr;

use anyhow::Context;
use shared_types::{KeyId, OrganisationId};
use standardized_types::jwk::PrivateJwk;
use time::OffsetDateTime;
use uuid::Uuid;

use super::KeyService;
use super::dto::{GetKeyListResponseDTO, KeyRequestDTO};
use super::mapper::request_to_certificate_params;
use crate::config::core_config::KeyAlgorithmType;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::mapper::x509::SigningKeyAdapter;
use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::model::key::{KeyListQuery, KeyRelations};
use crate::model::organisation::OrganisationRelations;
use crate::proto::session_provider::SessionExt;
use crate::repository::error::DataLayerError;
use crate::service::error::ServiceError;
use crate::service::key::dto::{
    KeyGenerateCSRRequestDTO, KeyGenerateCSRResponseDTO, KeyResponseDTO,
};
use crate::service::key::error::KeyServiceError;
use crate::service::key::mapper::from_create_request;
use crate::service::key::validator::{validate_generate_request, validate_key_algorithm_for_csr};
use crate::validator::{
    throw_if_org_not_matching_session, throw_if_org_relation_not_matching_session,
};

impl KeyService {
    /// Returns details of a key
    ///
    /// # Arguments
    ///
    /// * `KeyId` - Id of an existing key
    pub async fn get_key(&self, key_id: &KeyId) -> Result<KeyResponseDTO, KeyServiceError> {
        let key = self
            .key_repository
            .get_key(
                key_id,
                &KeyRelations {
                    organisation: Some(OrganisationRelations::default()),
                },
            )
            .await
            .error_while("loading key")?;

        let Some(key) = key else {
            return Err(KeyServiceError::KeyNotFound(*key_id));
        };
        throw_if_org_relation_not_matching_session(
            key.organisation.as_ref(),
            &*self.session_provider,
        )
        .error_while("validating organisation")?;

        key.try_into()
    }

    /// Generates a new random key with data provided in arguments
    ///
    /// # Arguments
    ///
    /// * `request` - key data
    pub async fn create_key(&self, request: KeyRequestDTO) -> Result<KeyId, KeyServiceError> {
        throw_if_org_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("validating organisation")?;
        validate_generate_request(&request.key_type, &request.storage_type, &self.config)?;

        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
            .await
            .error_while("loading organisation from repository")?;

        let Some(organisation) = organisation else {
            return Err(KeyServiceError::MissingOrganisation(
                request.organisation_id,
            ));
        };

        if organisation.deactivated_at.is_some() {
            return Err(KeyServiceError::OrganisationDeactivated(
                request.organisation_id,
            ));
        }

        let provider = self
            .key_provider
            .get_key_storage(&request.storage_type)
            .ok_or(KeyServiceError::InvalidKeyStorage {
                key_storage: request.storage_type.to_string(),
            })?;

        let key_type = KeyAlgorithmType::from_str(&request.key_type).map_err(|_| {
            KeyServiceError::InvalidKeyAlgorithm {
                key_algorithm: request.key_type.to_string(),
            }
        })?;

        if !provider.get_capabilities().algorithms.contains(&key_type) {
            return Err(KeyServiceError::UnsupportedKeyType { key_type });
        }
        let (request, jwk) = extract_jwk(request).error_while("extracting jwk")?;
        let key_id = Uuid::new_v4().into();
        let key = match jwk {
            None => provider
                .generate(key_id, key_type)
                .await
                .error_while("generating key")?,
            Some(jwk) => provider
                .import(key_id, key_type, jwk)
                .await
                .error_while("importing key")?,
        };

        let key_entity = from_create_request(key_id, request, organisation, key);

        let uuid = self
            .key_repository
            .create_key(key_entity.to_owned())
            .await
            .map_err(|err| match err {
                DataLayerError::AlreadyExists => KeyServiceError::KeyAlreadyExists,
                err => err.error_while("creating key").into(),
            })?;

        tracing::info!(
            "Created key `{}` ({uuid}): storage provider `{}`, algorithm `{}`",
            key_entity.name,
            key_entity.storage_type,
            key_entity.key_type
        );
        Ok(uuid)
    }

    /// Returns list of keys according to query
    ///
    /// # Arguments
    ///
    /// * `query` - query parameters
    pub async fn get_key_list(
        &self,
        organisation_id: &OrganisationId,
        query: KeyListQuery,
    ) -> Result<GetKeyListResponseDTO, KeyServiceError> {
        throw_if_org_not_matching_session(organisation_id, &*self.session_provider)
            .error_while("validating organisation")?;
        let result = self
            .key_repository
            .get_key_list(query)
            .await
            .error_while("loading keys")?;

        Ok(result.into())
    }

    /// Returns x509 CSR of given key
    ///
    /// # Arguments
    ///
    /// * `KeyId` - Id of an existing key
    pub async fn generate_csr(
        &self,
        key_id: &KeyId,
        request: KeyGenerateCSRRequestDTO,
    ) -> Result<KeyGenerateCSRResponseDTO, KeyServiceError> {
        let key = self
            .key_repository
            .get_key(
                key_id,
                &KeyRelations {
                    organisation: Some(OrganisationRelations::default()),
                },
            )
            .await
            .error_while("loading key")?;

        let Some(key) = key else {
            return Err(KeyServiceError::KeyNotFound(*key_id));
        };
        throw_if_org_relation_not_matching_session(
            key.organisation.as_ref(),
            &*self.session_provider,
        )
        .error_while("validating organisation")?;
        validate_key_algorithm_for_csr(&key, &*self.key_algorithm_provider)?;

        let key_storage = self.key_provider.get_key_storage(&key.storage_type).ok_or(
            KeyServiceError::MissingKeyStorageProvider {
                key_storage: key.storage_type.clone(),
            },
        )?;
        let signing_key =
            SigningKeyAdapter::new(key.clone(), key_storage, tokio::runtime::Handle::current())
                .context("Failed creating remote key")?;

        let content = request_to_certificate_params(request)
            .serialize_request(&signing_key)
            .context("Failed creating CSR")?
            .pem()
            .context("CSR PEM conversion failed")?;

        tracing::info!("Created CSR for key `{}` ({})", key.name, key.id);

        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                action: HistoryAction::CsrGenerated,
                name: key.name,
                source: HistorySource::Core,
                target: None,
                entity_id: Some(key.id.into()),
                entity_type: HistoryEntityType::Key,
                metadata: None,
                organisation_id: Some(
                    key.organisation
                        .ok_or(KeyServiceError::MappingError(
                            "missing key organisation".to_string(),
                        ))?
                        .id,
                ),
                user: self.session_provider.session().user(),
            })
            .await;

        if let Err(err) = result {
            tracing::warn!("failed to insert key history event: {err:?}");
        }

        Ok(KeyGenerateCSRResponseDTO { content })
    }
}

fn extract_jwk(
    mut request: KeyRequestDTO,
) -> Result<(KeyRequestDTO, Option<PrivateJwk>), ServiceError> {
    let Some(raw_jwk) = request
        .storage_params
        .as_object_mut()
        .and_then(|obj| obj.remove("jwk"))
    else {
        return Ok((request, None));
    };

    serde_json::from_value::<PrivateJwk>(raw_jwk)
        .map(|jwk| (request, Some(jwk)))
        .map_err(|err| ServiceError::MappingError(format!("failed to decode jwk: {err}")))
}
