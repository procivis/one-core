use std::sync::Arc;

use anyhow::{bail, Context};
use one_providers::common_models::key::OpenKey;
use one_providers::key_algorithm::imp::es256::Es256;
use one_providers::key_storage::KeyStorage;
use rcgen::{KeyPair, RemoteKeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ED25519};
use shared_types::KeyId;
use uuid::Uuid;

use super::mapper::request_to_certificate_params;
use super::{
    dto::{GetKeyListResponseDTO, GetKeyQueryDTO},
    KeyService,
};
use crate::model::history::{HistoryAction, HistoryEntityType};
use crate::model::key::KeyRelations;
use crate::service::error::MissingProviderError;
use crate::service::key::dto::{KeyGenerateCSRRequestDTO, KeyGenerateCSRResponseDTO};
use crate::service::key::validator::validate_generate_csr_request;
use crate::util::history::history_event;
use crate::{
    model::organisation::OrganisationRelations,
    repository::error::DataLayerError,
    service::{
        error::{BusinessLogicError, EntityNotFoundError, ServiceError, ValidationError},
        key::{
            dto::{KeyRequestDTO, KeyResponseDTO},
            mapper::from_create_request,
            validator::validate_generate_request,
        },
    },
};

impl KeyService {
    /// Returns details of a key
    ///
    /// # Arguments
    ///
    /// * `KeyId` - Id of an existing key
    pub async fn get_key(&self, key_id: &KeyId) -> Result<KeyResponseDTO, ServiceError> {
        let key = self
            .key_repository
            .get_key(
                &key_id.to_owned().into(),
                &KeyRelations {
                    organisation: Some(OrganisationRelations::default()),
                },
            )
            .await?;

        let Some(key) = key else {
            return Err(EntityNotFoundError::Key(key_id.to_owned()).into());
        };

        key.try_into()
    }

    /// Generates a new random key with data provided in arguments
    ///
    /// # Arguments
    ///
    /// * `request` - key data
    pub async fn generate_key(&self, request: KeyRequestDTO) -> Result<KeyId, ServiceError> {
        validate_generate_request(&request, &self.config)?;

        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
            .await?;

        let Some(organisation) = organisation else {
            return Err(BusinessLogicError::MissingOrganisation(request.organisation_id).into());
        };
        let organisation_id = organisation.id;

        let provider = self
            .key_provider
            .get_key_storage(&request.storage_type)
            .ok_or(ValidationError::InvalidKeyStorage(
                request.storage_type.clone(),
            ))?;

        let key_id = Uuid::new_v4().into();
        let key = provider.generate(Some(key_id), &request.key_type).await?;

        let key_entity = from_create_request(key_id, request, organisation.into(), key);

        let uuid = self
            .key_repository
            .create_key(key_entity.to_owned())
            .await
            .map_err(|err| match err {
                DataLayerError::AlreadyExists => {
                    ServiceError::from(BusinessLogicError::KeyAlreadyExists)
                }
                err => ServiceError::from(err),
            })?;

        let _ = self
            .history_repository
            .create_history(history_event(
                uuid,
                organisation_id,
                HistoryEntityType::Key,
                HistoryAction::Created,
            ))
            .await;

        Ok(uuid.into())
    }

    /// Returns list of keys according to query
    ///
    /// # Arguments
    ///
    /// * `query` - query parameters
    pub async fn get_key_list(
        &self,
        query: GetKeyQueryDTO,
    ) -> Result<GetKeyListResponseDTO, ServiceError> {
        let result = self.key_repository.get_key_list(query).await?;

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
    ) -> Result<KeyGenerateCSRResponseDTO, ServiceError> {
        let key = self
            .key_repository
            .get_key(
                &key_id.to_owned().into(),
                &KeyRelations {
                    organisation: Some(OrganisationRelations::default()),
                },
            )
            .await?;

        let Some(key) = key else {
            return Err(EntityNotFoundError::Key(key_id.to_owned()).into());
        };

        validate_generate_csr_request(&request, &key.key_type, &self.config.key_algorithm)?;

        let key_storage = self.key_provider.get_key_storage(&key.storage_type).ok_or(
            ServiceError::MissingProvider(MissingProviderError::KeyStorage(
                key.key_type.to_owned(),
            )),
        )?;
        let remote_key = RemoteKeyAdapter::create_remote_key(
            key,
            key_storage,
            tokio::runtime::Handle::current(),
        )
        .map_err(|err| ServiceError::Other(format!("Failed creating remote key {err}")))?;
        let key_pair = KeyPair::from_remote(remote_key).unwrap();

        let content = request_to_certificate_params(request)
            .serialize_request(&key_pair)
            .map_err(|err| ServiceError::Other(format!("Failed creating CSR: {err}")))?
            .pem()
            .map_err(|err| ServiceError::Other(format!("CSR PEM conversion failed: {err}")))?;

        Ok(KeyGenerateCSRResponseDTO { content })
    }
}

struct RemoteKeyAdapter {
    key: OpenKey,
    decompressed_public_key: Option<Vec<u8>>,
    key_storage: Arc<dyn KeyStorage>,
    algorithm: &'static rcgen::SignatureAlgorithm,
    handle: tokio::runtime::Handle,
}

impl RemoteKeyAdapter {
    fn create_remote_key(
        key: OpenKey,
        key_storage: Arc<dyn KeyStorage>,
        handle: tokio::runtime::Handle,
    ) -> anyhow::Result<Box<(dyn RemoteKeyPair + Send + Sync + 'static)>> {
        let mut decompressed_public_key = None;

        let algorithm = match key.key_type.as_str() {
            "ES256" => &PKCS_ECDSA_P256_SHA256,
            "EDDSA" => &PKCS_ED25519,
            other => bail!("Unsupported key type `{other}` for CSR"),
        };
        if algorithm == &PKCS_ECDSA_P256_SHA256 {
            decompressed_public_key = Some(
                Es256::decompress_public_key(&key.public_key)
                    .context("Key decompression failed")?,
            );
        }

        Ok(Box::new(Self {
            key,
            key_storage,
            algorithm,
            handle,
            decompressed_public_key,
        }) as _)
    }
}

impl rcgen::RemoteKeyPair for RemoteKeyAdapter {
    fn public_key(&self) -> &[u8] {
        self.decompressed_public_key
            .as_ref()
            .unwrap_or(&self.key.public_key)
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let _guard = self.handle.enter();

        futures::executor::block_on(async {
            self.key_storage
                .sign(&self.key.to_owned(), msg)
                .await
                .map_err(|error| {
                    tracing::error!(%error,  "Failed to sign CSR");
                    rcgen::Error::RemoteKeyError
                })
        })
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        self.algorithm
    }
}
