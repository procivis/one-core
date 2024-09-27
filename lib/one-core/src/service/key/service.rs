use std::sync::Arc;

use anyhow::{bail, Context};
use rcgen::{KeyPair, RemoteKeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ED25519};
use shared_types::KeyId;
use uuid::Uuid;

use super::dto::{GetKeyListResponseDTO, KeyCheckCertificateRequestDTO};
use super::mapper::request_to_certificate_params;
use super::KeyService;
use crate::model::history::{HistoryAction, HistoryEntityType};
use crate::model::key::{Key, KeyListQuery, KeyRelations};
use crate::model::organisation::OrganisationRelations;
use crate::provider::did_method::mdl::{parse_pem, parse_x509_from_der, parse_x509_from_pem};
use crate::provider::key_algorithm::es256::Es256;
use crate::provider::key_storage::KeyStorage;
use crate::repository::error::DataLayerError;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError, ValidationError,
};
use crate::service::key::dto::{
    KeyGenerateCSRRequestDTO, KeyGenerateCSRResponseDTO, KeyRequestDTO, KeyResponseDTO,
};
use crate::service::key::mapper::from_create_request;
use crate::service::key::validator::{validate_generate_csr_request, validate_generate_request};
use crate::util::history::history_event;

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
                key_id,
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

        let key_entity = from_create_request(key_id, request, organisation, key);

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

        Ok(uuid)
    }

    /// Returns list of keys according to query
    ///
    /// # Arguments
    ///
    /// * `query` - query parameters
    pub async fn get_key_list(
        &self,
        query: KeyListQuery,
    ) -> Result<GetKeyListResponseDTO, ServiceError> {
        let result = self.key_repository.get_key_list(query).await?;

        Ok(result.into())
    }

    /// Check certificate in PEM or DER format
    ///
    /// # Arguments
    ///
    /// * `KeyId` - Id of an existing key
    pub async fn check_certificate(
        &self,
        key_id: &KeyId,
        request: KeyCheckCertificateRequestDTO,
    ) -> Result<(), ServiceError> {
        let key = self
            .key_repository
            .get_key(
                key_id,
                &KeyRelations {
                    organisation: Some(OrganisationRelations::default()),
                },
            )
            .await?
            .ok_or(EntityNotFoundError::Key(key_id.to_owned()))?;

        if let Ok(pem) = parse_pem(&request.certificate) {
            let certificate = parse_x509_from_pem(&pem)?;
            self.did_mdl_validator
                .validate_subject_public_key(&certificate, &key)?;
            self.did_mdl_validator.validate_certificate(&certificate)?;
        } else {
            let certificate = parse_x509_from_der(request.certificate.as_bytes())?;
            self.did_mdl_validator
                .validate_subject_public_key(&certificate, &key)?;
            self.did_mdl_validator.validate_certificate(&certificate)?;
        };

        Ok(())
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
                key_id,
                &KeyRelations {
                    organisation: Some(OrganisationRelations::default()),
                },
            )
            .await?;

        let Some(key) = key else {
            return Err(EntityNotFoundError::Key(key_id.to_owned()).into());
        };

        validate_generate_csr_request(&request, &key.key_type, &*self.key_algorithm_provider)?;

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
    key: Key,
    decompressed_public_key: Option<Vec<u8>>,
    key_storage: Arc<dyn KeyStorage>,
    algorithm: &'static rcgen::SignatureAlgorithm,
    handle: tokio::runtime::Handle,
}

impl RemoteKeyAdapter {
    fn create_remote_key(
        key: Key,
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
        let handle = self.handle.clone();
        let key_storage = self.key_storage.clone();
        let key = self.key.clone();
        let msg = msg.to_vec();

        std::thread::spawn(move || {
            let _guard = handle.enter();
            let handle = tokio::spawn(async move {
                key_storage.sign(&key, &msg).await.map_err(|error| {
                    tracing::error!(%error, "Failed to sign CSR");
                    rcgen::Error::RemoteKeyError
                })
            });
            futures::executor::block_on(handle).map_err(|_| {
                tracing::error!("Failed to join CSR task");
                rcgen::Error::RemoteKeyError
            })?
        })
        .join()
        .map_err(|_| {
            tracing::error!("Failed to join CSR thread");
            rcgen::Error::RemoteKeyError
        })?
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        self.algorithm
    }
}
