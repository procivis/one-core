use std::str::FromStr;
use std::sync::Arc;

use shared_types::{HolderWalletUnitId, WalletUnitId};
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use crate::config::core_config::{KeyAlgorithmType, KeyStorageType};
use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::model::holder_wallet_unit::HolderWalletUnit;
use crate::model::key::{Key, PublicKeyJwk};
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::model::wallet_unit::{WalletUnitOs, WalletUnitStatus};
use crate::proto::jwt::model::JWTPayload;
use crate::proto::jwt::{Jwt, JwtPublicKeyInfo};
use crate::proto::session_provider::SessionExt;
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_storage::KeyStorage;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::wallet_provider_client::error::WalletProviderClientError;
use crate::repository::error::DataLayerError;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError, ValidationError,
};
use crate::service::wallet_provider::dto::{
    ActivateWalletUnitRequestDTO, RegisterWalletUnitRequestDTO, RegisterWalletUnitResponseDTO,
};
use crate::service::wallet_unit::WalletUnitService;
use crate::service::wallet_unit::dto::{HolderRegisterWalletUnitRequestDTO, NoncePayload};
use crate::service::wallet_unit::error::HolderWalletUnitError;
use crate::service::wallet_unit::mapper::key_from_generated_key;
use crate::validator::throw_if_org_not_matching_session;

impl WalletUnitService {
    pub async fn holder_register(
        &self,
        request: HolderRegisterWalletUnitRequestDTO,
    ) -> Result<HolderWalletUnitId, ServiceError> {
        throw_if_org_not_matching_session(&request.organisation_id, &*self.session_provider)?;
        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
            .await?
            .ok_or(EntityNotFoundError::Organisation(request.organisation_id))?;

        if organisation.deactivated_at.is_some() {
            return Err(ServiceError::from(
                BusinessLogicError::OrganisationIsDeactivated(request.organisation_id),
            ));
        }

        let os = WalletUnitOs::from(self.os_info_provider.get_os_name().await);
        let key_storage_type = match os {
            WalletUnitOs::Android | WalletUnitOs::Ios => KeyStorageType::SecureElement,
            WalletUnitOs::Web => KeyStorageType::Internal,
        };
        let key_storage_id = self
            .config
            .key_storage
            .iter()
            .filter(|(_, v)| v.enabled.unwrap_or(true) && v.r#type == key_storage_type)
            .map(|(k, _)| k)
            .next()
            .ok_or(MissingProviderError::KeyStorage(format!(
                "No enabled key storage of type {key_storage_type}"
            )))?;

        let key_type = KeyAlgorithmType::from_str(&request.key_type).map_err(|err| {
            ServiceError::from(ValidationError::InvalidKeyAlgorithm(err.to_string()))
        })?;

        // Ensure the key type is known and enabled
        if let Some(key_algorithm) = self.config.key_algorithm.get(&key_type) {
            if !key_algorithm.enabled.unwrap_or(true) {
                return Err(ServiceError::from(ValidationError::InvalidKeyAlgorithm(
                    request.key_type.clone(),
                )));
            }
        } else {
            return Err(ServiceError::from(ValidationError::InvalidKeyAlgorithm(
                request.key_type.clone(),
            )));
        }

        let wallet_provider_url = Url::from_str(&request.wallet_provider.url)
            .map_err(|err| ValidationError::InvalidWalletProviderUrl(format!("{err}")))?
            .origin()
            .ascii_serialization();
        let metadata = self
            .wallet_provider_client
            .get_wallet_provider_metadata(&request.wallet_provider.url)
            .await
            .map_err(HolderWalletUnitError::from)?;
        let provider_info = WalletProviderInfo {
            name: metadata.name.clone(),
            url: wallet_provider_url.clone(),
        };

        let result = if metadata
            .wallet_unit_attestation
            .app_integrity_check_required
            && os != WalletUnitOs::Web
        {
            self.register_with_integrity_check(
                &provider_info,
                key_storage_id,
                key_type,
                os,
                organisation.clone(),
            )
            .await?
        } else {
            self.register_without_integrity_check(
                &provider_info,
                key_storage_id,
                key_type,
                os,
                organisation.clone(),
            )
            .await?
        };

        let now = self.clock.now_utc();
        let wallet_unit = HolderWalletUnit {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            status: WalletUnitStatus::Active,
            wallet_provider_url,
            wallet_provider_type: request.wallet_provider.r#type.clone(),
            wallet_provider_name: metadata.name,
            organisation: Some(organisation.clone()),
            authentication_key: Some(result.key),
            provider_wallet_unit_id: result.wallet_unit_id,
            wallet_unit_attestations: None,
        };

        let holder_wallet_unit_id = self
            .holder_wallet_unit_repository
            .create_holder_wallet_unit(wallet_unit)
            .await?;

        let wallet_unit_name = format!(
            "{}-{}-{}",
            request.wallet_provider.r#type,
            os,
            now.unix_timestamp()
        );

        self.history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: now,
                action: HistoryAction::Created,
                name: wallet_unit_name,
                target: None,
                entity_id: Some(holder_wallet_unit_id.into()),
                entity_type: HistoryEntityType::WalletUnitAttestation,
                metadata: None,
                organisation_id: Some(organisation.id),
                user: self.session_provider.session().user(),
            })
            .await?;
        Ok(holder_wallet_unit_id)
    }

    async fn register_without_integrity_check(
        &self,
        provider_info: &WalletProviderInfo,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        os: WalletUnitOs,
        organisation: Organisation,
    ) -> Result<Registration, ServiceError> {
        let key_storage = self
            .key_provider
            .get_key_storage(key_storage_id)
            .ok_or(MissingProviderError::KeyStorage(key_storage_id.to_string()))?;

        let key = self
            .new_key(key_storage_id, key_type, organisation, &key_storage)
            .await?;

        let key_handle = key_storage
            .key_handle(&key)
            .map_err(|e| ServiceError::KeyStorageError(KeyStorageError::SignerError(e)))?;

        let auth_fn = self.key_provider.get_signature_provider(
            &key,
            None,
            self.key_algorithm_provider.clone(),
        )?;
        let signed_proof = self
            .create_signed_key_possession_proof(
                self.clock.now_utc(),
                &provider_info.name,
                auth_fn,
                &provider_info.url,
                None,
            )
            .await?;

        let register_request = RegisterWalletUnitRequestDTO {
            wallet_provider: provider_info.name.clone(),
            os,
            public_key: Some(key_handle.public_key_as_jwk()?.into()),
            proof: Some(signed_proof),
        };

        let register_response = self.register(&provider_info.url, register_request).await?;
        Ok(Registration {
            wallet_unit_id: register_response.id,
            key,
        })
    }

    async fn register_with_integrity_check(
        &self,
        provider_info: &WalletProviderInfo,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        os: WalletUnitOs,
        organisation: Organisation,
    ) -> Result<Registration, ServiceError> {
        let register_request = RegisterWalletUnitRequestDTO {
            wallet_provider: provider_info.name.clone(),
            os,
            public_key: None,
            proof: None,
        };
        let register_response = self.register(&provider_info.url, register_request).await?;

        let Some(nonce) = register_response.nonce else {
            // integrity check was expected, but is not required
            return Err(HolderWalletUnitError::AppIntegrityCheckNotRequired.into());
        };

        let key_storage = self
            .key_provider
            .get_key_storage(key_storage_id)
            .ok_or(MissingProviderError::KeyStorage(key_storage_id.to_string()))?;

        let key_id = Uuid::new_v4().into();
        let attestation_key = key_storage
            .generate_attestation_key(key_id, Some(nonce.clone()))
            .await?;
        let attestation_key = key_from_generated_key(
            key_id,
            key_storage_id,
            key_type.as_ref(),
            organisation.clone(),
            attestation_key,
        );

        self.store_key(&attestation_key).await?;
        let attestation = key_storage
            .generate_attestation(&attestation_key, Some(nonce.clone()))
            .await?;

        // Use SignatureProvider that uses the attestation key and the key_storage.sign_with_attestation_key method
        let auth_fn = self.key_provider.get_attestation_signature_provider(
            &attestation_key,
            None,
            self.key_algorithm_provider.clone(),
        )?;
        let attestation_key_proof = self
            .create_signed_key_possession_proof(
                self.clock.now_utc(),
                &provider_info.name,
                auth_fn,
                &provider_info.url,
                Some(nonce.clone()),
            )
            .await?;

        let (device_sig_pop, device_sig_key) = if os == WalletUnitOs::Ios {
            let device_signing_key = self
                .new_key(key_storage_id, key_type, organisation, &key_storage)
                .await?;

            let key_handle = key_storage
                .key_handle(&device_signing_key)
                .map_err(|e| ServiceError::KeyStorageError(KeyStorageError::SignerError(e)))?;

            let auth_fn = self.key_provider.get_signature_provider(
                &device_signing_key,
                None,
                self.key_algorithm_provider.clone(),
            )?;
            let signed_proof = self
                .create_device_signing_key_pop(
                    self.clock.now_utc(),
                    auth_fn,
                    key_handle.public_key_as_jwk()?,
                    &provider_info.name,
                    &provider_info.url,
                    nonce,
                )
                .await?;
            (Some(signed_proof), Some(device_signing_key))
        } else {
            (None, None)
        };

        let activate_request = ActivateWalletUnitRequestDTO {
            attestation,
            attestation_key_proof,
            device_signing_key_proof: device_sig_pop,
        };

        self.wallet_provider_client
            .activate(&provider_info.url, register_response.id, activate_request)
            .await
            .map_err(HolderWalletUnitError::from)?;

        Ok(Registration {
            wallet_unit_id: register_response.id,
            key: device_sig_key.unwrap_or(attestation_key),
        })
    }

    async fn new_key(
        &self,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        organisation: Organisation,
        key_storage: &Arc<dyn KeyStorage>,
    ) -> Result<Key, ServiceError> {
        let key_id = Uuid::new_v4().into();
        let key = key_storage.generate(key_id, key_type).await?;
        let key =
            key_from_generated_key(key_id, key_storage_id, key_type.as_ref(), organisation, key);
        self.store_key(&key).await?;
        Ok(key)
    }

    async fn register(
        &self,
        url: &str,
        register_request: RegisterWalletUnitRequestDTO,
    ) -> Result<RegisterWalletUnitResponseDTO, HolderWalletUnitError> {
        self.wallet_provider_client
            .register(url, register_request)
            .await
            .map_err(|err| match err {
                WalletProviderClientError::Transport(_) => HolderWalletUnitError::from(err),
                WalletProviderClientError::IntegrityCheckRequired => {
                    HolderWalletUnitError::AppIntegrityCheckRequired
                }
                WalletProviderClientError::IntegrityCheckNotRequired => {
                    HolderWalletUnitError::AppIntegrityCheckNotRequired
                }
            })
    }

    async fn store_key(&self, key: &Key) -> Result<(), ServiceError> {
        self.key_repository
            .create_key(key.clone())
            .await
            .map_err(|err| match err {
                DataLayerError::AlreadyExists => {
                    ServiceError::from(BusinessLogicError::KeyAlreadyExists)
                }
                err => ServiceError::from(err),
            })?;
        Ok(())
    }

    async fn create_signed_key_possession_proof(
        &self,
        now: OffsetDateTime,
        wallet_provider_name: &str,
        auth_fn: AuthenticationFn,
        audience: &str,
        nonce: Option<String>,
    ) -> Result<String, ServiceError> {
        let proof = Jwt::new(
            "jwt".to_string(),
            auth_fn.jose_alg().ok_or(KeyAlgorithmError::Failed(
                "No JOSE alg specified".to_string(),
            ))?,
            auth_fn.get_key_id(),
            None,
            JWTPayload {
                issued_at: Some(now),
                expires_at: Some(now + Duration::minutes(60)),
                invalid_before: Some(now),
                issuer: None,
                subject: self
                    .base_url
                    .clone()
                    .map(|base_url| format!("{base_url}/{wallet_provider_name}")),
                audience: Some(vec![audience.to_owned()]),
                jwt_id: None,
                proof_of_possession_key: None,
                custom: NoncePayload { nonce },
            },
        );

        let signed_proof = proof.tokenize(Some(&*auth_fn)).await?;
        Ok(signed_proof)
    }

    async fn create_device_signing_key_pop(
        &self,
        now: OffsetDateTime,
        auth_fn: AuthenticationFn,
        public_key: PublicKeyJwk,
        wallet_provider_name: &str,
        audience: &str,
        nonce: String,
    ) -> Result<String, ServiceError> {
        let proof = Jwt::new(
            "jwt".to_string(),
            auth_fn.jose_alg().ok_or(KeyAlgorithmError::Failed(
                "No JOSE alg specified".to_string(),
            ))?,
            None,
            Some(JwtPublicKeyInfo::Jwk(public_key.into())),
            JWTPayload {
                issued_at: Some(now),
                expires_at: Some(now + Duration::minutes(60)),
                invalid_before: Some(now),
                issuer: None,
                subject: self
                    .base_url
                    .clone()
                    .map(|base_url| format!("{base_url}/{wallet_provider_name}")),
                audience: Some(vec![audience.to_owned()]),
                jwt_id: None,
                proof_of_possession_key: None,
                custom: NoncePayload { nonce: Some(nonce) },
            },
        );

        let signed_proof = proof.tokenize(Some(&*auth_fn)).await?;
        Ok(signed_proof)
    }
}

struct WalletProviderInfo {
    name: String,
    url: String,
}

struct Registration {
    wallet_unit_id: WalletUnitId,
    key: Key,
}
