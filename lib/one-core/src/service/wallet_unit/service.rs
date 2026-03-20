use std::str::FromStr;
use std::sync::Arc;

use one_dto_mapper::convert_inner;
use shared_types::{HolderWalletUnitId, WalletUnitId};
use standardized_types::jwk::PublicJwk;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use super::WalletUnitService;
use super::dto::{
    HolderRegisterWalletUnitRequestDTO, HolderWalletUnitRegisterResponseDTO,
    HolderWalletUnitResponseDTO, NoncePayload,
};
use super::error::HolderWalletUnitError;
use super::mapper::key_from_generated_key;
use crate::config::core_config::{KeyAlgorithmType, KeyStorageType};
use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, ErrorCodeMixinExt};
use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::model::holder_wallet_unit::{
    CreateHolderWalletUnitRequest, HolderWalletUnitRelations, UpdateHolderWalletUnitRequest,
};
use crate::model::key::{Key, KeyRelations};
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::model::wallet_unit::{WalletUnitOs, WalletUnitStatus};
use crate::model::wallet_unit_attestation::WalletUnitAttestationRelations;
use crate::proto::jwt::model::JWTPayload;
use crate::proto::jwt::{Jwt, JwtPublicKeyInfo, TokenError};
use crate::proto::session_provider::SessionExt;
use crate::proto::wallet_unit::WalletUnitStatusCheckResponse;
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::key_storage::KeyStorage;
use crate::provider::key_storage::error::KeyStorageError;
use crate::repository::error::DataLayerError;
use crate::service::error::MissingProviderError;
use crate::service::wallet_provider::dto::{
    ActivateWalletUnitRequestDTO, RegisterWalletUnitRequestDTO, RegisterWalletUnitResponseDTO,
};
use crate::validator::throw_if_org_not_matching_session;

impl WalletUnitService {
    pub async fn holder_register(
        &self,
        request: HolderRegisterWalletUnitRequestDTO,
    ) -> Result<HolderWalletUnitRegisterResponseDTO, HolderWalletUnitError> {
        throw_if_org_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("checking session")?;
        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
            .await
            .error_while("getting organisation")?
            .ok_or(HolderWalletUnitError::MissingOrganisation(
                request.organisation_id,
            ))?;

        if organisation.deactivated_at.is_some() {
            return Err(HolderWalletUnitError::OrganisationIsDeactivated(
                request.organisation_id,
            ));
        }

        if let Some(wallet_unit) = self
            .holder_wallet_unit_repository
            .get_holder_wallet_unit_by_org_id(&request.organisation_id)
            .await
            .error_while("checking presence of wallet unit")?
        {
            return Err(HolderWalletUnitError::WalletUnitAlreadyExists(
                wallet_unit.id,
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
            .filter(|(_, v)| v.enabled && v.r#type == key_storage_type)
            .map(|(k, _)| k)
            .next()
            .ok_or(MissingProviderError::KeyStorage(format!(
                "No enabled key storage of type {key_storage_type}"
            )))
            .error_while("finding key storage")?;

        let key_type = KeyAlgorithmType::from_str(&request.key_type)
            .map_err(|err| HolderWalletUnitError::InvalidKeyAlgorithm(err.to_string()))?;

        // Ensure the key type is known and enabled
        if let Some(key_algorithm) = self.config.key_algorithm.get(&key_type) {
            if !key_algorithm.enabled {
                return Err(HolderWalletUnitError::InvalidKeyAlgorithm(
                    request.key_type.clone(),
                ));
            }
        } else {
            return Err(HolderWalletUnitError::InvalidKeyAlgorithm(
                request.key_type.clone(),
            ));
        }

        let wallet_provider_url = Url::from_str(&request.wallet_provider.url)
            .map_err(HolderWalletUnitError::InvalidWalletProviderUrl)?
            .origin()
            .ascii_serialization();
        let metadata = self
            .wallet_provider_client
            .get_wallet_provider_metadata(&request.wallet_provider.url)
            .await
            .error_while("getting wallet provider metadata")?;
        let provider_info = WalletProviderInfo {
            name: metadata.name.clone(),
            url: wallet_provider_url.clone(),
        };

        let registration = if metadata
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

        let status = if registration.key.is_some() {
            WalletUnitStatus::Active
        } else {
            WalletUnitStatus::Unattested
        };
        let wallet_unit_request = CreateHolderWalletUnitRequest {
            id: Uuid::new_v4().into(),
            status,
            wallet_provider_url,
            wallet_provider_type: request.wallet_provider.r#type.clone(),
            wallet_provider_name: metadata.name,
            organisation: organisation.clone(),
            authentication_key: registration.key,
            provider_wallet_unit_id: registration.wallet_unit_id,
        };
        let holder_wallet_unit_id = self
            .holder_wallet_unit_repository
            .create_holder_wallet_unit(wallet_unit_request)
            .await
            .error_while("creating holder wallet unit")?;

        let now = self.clock.now_utc();
        let wallet_unit_name = format!(
            "{}-{}-{}",
            request.wallet_provider.r#type,
            os,
            now.unix_timestamp()
        );
        let success_log = format!(
            "Registered wallet unit `{wallet_unit_name}`({holder_wallet_unit_id}) using wallet provider `{}`, with status {status}",
            request.wallet_provider.url
        );
        self.history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: now,
                action: HistoryAction::Created,
                name: wallet_unit_name,
                source: HistorySource::Core,
                target: None,
                entity_id: Some(holder_wallet_unit_id.into()),
                entity_type: HistoryEntityType::WalletUnit,
                metadata: None,
                organisation_id: Some(organisation.id),
                user: self.session_provider.session().user(),
            })
            .await
            .error_while("creating history")?;

        self.trust_collection_manager
            .create_empty_trust_collections(
                &request.wallet_provider.url,
                convert_inner(metadata.trust_collections),
                organisation.id,
            )
            .await
            .error_while("creating empty trust collections")?;

        tracing::info!(message = success_log);
        Ok(HolderWalletUnitRegisterResponseDTO {
            id: holder_wallet_unit_id,
            status,
        })
    }

    pub async fn holder_get_wallet_unit_details(
        &self,
        id: HolderWalletUnitId,
    ) -> Result<HolderWalletUnitResponseDTO, HolderWalletUnitError> {
        let result = self
            .holder_wallet_unit_repository
            .get_holder_wallet_unit(
                &id,
                &HolderWalletUnitRelations {
                    authentication_key: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .error_while("getting holder wallet unit")?
            .ok_or(HolderWalletUnitError::HolderWalletUnitNotFound(id))?;

        Ok(result.into())
    }

    pub async fn holder_wallet_unit_status(
        &self,
        id: HolderWalletUnitId,
    ) -> Result<(), HolderWalletUnitError> {
        let holder_wallet_unit = self
            .holder_wallet_unit_repository
            .get_holder_wallet_unit(
                &id,
                &HolderWalletUnitRelations {
                    authentication_key: Some(KeyRelations::default()),
                    wallet_unit_attestations: Some(WalletUnitAttestationRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .error_while("getting holder wallet unit")?
            .ok_or(HolderWalletUnitError::HolderWalletUnitNotFound(id))?;

        if holder_wallet_unit.status != WalletUnitStatus::Active {
            return Ok(());
        }

        let wallet_unit_status = self
            .wallet_unit_proto
            .check_wallet_unit_status(&holder_wallet_unit)
            .await
            .error_while("checking wallet unit status")?;

        if wallet_unit_status == WalletUnitStatusCheckResponse::Revoked {
            self.holder_wallet_unit_repository
                .update_holder_wallet_unit(
                    &id,
                    UpdateHolderWalletUnitRequest {
                        status: Some(WalletUnitStatus::Revoked),
                        ..Default::default()
                    },
                )
                .await
                .error_while("updating holder wallet unit")?;

            self.history_repository
                .create_history(History {
                    id: Uuid::new_v4().into(),
                    action: HistoryAction::Revoked,
                    name: holder_wallet_unit.wallet_provider_name.clone(),
                    source: HistorySource::Core,
                    target: None,
                    entity_id: Some(id.into()),
                    entity_type: HistoryEntityType::WalletUnit,
                    metadata: None,
                    organisation_id: holder_wallet_unit.organisation.map(|o| o.id),
                    user: self.session_provider.session().user(),
                    created_date: self.clock.now_utc(),
                })
                .await
                .error_while("creating history")?;
        }
        Ok(())
    }

    async fn register_without_integrity_check(
        &self,
        provider_info: &WalletProviderInfo,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        os: WalletUnitOs,
        organisation: Organisation,
    ) -> Result<Registration, HolderWalletUnitError> {
        let key_storage = self
            .key_provider
            .get_key_storage(key_storage_id)
            .ok_or(MissingProviderError::KeyStorage(key_storage_id.to_string()))
            .error_while("getting key storage")?;

        let key = self
            .new_key(key_storage_id, key_type, organisation, &key_storage)
            .await?;

        let key_handle = key_storage
            .key_handle(&key)
            .error_while("getting key handle")?;

        let auth_fn = self
            .key_provider
            .get_signature_provider(&key, None, self.key_algorithm_provider.clone())
            .error_while("getting signature provider")?;
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
            public_key: Some(key_handle.public_key_as_jwk().error_while("creating JWK")?),
            proof: Some(signed_proof),
        };

        let register_response = self
            .register(&provider_info.url, register_request)
            .await
            .error_while("registering")?;
        Ok(Registration {
            wallet_unit_id: register_response.id,
            key: Some(key),
        })
    }

    async fn register_with_integrity_check(
        &self,
        provider_info: &WalletProviderInfo,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        os: WalletUnitOs,
        organisation: Organisation,
    ) -> Result<Registration, HolderWalletUnitError> {
        let register_request = RegisterWalletUnitRequestDTO {
            wallet_provider: provider_info.name.clone(),
            os,
            public_key: None,
            proof: None,
        };
        let register_response = self
            .register(&provider_info.url, register_request)
            .await
            .error_while("registering")?;

        let Some(nonce) = register_response.nonce else {
            // integrity check was expected, but is not required
            return Err(HolderWalletUnitError::AppIntegrityCheckNotRequired);
        };

        let key_storage = self
            .key_provider
            .get_key_storage(key_storage_id)
            .ok_or(MissingProviderError::KeyStorage(key_storage_id.to_string()))
            .error_while("getting key storage")?;

        let key_id = Uuid::new_v4().into();
        let attestation_key = match key_storage
            .generate_attestation_key(key_id, Some(nonce.clone()))
            .await
        {
            Ok(key) => key,
            Err(KeyStorageError::NotSupported(description)) => {
                tracing::info!("Attestation keys not supported: {description}");
                return Ok(Registration {
                    wallet_unit_id: register_response.id,
                    key: None,
                });
            }
            Err(err) => {
                return Err(err.error_while("getting attestation key").into());
            }
        };
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
            .await
            .error_while("getting attestation")?;

        // Use SignatureProvider that uses the attestation key and the key_storage.sign_with_attestation_key method
        let auth_fn = self
            .key_provider
            .get_attestation_signature_provider(
                &attestation_key,
                None,
                self.key_algorithm_provider.clone(),
            )
            .error_while("getting attestation signature provider")?;
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
                .error_while("getting key handle")?;

            let auth_fn = self
                .key_provider
                .get_signature_provider(
                    &device_signing_key,
                    None,
                    self.key_algorithm_provider.clone(),
                )
                .error_while("getting signature provider")?;
            let signed_proof = self
                .create_device_signing_key_pop(
                    self.clock.now_utc(),
                    auth_fn,
                    key_handle.public_key_as_jwk().error_while("creating JWK")?,
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

        match self
            .wallet_provider_client
            .activate(&provider_info.url, register_response.id, activate_request)
            .await
        {
            Ok(_) => {}
            Err(err) if err.error_code() == ErrorCode::BR_0395 => {
                tracing::warn!("Activation request failed: {err}");
                return Ok(Registration {
                    wallet_unit_id: register_response.id,
                    key: None,
                });
            }
            Err(err) => return Err(err.error_while("activating wallet unit").into()),
        };

        Ok(Registration {
            wallet_unit_id: register_response.id,
            key: Some(device_sig_key.unwrap_or(attestation_key)),
        })
    }

    async fn new_key(
        &self,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        organisation: Organisation,
        key_storage: &Arc<dyn KeyStorage>,
    ) -> Result<Key, HolderWalletUnitError> {
        let key_id = Uuid::new_v4().into();
        let key = key_storage
            .generate(key_id, key_type)
            .await
            .error_while("generating key")?;
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
        Ok(self
            .wallet_provider_client
            .register(url, register_request)
            .await
            .error_while("registering wallet unit")?)
    }

    async fn store_key(&self, key: &Key) -> Result<(), HolderWalletUnitError> {
        self.key_repository
            .create_key(key.clone())
            .await
            .map_err(|err| match err {
                DataLayerError::AlreadyExists => HolderWalletUnitError::KeyAlreadyExists,
                err => err.error_while("creating key").into(),
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
    ) -> Result<String, HolderWalletUnitError> {
        let proof = Jwt::new(
            "jwt".to_string(),
            auth_fn
                .jose_alg()
                .ok_or(TokenError::MissingJOSEAlgorithm(
                    "No JOSE alg specified".to_string(),
                ))
                .error_while("preparing key possession proof header")?,
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

        let signed_proof = proof
            .tokenize(Some(&*auth_fn))
            .await
            .error_while("creating key possession proof token")?;
        Ok(signed_proof)
    }

    async fn create_device_signing_key_pop(
        &self,
        now: OffsetDateTime,
        auth_fn: AuthenticationFn,
        public_key: PublicJwk,
        wallet_provider_name: &str,
        audience: &str,
        nonce: String,
    ) -> Result<String, HolderWalletUnitError> {
        let proof = Jwt::new(
            "jwt".to_string(),
            auth_fn
                .jose_alg()
                .ok_or(TokenError::MissingJOSEAlgorithm(
                    "No JOSE alg specified".to_string(),
                ))
                .error_while("preparing device signing key POP header")?,
            None,
            Some(JwtPublicKeyInfo::Jwk(public_key)),
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

        let signed_proof = proof
            .tokenize(Some(&*auth_fn))
            .await
            .error_while("creating device signing proof token")?;
        Ok(signed_proof)
    }
}

struct WalletProviderInfo {
    name: String,
    url: String,
}

struct Registration {
    wallet_unit_id: WalletUnitId,
    key: Option<Key>,
}
