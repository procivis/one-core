use std::str::FromStr;

use shared_types::{OrganisationId, WalletUnitId};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config::core_config::{KeyAlgorithmType, KeyStorageType};
use crate::mapper::list_response_into;
use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::model::key::{Key, KeyRelations};
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::model::wallet_unit::{
    WalletUnitClaims, WalletUnitListQuery, WalletUnitOs, WalletUnitRelations, WalletUnitStatus,
};
use crate::model::wallet_unit_attestation::{
    UpdateWalletUnitAttestationRequest, WalletUnitAttestation, WalletUnitAttestationRelations,
};
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::{DecomposedToken, JWTPayload};
use crate::proto::session_provider::SessionExt;
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::wallet_provider_client::dto::RefreshWalletUnitResponse;
use crate::provider::wallet_provider_client::error::WalletProviderClientError;
use crate::repository::error::DataLayerError;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError, ValidationError,
};
use crate::service::ssi_wallet_provider::dto::{
    ActivateWalletUnitRequestDTO, RefreshWalletUnitRequestDTO, RegisterWalletUnitRequestDTO,
    RegisterWalletUnitResponseDTO,
};
use crate::service::wallet_unit::WalletUnitService;
use crate::service::wallet_unit::dto::{
    GetWalletUnitListResponseDTO, GetWalletUnitResponseDTO, HolderRefreshWalletUnitRequestDTO,
    HolderRegisterWalletUnitRequestDTO, HolderRegisterWalletUnitResponseDTO,
    HolderWalletUnitAttestationResponseDTO,
};
use crate::service::wallet_unit::error::WalletUnitAttestationError;
use crate::service::wallet_unit::mapper::key_from_generated_key;
use crate::validator::{
    throw_if_org_not_matching_session, throw_if_org_relation_not_matching_session,
};

impl WalletUnitService {
    /// Returns details of a wallet unit
    ///
    /// # Arguments
    ///
    /// * `id` - Wallet unit uuid
    pub async fn get_wallet_unit(
        &self,
        id: &WalletUnitId,
    ) -> Result<GetWalletUnitResponseDTO, ServiceError> {
        let result = self
            .wallet_unit_repository
            .get_wallet_unit(
                id,
                &WalletUnitRelations {
                    organisation: Some(OrganisationRelations::default()),
                },
            )
            .await?
            .ok_or(EntityNotFoundError::WalletUnit(*id))?;
        throw_if_org_relation_not_matching_session(
            result.organisation.as_ref(),
            &*self.session_provider,
        )?;

        Ok(result.into())
    }

    /// Returns list of wallet units according to query
    ///
    /// # Arguments
    ///
    /// * `query` - query parameters
    pub async fn get_wallet_unit_list(
        &self,
        organisation_id: &OrganisationId,
        query: WalletUnitListQuery,
    ) -> Result<GetWalletUnitListResponseDTO, ServiceError> {
        throw_if_org_not_matching_session(organisation_id, &*self.session_provider)?;
        let result = self
            .wallet_unit_repository
            .get_wallet_unit_list(query)
            .await?;

        Ok(list_response_into(result))
    }

    pub async fn holder_register(
        &self,
        request: HolderRegisterWalletUnitRequestDTO,
    ) -> Result<HolderRegisterWalletUnitResponseDTO, ServiceError> {
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

        let result =
            if request.wallet_provider.app_integrity_check_required && os != WalletUnitOs::Web {
                self.register_with_integrity_check(
                    &request,
                    key_storage_id,
                    key_type,
                    os,
                    organisation.clone(),
                )
                .await?
            } else {
                self.register_without_integrity_check(
                    &request,
                    key_storage_id,
                    key_type,
                    os,
                    organisation.clone(),
                )
                .await?
            };

        let key_id = result.key.id;
        let attestation_token: DecomposedToken<WalletUnitClaims> =
            Jwt::decompose_token(&result.attestation)?;
        let now = self.clock.now_utc();
        let wallet_unit_attestation = WalletUnitAttestation {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            expiration_date: attestation_token
                .payload
                .expires_at
                .ok_or(ServiceError::MappingError("expires_at is None".to_string()))?,
            status: WalletUnitStatus::Active,
            attestation: result.attestation,
            wallet_unit_id: result.wallet_unit_id,
            wallet_provider_url: request.wallet_provider.url,
            wallet_provider_type: request.wallet_provider.r#type.clone(),
            wallet_provider_name: request.wallet_provider.name,
            organisation: Some(organisation.clone()),
            key: Some(result.key),
        };

        let wallet_unit_attestation_id = self
            .wallet_unit_attestation_repository
            .create_wallet_unit_attestation(wallet_unit_attestation)
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
                entity_id: Some(wallet_unit_attestation_id.into()),
                entity_type: HistoryEntityType::WalletUnitAttestation,
                metadata: None,
                organisation_id: Some(organisation.id),
                user: self.session_provider.session().user(),
            })
            .await?;
        Ok(HolderRegisterWalletUnitResponseDTO {
            id: result.wallet_unit_id,
            key_id,
        })
    }

    async fn register_without_integrity_check(
        &self,
        request: &HolderRegisterWalletUnitRequestDTO,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        os: WalletUnitOs,
        organisation: Organisation,
    ) -> Result<Registration, ServiceError> {
        let key_storage = self
            .key_provider
            .get_key_storage(key_storage_id)
            .ok_or(MissingProviderError::KeyStorage(key_storage_id.to_string()))?;

        let key_id = Uuid::new_v4().into();
        let key = key_storage.generate(key_id, key_type).await?;
        let key =
            key_from_generated_key(key_id, key_storage_id, key_type.as_ref(), organisation, key);

        self.store_key(&key).await?;

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
                &request.wallet_provider.name,
                auth_fn,
                &request.wallet_provider.url,
            )
            .await?;

        let register_request = RegisterWalletUnitRequestDTO {
            wallet_provider: request.wallet_provider.name.clone(),
            os,
            public_key: Some(key_handle.public_key_as_jwk()?.into()),
            proof: Some(signed_proof),
        };

        let register_response = self.register(&request, register_request).await?;

        let Some(attestation) = register_response.attestation else {
            // integrity check was not expected, but is required
            return Err(WalletUnitAttestationError::AppIntegrityCheckRequired.into());
        };

        Ok(Registration {
            wallet_unit_id: register_response.id,
            key,
            attestation,
        })
    }

    async fn register_with_integrity_check(
        &self,
        request: &HolderRegisterWalletUnitRequestDTO,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        os: WalletUnitOs,
        organisation: Organisation,
    ) -> Result<Registration, ServiceError> {
        let register_request = RegisterWalletUnitRequestDTO {
            wallet_provider: request.wallet_provider.name.clone(),
            os,
            public_key: None,
            proof: None,
        };
        let register_response = self.register(&request, register_request).await?;

        let Some(nonce) = register_response.nonce else {
            // integrity check was expected, but is not required
            return Err(WalletUnitAttestationError::AppIntegrityCheckNotRequired.into());
        };

        let key_storage = self
            .key_provider
            .get_key_storage(key_storage_id)
            .ok_or(MissingProviderError::KeyStorage(key_storage_id.to_string()))?;

        let key_id = Uuid::new_v4().into();
        let key = key_storage
            .generate_attestation_key(key_id, Some(nonce.clone()))
            .await?;
        let key =
            key_from_generated_key(key_id, key_storage_id, key_type.as_ref(), organisation, key);

        self.store_key(&key).await?;
        let attestation = key_storage.generate_attestation(&key, Some(nonce)).await?;

        // Use SignatureProvider that uses the attestation key and the key_storage.sign_with_attestation_key method
        let auth_fn = self.key_provider.get_attestation_signature_provider(
            &key,
            None,
            self.key_algorithm_provider.clone(),
        )?;
        let proof = self
            .create_signed_key_possession_proof(
                self.clock.now_utc(),
                &request.wallet_provider.name,
                auth_fn,
                &request.wallet_provider.url,
            )
            .await?;

        let activate_request = ActivateWalletUnitRequestDTO { attestation, proof };

        let activation_response = self
            .wallet_provider_client
            .activate(
                &request.wallet_provider.url,
                register_response.id,
                activate_request,
            )
            .await
            .map_err(WalletUnitAttestationError::from)?;

        Ok(Registration {
            wallet_unit_id: register_response.id,
            key,
            attestation: activation_response.attestation,
        })
    }

    async fn register(
        &self,
        request: &&HolderRegisterWalletUnitRequestDTO,
        register_request: RegisterWalletUnitRequestDTO,
    ) -> Result<RegisterWalletUnitResponseDTO, WalletUnitAttestationError> {
        self.wallet_provider_client
            .register(&request.wallet_provider.url, register_request)
            .await
            .map_err(|err| match err {
                WalletProviderClientError::Transport(_) => WalletUnitAttestationError::from(err),
                WalletProviderClientError::IntegrityCheckRequired => {
                    WalletUnitAttestationError::AppIntegrityCheckRequired
                }
                WalletProviderClientError::IntegrityCheckNotRequired => {
                    WalletUnitAttestationError::AppIntegrityCheckNotRequired
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

    pub async fn holder_refresh(
        &self,
        request: HolderRefreshWalletUnitRequestDTO,
    ) -> Result<(), ServiceError> {
        throw_if_org_not_matching_session(&request.organisation_id, &*self.session_provider)?;
        let wallet_unit_attestation: WalletUnitAttestation = self
            .wallet_unit_attestation_repository
            .get_wallet_unit_attestation_by_organisation(
                &request.organisation_id,
                &WalletUnitAttestationRelations {
                    key: Some(KeyRelations::default()),
                    organisation: Some(OrganisationRelations::default()),
                },
            )
            .await?
            .ok_or(EntityNotFoundError::WalletUnitAttestationByOrganisation(
                request.organisation_id,
            ))?;

        let Some(organisation) = wallet_unit_attestation.organisation else {
            return Err(ServiceError::MappingError(
                "organisation is None".to_string(),
            ));
        };

        let Some(key) = wallet_unit_attestation.key.as_ref() else {
            return Err(ServiceError::MappingError("key is None".to_string()));
        };

        if wallet_unit_attestation.status != WalletUnitStatus::Active {
            return Err(WalletUnitAttestationError::WalletUnitRevoked.into());
        }

        let os = WalletUnitOs::from(self.os_info_provider.get_os_name().await);

        let auth_fn = if request.app_integrity_check_required && os != WalletUnitOs::Web {
            self.key_provider.get_attestation_signature_provider(
                key,
                None,
                self.key_algorithm_provider.clone(),
            )?
        } else {
            self.key_provider.get_signature_provider(
                key,
                None,
                self.key_algorithm_provider.clone(),
            )?
        };

        let now = self.clock.now_utc();
        let signed_proof = self
            .create_signed_key_possession_proof(
                now,
                &wallet_unit_attestation.wallet_provider_name,
                auth_fn,
                &wallet_unit_attestation.wallet_provider_url,
            )
            .await?;

        let refresh_response = self
            .wallet_provider_client
            .refresh(
                &wallet_unit_attestation.wallet_provider_url,
                wallet_unit_attestation.wallet_unit_id,
                RefreshWalletUnitRequestDTO {
                    proof: signed_proof,
                },
            )
            .await
            .map_err(WalletUnitAttestationError::from)?;

        let wallet_unit_name = format!(
            "{}-{}-{}",
            wallet_unit_attestation.wallet_provider_type,
            self.os_info_provider.get_os_name().await,
            now.unix_timestamp()
        );

        match refresh_response {
            RefreshWalletUnitResponse::Active(refresh_response) => {
                let attestation_token: DecomposedToken<()> =
                    Jwt::decompose_token(&refresh_response.attestation)?;

                self.wallet_unit_attestation_repository
                    .update_wallet_attestation(
                        &wallet_unit_attestation.id,
                        UpdateWalletUnitAttestationRequest {
                            expiration_date: Some(attestation_token.payload.expires_at.ok_or(
                                ServiceError::MappingError("expires_at is None".to_string()),
                            )?),
                            attestation: Some(refresh_response.attestation),
                            ..Default::default()
                        },
                    )
                    .await?;

                self.history_repository
                    .create_history(History {
                        id: Uuid::new_v4().into(),
                        created_date: now,
                        action: HistoryAction::Updated,
                        name: wallet_unit_name,
                        target: None,
                        entity_id: Some(wallet_unit_attestation.id.into()),
                        entity_type: HistoryEntityType::WalletUnitAttestation,
                        metadata: None,
                        organisation_id: Some(organisation.id),
                        user: self.session_provider.session().user(),
                    })
                    .await?;
                Ok(())
            }
            RefreshWalletUnitResponse::Revoked => {
                self.wallet_unit_attestation_repository
                    .update_wallet_attestation(
                        &wallet_unit_attestation.id,
                        UpdateWalletUnitAttestationRequest {
                            status: Some(WalletUnitStatus::Revoked),
                            ..Default::default()
                        },
                    )
                    .await?;
                self.history_repository
                    .create_history(History {
                        id: Uuid::new_v4().into(),
                        created_date: now,
                        action: HistoryAction::Revoked,
                        name: wallet_unit_name,
                        target: None,
                        entity_id: Some(wallet_unit_attestation.id.into()),
                        entity_type: HistoryEntityType::WalletUnitAttestation,
                        metadata: None,
                        organisation_id: Some(organisation.id),
                        user: self.session_provider.session().user(),
                    })
                    .await?;
                Err(WalletUnitAttestationError::WalletUnitRevoked.into())
            }
        }
    }

    pub async fn holder_attestation(
        &self,
        organisation_id: OrganisationId,
    ) -> Result<HolderWalletUnitAttestationResponseDTO, ServiceError> {
        let attestation = self
            .wallet_unit_attestation_repository
            .get_wallet_unit_attestation_by_organisation(
                &organisation_id,
                &WalletUnitAttestationRelations::default(),
            )
            .await?;

        attestation
            .map(Into::into)
            .ok_or(EntityNotFoundError::WalletUnitAttestationByOrganisation(organisation_id).into())
    }

    async fn create_signed_key_possession_proof(
        &self,
        now: OffsetDateTime,
        wallet_provider_name: &str,
        auth_fn: AuthenticationFn,
        audience: &str,
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
                custom: (),
            },
        );

        let signed_proof = proof.tokenize(Some(auth_fn)).await?;
        Ok(signed_proof)
    }
}

struct Registration {
    wallet_unit_id: WalletUnitId,
    key: Key,
    attestation: String,
}
