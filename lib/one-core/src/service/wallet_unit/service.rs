use shared_types::{OrganisationId, WalletUnitId};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::common_mapper::list_response_into;
use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::model::key::KeyRelations;
use crate::model::organisation::OrganisationRelations;
use crate::model::wallet_unit::WalletUnitStatus::Revoked;
use crate::model::wallet_unit::{WalletUnitListQuery, WalletUnitRelations, WalletUnitStatus};
use crate::model::wallet_unit_attestation::{
    UpdateWalletUnitAttestationRequest, WalletUnitAttestation, WalletUnitAttestationRelations,
};
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::wallet_provider_client::dto::RefreshWalletUnitResponse;
use crate::service::error::{EntityNotFoundError, MissingProviderError, ServiceError};
use crate::service::ssi_wallet_provider::dto::{
    RefreshWalletUnitRequestDTO, RegisterWalletUnitRequestDTO,
};
use crate::service::wallet_unit::WalletUnitService;
use crate::service::wallet_unit::dto::{
    GetWalletUnitListResponseDTO, GetWalletUnitResponseDTO, HolderRefreshWalletUnitRequestDTO,
    HolderRegisterWalletUnitRequestDTO, HolderWalletUnitAttestationResponseDTO,
};
use crate::service::wallet_unit::error::WalletUnitAttestationError;
use crate::util::jwt::Jwt;
use crate::util::jwt::model::{DecomposedToken, JWTPayload};

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
            .get_wallet_unit(id, &WalletUnitRelations::default())
            .await?
            .ok_or(EntityNotFoundError::WalletUnit(*id))?;

        Ok(result.into())
    }

    /// Returns list of proof schemas according to query
    ///
    /// # Arguments
    ///
    /// * `query` - query parameters
    pub async fn get_wallet_unit_list(
        &self,
        query: WalletUnitListQuery,
    ) -> Result<GetWalletUnitListResponseDTO, ServiceError> {
        let result = self
            .wallet_unit_repository
            .get_wallet_unit_list(query)
            .await?;

        Ok(list_response_into(result))
    }

    pub async fn holder_register(
        &self,
        request: HolderRegisterWalletUnitRequestDTO,
    ) -> Result<(), ServiceError> {
        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
            .await?
            .ok_or(EntityNotFoundError::Organisation(request.organisation_id))?;

        let key = self
            .key_repository
            .get_key(&request.key_id, &KeyRelations::default())
            .await?
            .ok_or(EntityNotFoundError::Key(request.key_id))?;

        let key_storage = self
            .key_provider
            .get_key_storage(&key.storage_type)
            .ok_or(MissingProviderError::KeyStorage(key.storage_type.clone()))?;

        let key_handle = key_storage
            .key_handle(&key)
            .map_err(|e| ServiceError::KeyStorageError(KeyStorageError::SignerError(e)))?;

        let auth_fn = self.key_provider.get_signature_provider(
            &key,
            None,
            self.key_algorithm_provider.clone(),
        )?;

        let now = self.clock.now_utc();
        let os_name = self.os_info_provider.get_os_name().await;
        let signed_proof = self
            .create_signed_key_possession_proof(
                now,
                &request.wallet_provider.name,
                auth_fn,
                &request.wallet_provider.url,
            )
            .await?;

        let register_request = RegisterWalletUnitRequestDTO {
            wallet_provider: request.wallet_provider.name.clone(),
            os: os_name.into(),
            public_key: key_handle.public_key_as_jwk()?.into(),
            proof: signed_proof,
        };

        let register_response = self
            .wallet_provider_client
            .register(&request.wallet_provider.url, register_request)
            .await
            .map_err(WalletUnitAttestationError::from)?;

        let Some(attestation) = register_response.attestation else {
            unimplemented!("holder nonce handling: TODO ONE-7129")
        };

        let attestation_token: DecomposedToken<()> = Jwt::decompose_token(&attestation)?;

        let wallet_unit_attestation = WalletUnitAttestation {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            expiration_date: attestation_token
                .payload
                .expires_at
                .ok_or(ServiceError::MappingError("expires_at is None".to_string()))?,
            status: WalletUnitStatus::Active,
            attestation,
            wallet_unit_id: register_response.id,
            wallet_provider_url: request.wallet_provider.url,
            wallet_provider_type: request.wallet_provider.r#type.clone(),
            wallet_provider_name: request.wallet_provider.name,
            organisation: Some(organisation.clone()),
            key: Some(key),
        };

        let wallet_unit_attestation_id = self
            .wallet_unit_attestation_repository
            .create_wallet_unit_attestation(wallet_unit_attestation)
            .await?;

        let wallet_unit_name = format!(
            "{}-{}-{}",
            request.wallet_provider.r#type,
            os_name,
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
            })
            .await?;

        Ok(())
    }

    pub async fn holder_refresh(
        &self,
        request: HolderRefreshWalletUnitRequestDTO,
    ) -> Result<(), ServiceError> {
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

        let auth_fn = self.key_provider.get_signature_provider(
            key,
            None,
            self.key_algorithm_provider.clone(),
        )?;

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
                    })
                    .await?;
                Ok(())
            }
            RefreshWalletUnitResponse::Revoked => {
                self.wallet_unit_attestation_repository
                    .update_wallet_attestation(
                        &wallet_unit_attestation.id,
                        UpdateWalletUnitAttestationRequest {
                            status: Some(Revoked),
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
