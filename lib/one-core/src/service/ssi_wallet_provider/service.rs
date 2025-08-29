use std::ops::Add;

use shared_types::{IdentifierId, WalletUnitId};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::common_validator::{
    validate_expiration_time, validate_issuance_time, validate_not_before_time,
};
use crate::config::ConfigValidationError;
use crate::config::core_config::{Fields, KeyAlgorithmType, WalletProviderType};
use crate::model::certificate::CertificateRelations;
use crate::model::did::{DidRelations, KeyFilter};
use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::model::identifier::{IdentifierRelations, IdentifierType};
use crate::model::key::{KeyRelations, PublicKeyJwk};
use crate::model::wallet_unit::{
    UpdateWalletUnitRequest, WalletUnit, WalletUnitRelations, WalletUnitStatus,
};
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::ParsedKey;
use crate::service::error::{EntityNotFoundError, ServiceError};
use crate::service::ssi_wallet_provider::SSIWalletProviderService;
use crate::service::ssi_wallet_provider::dto::{
    RefreshWalletUnitRequestDTO, RefreshWalletUnitResponseDTO, RegisterWalletUnitRequestDTO,
    RegisterWalletUnitResponseDTO, WalletProviderParams,
};
use crate::service::ssi_wallet_provider::error::WalletProviderError;
use crate::service::ssi_wallet_provider::validator::validate_audience;
use crate::util::jwt::Jwt;
use crate::util::jwt::model::{
    DecomposedToken, JWTPayload, ProofOfPossessionJwk, ProofOfPossessionKey,
};

const WUA_JWT_TYPE: &str = "oauth-client-attestation+jwt";
const LEEWAY: u64 = 60;

impl SSIWalletProviderService {
    pub async fn register_wallet_unit(
        &self,
        request: RegisterWalletUnitRequestDTO,
    ) -> Result<RegisterWalletUnitResponseDTO, ServiceError> {
        let (config, config_params) =
            self.get_wallet_provider_config_params(request.wallet_provider.clone())?;

        let proof = Jwt::<()>::decompose_token(&request.proof)?;
        let public_key_jwk = request.public_key.into();
        let public_key = self
            .parse_jwk(&proof.header.algorithm, &public_key_jwk)
            .await?;

        self.verify_proof(&proof, &public_key, LEEWAY).await?;

        let now = self.clock.now_utc();

        let auth_fn = self.get_auth_fn(config_params.issuer_identifier).await?;
        let attestation = self.create_attestation(
            now,
            &request.wallet_provider,
            config_params.lifetime.expiration_time,
            public_key_jwk.clone(),
            &auth_fn,
        )?;
        let signed_attestation = attestation.tokenize(Some(auth_fn)).await?;

        let wallet_unit_name = format!("{}-{}-{}", config.r#type, request.os, now.unix_timestamp());

        let encoded_public_key = serde_json::to_string(&public_key_jwk)
            .map_err(|e| ServiceError::MappingError(format!("Could not encode public key: {e}")))?;
        let wallet_unit = WalletUnit {
            id: Uuid::new_v4().into(),
            name: wallet_unit_name.clone(),
            created_date: now,
            last_modified: now,
            last_issuance: now,
            os: request.os,
            status: WalletUnitStatus::Active,
            wallet_provider_name: request.wallet_provider,
            wallet_provider_type: config.r#type.into(),
            public_key: encoded_public_key,
        };
        let wallet_unit_id = self
            .wallet_unit_repository
            .create_wallet_unit(wallet_unit)
            .await?;

        self.history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: now,
                action: HistoryAction::Created,
                name: wallet_unit_name,
                target: Some(wallet_unit_id.to_string()),
                entity_id: Some(wallet_unit_id.into()),
                entity_type: HistoryEntityType::WalletUnit,
                metadata: None,
                organisation_id: None,
            })
            .await?;

        Ok(RegisterWalletUnitResponseDTO {
            id: wallet_unit_id,
            attestation: signed_attestation,
        })
    }

    pub async fn refresh_wallet_unit(
        &self,
        wallet_unit_id: WalletUnitId,
        request: RefreshWalletUnitRequestDTO,
    ) -> Result<RefreshWalletUnitResponseDTO, ServiceError> {
        let wallet_unit = self
            .wallet_unit_repository
            .get_wallet_unit(&wallet_unit_id, &WalletUnitRelations::default())
            .await?
            .ok_or(EntityNotFoundError::WalletUnit(wallet_unit_id))?;

        let (_, config_params) =
            self.get_wallet_provider_config_params(wallet_unit.wallet_provider_name.clone())?;

        let decoded_public_key = serde_json::from_str::<PublicKeyJwk>(&wallet_unit.public_key)
            .map_err(|e| ServiceError::MappingError(format!("Could not decode public key: {e}")))?;

        let ParsedKey { key, .. } = self.key_algorithm_provider.parse_jwk(&decoded_public_key)?;

        let proof = Jwt::<()>::decompose_token(&request.proof)?;
        self.verify_proof(&proof, &key, LEEWAY).await?;

        let now = self.clock.now_utc();
        let can_be_issued_after = wallet_unit.last_issuance.add(Duration::minutes(
            config_params.lifetime.minimum_refresh_time,
        ));
        if can_be_issued_after > now {
            return Err(WalletProviderError::RefreshTimeNotReached.into());
        }

        if wallet_unit.status != WalletUnitStatus::Active {
            return Err(WalletProviderError::WalletUnitRevoked.into());
        }

        let auth_fn = self.get_auth_fn(config_params.issuer_identifier).await?;
        let attestation = self.create_attestation(
            now,
            &wallet_unit.wallet_provider_name,
            config_params.lifetime.expiration_time,
            key.public_key_as_jwk()?,
            &auth_fn,
        )?;
        let signed_attestation = attestation.tokenize(Some(auth_fn)).await?;

        self.wallet_unit_repository
            .update_wallet_unit(
                &wallet_unit_id,
                UpdateWalletUnitRequest {
                    last_issuance: Some(now),
                    ..Default::default()
                },
            )
            .await?;

        self.history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: now,
                action: HistoryAction::Updated,
                name: wallet_unit.name,
                target: Some(wallet_unit.id.to_string()),
                entity_id: Some(wallet_unit.id.into()),
                entity_type: HistoryEntityType::WalletUnit,
                metadata: None,
                organisation_id: None,
            })
            .await?;

        Ok(RefreshWalletUnitResponseDTO {
            id: wallet_unit.id,
            attestation: signed_attestation,
        })
    }

    fn get_wallet_provider_config_params(
        &self,
        wallet_provider: String,
    ) -> Result<(&Fields<WalletProviderType>, WalletProviderParams), ServiceError> {
        let wallet_provider_config = self
            .config
            .wallet_provider
            .get_if_enabled(wallet_provider.as_str())
            .map_err(WalletProviderError::WalletProviderDisabled)?;

        let wallet_provider_config_params = wallet_provider_config
            .deserialize::<WalletProviderParams>()
            .map_err(|source| ConfigValidationError::FieldsDeserialization {
                key: wallet_provider.to_string(),
                source,
            })?;
        Ok((wallet_provider_config, wallet_provider_config_params))
    }

    fn create_attestation(
        &self,
        now: OffsetDateTime,
        wallet_provider_name: &str,
        expiration_time: i64,
        proof_jwk: PublicKeyJwk,
        auth_fn: &AuthenticationFn,
    ) -> Result<Jwt<()>, ServiceError> {
        Ok(Jwt::new(
            WUA_JWT_TYPE.to_string(),
            auth_fn.jose_alg().ok_or(KeyAlgorithmError::Failed(
                "No JOSE alg specified".to_string(),
            ))?,
            auth_fn.get_key_id(),
            None,
            JWTPayload {
                issued_at: Some(now),
                expires_at: Some(now.add(Duration::seconds(expiration_time))),
                invalid_before: Some(now),
                issuer: self.base_url.clone(),
                subject: self
                    .base_url
                    .clone()
                    .map(|base_url| format!("{base_url}/{wallet_provider_name}")),
                audience: None,
                jwt_id: None,
                proof_of_possession_key: Some(ProofOfPossessionKey {
                    key_id: None,
                    jwk: ProofOfPossessionJwk::Jwk {
                        jwk: proof_jwk.into(),
                    },
                }),
                custom: (),
            },
        ))
    }

    async fn get_auth_fn(
        &self,
        issuer_identifier_id: IdentifierId,
    ) -> Result<AuthenticationFn, ServiceError> {
        let issuer_identifier = self
            .identifier_repository
            .get(
                issuer_identifier_id,
                &IdentifierRelations {
                    organisation: None,
                    did: Some(DidRelations {
                        keys: Some(KeyRelations::default()),
                        ..Default::default()
                    }),
                    key: Some(KeyRelations::default()),
                    certificates: Some(CertificateRelations {
                        key: Some(KeyRelations::default()),
                        ..Default::default()
                    }),
                },
            )
            .await?;

        let Some(issuer_identifier) = issuer_identifier else {
            return Err(EntityNotFoundError::Identifier(issuer_identifier_id).into());
        };

        let issuer_key = issuer_identifier
            .find_matching_key(&KeyFilter {
                role: None,
                algorithms: Some(vec![KeyAlgorithmType::Ecdsa]),
            })?
            .ok_or(WalletProviderError::IssuerKeyWithAlgorithmNotFound(
                KeyAlgorithmType::Ecdsa,
            ))?;

        let key_id = if issuer_identifier.r#type == IdentifierType::Did {
            let issuer_did = issuer_identifier
                .did
                .as_ref()
                .ok_or(ServiceError::MappingError("issuer did is None".to_string()))?;

            let key = issuer_did
                .find_key(
                    &issuer_key.id,
                    &KeyFilter {
                        algorithms: Some(vec![KeyAlgorithmType::Ecdsa]),
                        ..Default::default()
                    },
                )?
                .ok_or(WalletProviderError::IssuerKeyWithAlgorithmNotFound(
                    KeyAlgorithmType::Ecdsa,
                ))?;

            Some(issuer_did.verification_method_id(key))
        } else {
            None
        };

        let auth_fn = self.key_provider.get_signature_provider(
            issuer_key,
            key_id,
            self.key_algorithm_provider.clone(),
        )?;
        Ok(auth_fn)
    }

    async fn parse_jwk(
        &self,
        key_algorithm: &str,
        jwk: &PublicKeyJwk,
    ) -> Result<KeyHandle, WalletProviderError> {
        let (_, key_algorithm) = self
            .key_algorithm_provider
            .key_algorithm_from_jose_alg(key_algorithm)
            .ok_or(WalletProviderError::CouldNotVerifyProof(format!(
                "Missing key algorithm for {key_algorithm}"
            )))?;

        key_algorithm
            .parse_jwk(jwk)
            .map_err(|e| WalletProviderError::CouldNotVerifyProof(e.to_string()))
    }

    async fn verify_proof(
        &self,
        proof: &DecomposedToken<()>,
        public_key: &KeyHandle,
        leeway: u64,
    ) -> Result<(), ServiceError> {
        public_key
            .verify(proof.unverified_jwt.as_bytes(), &proof.signature)
            .map_err(|e| WalletProviderError::CouldNotVerifyProof(e.to_string()))?;
        validate_issuance_time(&proof.payload.issued_at, leeway)?;

        if proof.payload.invalid_before.is_none() {
            return Err(WalletProviderError::CouldNotVerifyProof("Missing nbf".to_string()).into());
        }
        validate_not_before_time(&proof.payload.invalid_before, leeway)?;

        if proof.payload.expires_at.is_none() {
            return Err(WalletProviderError::CouldNotVerifyProof("Missing ext".to_string()).into());
        }
        validate_expiration_time(&proof.payload.expires_at, leeway)?;

        let Some(audience) = proof.payload.audience.as_ref() else {
            return Err(WalletProviderError::CouldNotVerifyProof("Missing aud".to_string()).into());
        };
        validate_audience(audience, self.base_url.as_deref())?;
        Ok(())
    }
}
