use std::ops::Add;

use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use one_crypto::utilities::generate_alphanumeric;
use shared_types::{EntityId, IdentifierId, WalletUnitId};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::common_validator::{
    validate_audience, validate_expiration_time, validate_issuance_time, validate_not_before_time,
};
use crate::config::ConfigValidationError;
use crate::config::core_config::{ConfigExt, Fields, KeyAlgorithmType, WalletProviderType};
use crate::model::certificate::CertificateRelations;
use crate::model::did::{DidRelations, KeyFilter};
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryErrorMetadata, HistoryMetadata,
};
use crate::model::identifier::{IdentifierRelations, IdentifierType};
use crate::model::key::{KeyRelations, PublicKeyJwk};
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::model::wallet_unit::{
    UpdateWalletUnitRequest, WalletUnit, WalletUnitOs, WalletUnitRelations, WalletUnitStatus,
};
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::service::error::{EntityNotFoundError, ErrorCodeMixin, ServiceError};
use crate::service::ssi_wallet_provider::SSIWalletProviderService;
use crate::service::ssi_wallet_provider::app_integrity::android::validate_attestation_android;
use crate::service::ssi_wallet_provider::app_integrity::ios::{
    validate_attestation_ios, webauthn_signed_jwt_to_msg_and_sig,
};
use crate::service::ssi_wallet_provider::dto::{
    RefreshWalletUnitRequestDTO, RefreshWalletUnitResponseDTO, RegisterWalletUnitRequestDTO,
    RegisterWalletUnitResponseDTO, WalletProviderParams, WalletUnitActivationRequestDTO,
    WalletUnitActivationResponseDTO,
};
use crate::service::ssi_wallet_provider::error::WalletProviderError;
use crate::service::ssi_wallet_provider::mapper::{
    map_already_exists_error, public_key_from_wallet_unit, wallet_unit_from_request,
};
use crate::service::ssi_wallet_provider::validator::validate_org_wallet_provider;
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
            self.get_wallet_provider_config_params(request.wallet_provider.as_ref())?;

        let Some(organisation) = self
            .organisation_repository
            .get_organisation_for_wallet_provider(request.wallet_provider.as_ref())
            .await?
        else {
            return Err(WalletProviderError::WalletProviderNotAssociatedWithOrganisation.into());
        };
        let issuer = validate_org_wallet_provider(&organisation, &request.wallet_provider)?;

        if !config_params.integrity_check.enabled
            && request.proof.is_none()
            && request.public_key.is_none()
        {
            // If both, proof and public key are missing, the assumption is that the client is expecting
            // an app integrity check with a nonce --> return specific error code to cover that case.
            return Err(WalletProviderError::AppIntegrityCheckNotRequired.into());
        }

        if config_params.integrity_check.enabled && request.os != WalletUnitOs::Web {
            if request.public_key.is_some() || request.proof.is_some() {
                return Err(WalletProviderError::AppIntegrityCheckRequired.into());
            }
            self.create_integrity_check_nonce(request, organisation, config)
                .await
        } else {
            let proof = Jwt::<()>::decompose_token(
                request
                    .proof
                    .as_ref()
                    .ok_or(WalletProviderError::MissingProof)?,
            )?;
            let public_key_jwk = request
                .public_key
                .clone()
                .ok_or(WalletProviderError::MissingPublicKey)?
                .into();
            let public_key = self
                .parse_jwk(&proof.header.algorithm, &public_key_jwk)
                .await?;
            self.verify_proof(
                &proof,
                &public_key,
                request.os,
                config_params.integrity_check.enabled,
                LEEWAY,
            )
            .await?;
            self.create_wallet_unit_with_attestation(
                request,
                issuer,
                organisation,
                config,
                config_params,
                public_key_jwk,
            )
            .await
        }
    }

    async fn create_integrity_check_nonce(
        &self,
        request: RegisterWalletUnitRequestDTO,
        organisation: Organisation,
        config: &Fields<WalletProviderType>,
    ) -> Result<RegisterWalletUnitResponseDTO, ServiceError> {
        let now = self.clock.now_utc();
        let nonce = generate_alphanumeric(44).to_owned();
        let wallet_unit = wallet_unit_from_request(
            request,
            organisation,
            config,
            None,
            now,
            Some(nonce.clone()),
        )?;
        let wallet_unit_name = wallet_unit.name.clone();
        let wallet_unit_id = self
            .wallet_unit_repository
            .create_wallet_unit(wallet_unit)
            .await?;

        self.create_wallet_unit_history(
            &wallet_unit_id,
            wallet_unit_name,
            HistoryAction::Pending,
            None,
        )
        .await;

        Ok(RegisterWalletUnitResponseDTO {
            id: wallet_unit_id,
            attestation: None,
            nonce: Some(nonce),
        })
    }

    async fn create_wallet_unit_history(
        &self,
        wallet_unit_id: &WalletUnitId,
        wallet_unit_name: String,
        action: HistoryAction,
        metadata: Option<HistoryMetadata>,
    ) {
        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: self.clock.now_utc(),
                action,
                name: wallet_unit_name,
                target: Some(wallet_unit_id.to_string()),
                entity_id: Some(EntityId::from(*wallet_unit_id)),
                entity_type: HistoryEntityType::WalletUnit,
                metadata,
                organisation_id: None,
                user: None,
            })
            .await;
        if let Err(err) = result {
            tracing::warn!("Failed to write wallet unit history: {err}")
        };
    }

    async fn create_wallet_unit_with_attestation(
        &self,
        request: RegisterWalletUnitRequestDTO,
        issuer: IdentifierId,
        organisation: Organisation,
        config: &Fields<WalletProviderType>,
        config_params: WalletProviderParams,
        public_key_jwk: PublicKeyJwk,
    ) -> Result<RegisterWalletUnitResponseDTO, ServiceError> {
        let now = self.clock.now_utc();
        let wallet_provider = request.wallet_provider.clone();
        let wallet_unit = wallet_unit_from_request(
            request,
            organisation,
            config,
            Some(&public_key_jwk),
            now,
            None,
        )?;
        let wallet_unit_name = wallet_unit.name.clone();
        let (signed_attestation, attestation_hash) = self
            .sign_attestation(
                issuer,
                &config_params,
                public_key_jwk,
                wallet_provider.as_ref(),
            )
            .await?;
        let wallet_unit_id = self
            .wallet_unit_repository
            .create_wallet_unit(wallet_unit)
            .await
            .map_err(map_already_exists_error)?;
        self.create_wallet_unit_history(
            &wallet_unit_id,
            wallet_unit_name,
            HistoryAction::Created,
            Some(HistoryMetadata::WalletUnitJWT(attestation_hash)),
        )
        .await;

        Ok(RegisterWalletUnitResponseDTO {
            id: wallet_unit_id,
            attestation: Some(signed_attestation),
            nonce: None,
        })
    }

    async fn sign_attestation(
        &self,
        issuer: IdentifierId,
        config_params: &WalletProviderParams,
        public_key_jwk: PublicKeyJwk,
        wallet_provider: &str,
    ) -> Result<(String, String), ServiceError> {
        let now = self.clock.now_utc();
        let auth_fn = self.get_auth_fn(issuer).await?;
        let attestation = self.create_attestation(
            now,
            wallet_provider,
            config_params.lifetime.expiration_time,
            public_key_jwk,
            &auth_fn,
        )?;
        let signed_attestation = attestation.tokenize(Some(auth_fn)).await?;
        let attestation_hash = SHA256
            .hash_base64(signed_attestation.as_bytes())
            .map_err(|e| {
                ServiceError::MappingError(format!("Could not hash wallet unit attestation: {e}"))
            })?;
        Ok((signed_attestation, attestation_hash))
    }

    pub async fn activate_wallet_unit(
        &self,
        wallet_unit_id: WalletUnitId,
        request: WalletUnitActivationRequestDTO,
    ) -> Result<WalletUnitActivationResponseDTO, ServiceError> {
        let wallet_unit = self
            .wallet_unit_repository
            .get_wallet_unit(
                &wallet_unit_id,
                &WalletUnitRelations {
                    organisation: Some(OrganisationRelations::default()),
                },
            )
            .await?
            .ok_or(EntityNotFoundError::WalletUnit(wallet_unit_id))?;

        match wallet_unit.status {
            WalletUnitStatus::Pending => {} // OK
            WalletUnitStatus::Active | WalletUnitStatus::Error => {
                return Err(WalletProviderError::InvalidWalletUnitState.into());
            }
            WalletUnitStatus::Revoked => return Err(WalletProviderError::WalletUnitRevoked.into()),
        }

        let Some(wallet_unit_nonce) = &wallet_unit.nonce else {
            return Err(WalletProviderError::MissingWalletUnitAttestationNonce.into());
        };
        let Some(organisation) = &wallet_unit.organisation else {
            return Err(ServiceError::MappingError(format!(
                "Missing organisation on wallet unit `{}`",
                wallet_unit.id
            )));
        };
        let (_, config_params) =
            self.get_wallet_provider_config_params(&wallet_unit.wallet_provider_name)?;
        let issuer_identifier =
            validate_org_wallet_provider(organisation, &wallet_unit.wallet_provider_name)?;

        if wallet_unit.last_modified
            + Duration::seconds(config_params.integrity_check.timeout as i64)
            < self.clock.now_utc()
        {
            let error = WalletProviderError::InvalidWalletUnitAttestationNonce;
            self.set_wallet_unit_to_error(
                &wallet_unit,
                HistoryErrorMetadata {
                    error_code: error.error_code(),
                    message: format!(
                        "Failed to activate wallet unit {}: nonce expired",
                        wallet_unit.id
                    ),
                },
            )
            .await?;
            return Err(error.into());
        };

        let attestation_result = self
            .validate_attestation(
                &request.attestation,
                wallet_unit.os,
                wallet_unit_nonce,
                &config_params,
            )
            .await;
        let attested_public_key = match attestation_result {
            Ok(key) => key,
            Err(err) => {
                self.set_wallet_unit_to_error(
                    &wallet_unit,
                    HistoryErrorMetadata {
                        error_code: err.error_code(),
                        message: err.to_string(),
                    },
                )
                .await?;
                return Err(err.into());
            }
        };
        let proof = Jwt::<()>::decompose_token(&request.proof)?;
        self.verify_proof(
            &proof,
            &attested_public_key,
            wallet_unit.os,
            config_params.integrity_check.enabled,
            LEEWAY,
        )
        .await?;

        let jwk = attested_public_key.public_key_as_jwk()?;
        let encoded_public_key = serde_json::to_string(&jwk)
            .map_err(|e| ServiceError::MappingError(format!("Could not encode public key: {e}")))?;
        let (signed_attestation, attestation_hash) = self
            .sign_attestation(
                issuer_identifier,
                &config_params,
                jwk,
                &wallet_unit.wallet_provider_name,
            )
            .await?;

        self.wallet_unit_repository
            .update_wallet_unit(
                &wallet_unit_id,
                UpdateWalletUnitRequest {
                    status: Some(WalletUnitStatus::Active),
                    last_issuance: Some(self.clock.now_utc()),
                    public_key: Some(encoded_public_key),
                },
            )
            .await?;

        self.create_wallet_unit_history(
            &wallet_unit_id,
            wallet_unit.name,
            HistoryAction::Activated,
            Some(HistoryMetadata::WalletUnitJWT(attestation_hash)),
        )
        .await;

        Ok(WalletUnitActivationResponseDTO {
            attestation: signed_attestation,
        })
    }

    async fn validate_attestation(
        &self,
        attestation: &[String],
        os: WalletUnitOs,
        wallet_unit_nonce: &str,
        config_params: &WalletProviderParams,
    ) -> Result<KeyHandle, WalletProviderError> {
        match os {
            WalletUnitOs::Ios => {
                let attestation =
                    attestation
                        .first()
                        .ok_or(WalletProviderError::AppIntegrityValidationError(
                            "Missing attestation".to_string(),
                        ))?;
                let bundle = config_params.ios.as_ref().ok_or(
                    WalletProviderError::AppIntegrityValidationError(
                        "Missing iOS app integrity config".to_string(),
                    ),
                )?;
                validate_attestation_ios(
                    attestation,
                    wallet_unit_nonce,
                    bundle,
                    &*self.certificate_validator,
                )
                .await
            }
            WalletUnitOs::Android => {
                if attestation.is_empty() {
                    return Err(WalletProviderError::AppIntegrityValidationError(
                        "Missing attestation".to_string(),
                    ));
                }
                let bundle = config_params.android.as_ref().ok_or(
                    WalletProviderError::AppIntegrityValidationError(
                        "Missing Android app integrity config".to_string(),
                    ),
                )?;
                validate_attestation_android(
                    attestation,
                    wallet_unit_nonce,
                    bundle,
                    &*self.certificate_validator,
                )
                .await
            }
            WalletUnitOs::Web => Err(WalletProviderError::AppIntegrityValidationError(
                "Cannot integrity check wallet unit with os 'WEB'".to_string(),
            )),
        }
    }

    async fn set_wallet_unit_to_error(
        &self,
        wallet_unit: &WalletUnit,
        error_metadata: HistoryErrorMetadata,
    ) -> Result<(), ServiceError> {
        self.wallet_unit_repository
            .update_wallet_unit(
                &wallet_unit.id,
                UpdateWalletUnitRequest {
                    status: Some(WalletUnitStatus::Error),
                    last_issuance: None,
                    public_key: None,
                },
            )
            .await?;
        self.create_wallet_unit_history(
            &wallet_unit.id,
            wallet_unit.name.clone(),
            HistoryAction::Errored,
            Some(HistoryMetadata::ErrorMetadata(error_metadata)),
        )
        .await;
        Ok(())
    }

    pub async fn refresh_wallet_unit(
        &self,
        wallet_unit_id: WalletUnitId,
        request: RefreshWalletUnitRequestDTO,
    ) -> Result<RefreshWalletUnitResponseDTO, ServiceError> {
        let wallet_unit = self
            .wallet_unit_repository
            .get_wallet_unit(
                &wallet_unit_id,
                &WalletUnitRelations {
                    organisation: Some(OrganisationRelations::default()),
                },
            )
            .await?
            .ok_or(EntityNotFoundError::WalletUnit(wallet_unit_id))?;

        let Some(organisation) = &wallet_unit.organisation else {
            return Err(ServiceError::MappingError(format!(
                "Missing organisation on wallet unit `{}`",
                wallet_unit.id
            )));
        };
        let (_, config_params) =
            self.get_wallet_provider_config_params(&wallet_unit.wallet_provider_name)?;
        let issuer_identifier =
            validate_org_wallet_provider(organisation, &wallet_unit.wallet_provider_name)?;

        let key = public_key_from_wallet_unit(&wallet_unit, &*self.key_algorithm_provider)?;
        let proof = Jwt::<()>::decompose_token(&request.proof)?;
        self.verify_proof(
            &proof,
            &key,
            wallet_unit.os,
            config_params.integrity_check.enabled,
            LEEWAY,
        )
        .await?;

        let now = self.clock.now_utc();
        if let Some(last_issuance) = wallet_unit.last_issuance
            && last_issuance.add(Duration::minutes(
                config_params.lifetime.minimum_refresh_time,
            )) > now
        {
            return Err(WalletProviderError::RefreshTimeNotReached.into());
        }

        if wallet_unit.status != WalletUnitStatus::Active {
            return Err(WalletProviderError::WalletUnitRevoked.into());
        }

        let (signed_attestation, attestation_hash) = self
            .sign_attestation(
                issuer_identifier,
                &config_params,
                key.public_key_as_jwk()?,
                &wallet_unit.wallet_provider_name,
            )
            .await?;
        self.wallet_unit_repository
            .update_wallet_unit(
                &wallet_unit_id,
                UpdateWalletUnitRequest {
                    last_issuance: Some(now),
                    ..Default::default()
                },
            )
            .await?;

        self.create_wallet_unit_history(
            &wallet_unit_id,
            wallet_unit.name,
            HistoryAction::Updated,
            Some(HistoryMetadata::WalletUnitJWT(attestation_hash)),
        )
        .await;

        Ok(RefreshWalletUnitResponseDTO {
            id: wallet_unit.id,
            attestation: signed_attestation,
        })
    }

    fn get_wallet_provider_config_params(
        &self,
        wallet_provider: &str,
    ) -> Result<(&Fields<WalletProviderType>, WalletProviderParams), ServiceError> {
        let wallet_provider_config = self
            .config
            .wallet_provider
            .get_if_enabled(wallet_provider)
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

    pub(super) async fn verify_proof(
        &self,
        proof: &DecomposedToken<()>,
        public_key: &KeyHandle,
        wallet_unit_os: WalletUnitOs,
        integrity_check_enabled: bool,
        leeway: u64,
    ) -> Result<(), ServiceError> {
        let (msg, signature) = match (integrity_check_enabled, wallet_unit_os) {
            (true, WalletUnitOs::Ios) => webauthn_signed_jwt_to_msg_and_sig(proof)?,
            _ => (
                proof.unverified_jwt.as_bytes().to_vec(),
                proof.signature.clone(),
            ),
        };

        public_key
            .verify(&msg, &signature)
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
        if let Some(expected_audience) = self.base_url.as_deref() {
            validate_audience(audience, expected_audience)?;
        }
        Ok(())
    }

    pub async fn revoke_wallet_unit(&self, id: &WalletUnitId) -> Result<(), ServiceError> {
        let wallet_unit = self
            .wallet_unit_repository
            .get_wallet_unit(id, &WalletUnitRelations::default())
            .await?
            .ok_or(EntityNotFoundError::WalletUnit(*id))?;

        if wallet_unit.status != WalletUnitStatus::Active {
            return Err(WalletProviderError::WalletUnitMustBeActive.into());
        }

        self.wallet_unit_repository
            .update_wallet_unit(
                id,
                UpdateWalletUnitRequest {
                    status: Some(WalletUnitStatus::Revoked),
                    ..Default::default()
                },
            )
            .await?;
        self.create_wallet_unit_history(id, wallet_unit.name, HistoryAction::Revoked, None)
            .await;
        Ok(())
    }

    pub async fn delete_wallet_unit(&self, id: &WalletUnitId) -> Result<(), ServiceError> {
        let wallet_unit = self
            .wallet_unit_repository
            .get_wallet_unit(id, &WalletUnitRelations::default())
            .await?
            .ok_or(EntityNotFoundError::WalletUnit(*id))?;

        if wallet_unit.status != WalletUnitStatus::Pending {
            return Err(WalletProviderError::WalletUnitMustBePending.into());
        }

        self.wallet_unit_repository.delete_wallet_unit(id).await?;
        let _unused = self
            .history_repository
            .delete_history_by_entity_id((*id).into())
            .await
            .inspect_err(|e| tracing::warn!("Failed to write wallet unit history: {e}"));
        Ok(())
    }
}
