use std::ops::Add;
use std::sync::Arc;

use futures::FutureExt;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use one_crypto::utilities::generate_alphanumeric;
use one_dto_mapper::convert_inner;
use shared_types::{EntityId, IdentifierId, OrganisationId, WalletUnitId};
use time::Duration;
use uuid::Uuid;

use super::WalletProviderService;
use super::app_integrity::android::validate_attestation_android;
use super::app_integrity::ios::{validate_attestation_ios, webauthn_signed_jwt_to_msg_and_sig};
use super::dto::{
    GetWalletUnitListResponseDTO, GetWalletUnitResponseDTO, IssueWalletUnitAttestationRequestDTO,
    IssueWalletUnitAttestationResponseDTO, NoncePayload, RegisterWalletUnitRequestDTO,
    RegisterWalletUnitResponseDTO, WalletAppAttestationClaims, WalletProviderMetadataResponseDTO,
    WalletProviderParams, WalletRegistrationRequirement, WalletUnitActivationRequestDTO,
    WalletUnitAttestationClaims, WalletUnitAttestationMetadataDTO,
};
use super::error::WalletProviderError;
use super::mapper::{
    map_already_exists_error, public_key_from_wallet_unit, wallet_unit_from_request,
};
use super::validator::{
    validate_org_wallet_provider, validate_proof_payload, validate_revocation_method,
};
use crate::config::ConfigValidationError;
use crate::config::core_config::{ConfigExt, Fields, KeyAlgorithmType, WalletProviderType};
use crate::error::ErrorCodeMixin;
use crate::mapper::list_response_into;
use crate::mapper::x509::pem_chain_into_x5c;
use crate::model::certificate::CertificateRelations;
use crate::model::did::{DidRelations, KeyFilter};
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryErrorMetadata, HistoryMetadata, HistorySource,
};
use crate::model::identifier::{IdentifierRelations, IdentifierType};
use crate::model::key::{KeyRelations, PublicKeyJwk};
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::model::revocation_list::RevocationListRelations;
use crate::model::wallet_unit::{
    UpdateWalletUnitRequest, WalletUnit, WalletUnitListQuery, WalletUnitOs, WalletUnitRelations,
    WalletUnitStatus,
};
use crate::model::wallet_unit_attested_key::{
    WalletUnitAttestedKey, WalletUnitAttestedKeyRelations, WalletUnitAttestedKeyRevocationInfo,
};
use crate::proto::jwt::model::{
    DecomposedJwt, JWTPayload, ProofOfPossessionJwk, ProofOfPossessionKey,
};
use crate::proto::jwt::{Jwt, JwtPublicKeyInfo};
use crate::proto::session_provider::SessionExt;
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::credential_formatter::sdjwtvc_formatter::model::SdJwtVcStatus;
use crate::provider::issuance_protocol::model::KeyStorageSecurityLevel;
use crate::provider::key_algorithm::error::{KeyAlgorithmError, KeyAlgorithmProviderError};
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::model::{CredentialRevocationInfo, RevocationState};
use crate::service::error::{EntityNotFoundError, MissingProviderError, ServiceError};
use crate::validator::{
    throw_if_org_not_matching_session, throw_if_org_relation_not_matching_session,
};

const WAA_JWT_TYPE: &str = "oauth-client-attestation+jwt";
const WUA_JWT_TYPE: &str = "key-attestation+jwt";

impl WalletProviderService {
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
                    ..Default::default()
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

    pub async fn register_wallet_unit(
        &self,
        request: RegisterWalletUnitRequestDTO,
    ) -> Result<RegisterWalletUnitResponseDTO, ServiceError> {
        let wallet_provider = request.wallet_provider.to_owned();
        let (config, config_params) = self.get_wallet_provider_config_params(&wallet_provider)?;

        let Some(organisation) = self
            .organisation_repository
            .get_organisation_for_wallet_provider(&wallet_provider)
            .await?
        else {
            return Err(WalletProviderError::WalletProviderNotAssociatedWithOrganisation.into());
        };
        validate_org_wallet_provider(&organisation, &wallet_provider)?;

        if !config_params.wallet_app_attestation.integrity_check.enabled
            && request.proof.is_none()
            && request.public_key.is_none()
        {
            // If both, proof and public key are missing, the assumption is that the client is expecting
            // an app integrity check with a nonce --> return specific error code to cover that case.
            return Err(WalletProviderError::AppIntegrityCheckNotRequired.into());
        }

        let result = if config_params.wallet_app_attestation.integrity_check.enabled
            && request.os != WalletUnitOs::Web
        {
            if request.public_key.is_some() || request.proof.is_some() {
                return Err(WalletProviderError::AppIntegrityCheckRequired.into());
            }
            self.create_wallet_unit_with_nonce(request, organisation, config.r#type)
                .await
        } else {
            let proof = Jwt::<NoncePayload>::decompose_token(
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
            let public_key = self.parse_jwk(&proof.header.algorithm, &public_key_jwk)?;
            self.verify_device_signing_proof(
                &proof,
                &public_key,
                config_params.device_auth_leeway,
                None,
            )
            .await?;
            self.create_wallet_unit_with_auth_key(
                request,
                organisation,
                config.r#type,
                public_key_jwk,
            )
            .await
        }?;

        tracing::info!(
            "Created wallet unit {} (requires activation `{}`): wallet provider `{wallet_provider}`",
            result.id,
            result.nonce.is_some()
        );
        Ok(result)
    }

    async fn create_wallet_unit_with_nonce(
        &self,
        request: RegisterWalletUnitRequestDTO,
        organisation: Organisation,
        wallet_provider_type: WalletProviderType,
    ) -> Result<RegisterWalletUnitResponseDTO, ServiceError> {
        let now = self.clock.now_utc();
        let nonce = generate_alphanumeric(44).to_owned();
        let organisation_id = organisation.id;
        let wallet_unit = wallet_unit_from_request(
            request,
            organisation,
            wallet_provider_type,
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
            organisation_id,
        )
        .await;

        Ok(RegisterWalletUnitResponseDTO {
            id: wallet_unit_id,
            nonce: Some(nonce),
        })
    }

    async fn create_wallet_unit_history(
        &self,
        wallet_unit_id: &WalletUnitId,
        wallet_unit_name: String,
        action: HistoryAction,
        metadata: Option<HistoryMetadata>,
        organisation_id: OrganisationId,
    ) {
        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: self.clock.now_utc(),
                action,
                name: wallet_unit_name,
                source: HistorySource::Core,
                target: Some(wallet_unit_id.to_string()),
                entity_id: Some(EntityId::from(*wallet_unit_id)),
                entity_type: HistoryEntityType::WalletUnit,
                metadata,
                organisation_id: Some(organisation_id),
                user: self.session_provider.session().user(),
            })
            .await;
        if let Err(err) = result {
            tracing::warn!("Failed to write wallet unit history: {err}")
        };
    }

    async fn create_wallet_unit_with_auth_key(
        &self,
        request: RegisterWalletUnitRequestDTO,
        organisation: Organisation,
        wallet_provider_type: WalletProviderType,
        public_key_jwk: PublicKeyJwk,
    ) -> Result<RegisterWalletUnitResponseDTO, ServiceError> {
        let now = self.clock.now_utc();
        let organisation_id = organisation.id;
        let wallet_unit = wallet_unit_from_request(
            request,
            organisation,
            wallet_provider_type,
            Some(&public_key_jwk),
            now,
            None,
        )?;
        let wallet_unit_name = wallet_unit.name.clone();
        let wallet_unit_id = self
            .wallet_unit_repository
            .create_wallet_unit(wallet_unit)
            .await
            .map_err(map_already_exists_error)?;
        self.create_wallet_unit_history(
            &wallet_unit_id,
            wallet_unit_name,
            HistoryAction::Created,
            None,
            organisation_id,
        )
        .await;

        Ok(RegisterWalletUnitResponseDTO {
            id: wallet_unit_id,
            nonce: None,
        })
    }

    pub async fn activate_wallet_unit(
        &self,
        wallet_unit_id: WalletUnitId,
        request: WalletUnitActivationRequestDTO,
    ) -> Result<(), ServiceError> {
        let wallet_unit = self
            .wallet_unit_repository
            .get_wallet_unit(
                &wallet_unit_id,
                &WalletUnitRelations {
                    organisation: Some(OrganisationRelations::default()),
                    ..Default::default()
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

        validate_org_wallet_provider(organisation, &wallet_unit.wallet_provider_name)?;

        if wallet_unit.last_modified
            + Duration::seconds(config_params.wallet_app_attestation.integrity_check.timeout as i64)
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
        let attestation_key_proof =
            Jwt::<NoncePayload>::decompose_token(&request.attestation_key_proof)?;
        self.verify_attestation_proof(
            &attestation_key_proof,
            &attested_public_key,
            wallet_unit.os,
            config_params.wallet_app_attestation.integrity_check.enabled,
            config_params.device_auth_leeway,
            Some(wallet_unit_nonce),
        )
        .await?;

        // Allow devices to have the attestation issued to some other key than the attestation key.
        // This is necessary as the attestation key might have limitations in regard to general
        // purpose crypto signatures.
        // E.g. on iOS the attestation key is only able to produce WebAuthn signatures.
        let jwk = if let Some(device_signing_key_proof) = &request.device_signing_key_proof {
            let device_signing_key_proof =
                Jwt::<NoncePayload>::decompose_token(device_signing_key_proof)?;
            let (_, alg) = self
                .key_algorithm_provider
                .key_algorithm_from_jose_alg(&device_signing_key_proof.header.algorithm)
                .ok_or(MissingProviderError::KeyAlgorithmProvider(
                    KeyAlgorithmProviderError::MissingAlgorithmImplementation(
                        device_signing_key_proof.header.algorithm.clone(),
                    ),
                ))?;
            let device_signing_key =
                PublicKeyJwk::from(device_signing_key_proof.header.jwk.clone().ok_or(
                    ServiceError::MappingError(
                        "Missing JWK in device signing key header".to_string(),
                    ),
                )?);
            let device_signing_key_handle = alg.parse_jwk(&device_signing_key)?;
            self.verify_device_signing_proof(
                &device_signing_key_proof,
                &device_signing_key_handle,
                config_params.device_auth_leeway,
                Some(wallet_unit_nonce),
            )
            .await?;
            device_signing_key
        } else {
            attested_public_key.public_key_as_jwk()?
        };

        self.wallet_unit_repository
            .update_wallet_unit(
                &wallet_unit_id,
                UpdateWalletUnitRequest {
                    status: Some(WalletUnitStatus::Active),
                    last_issuance: Some(self.clock.now_utc()),
                    authentication_key_jwk: Some(jwk),
                    attested_keys: None,
                },
            )
            .await?;

        self.create_wallet_unit_history(
            &wallet_unit_id,
            wallet_unit.name,
            HistoryAction::Activated,
            None,
            organisation.id,
        )
        .await;
        tracing::info!("Activated wallet unit {}", wallet_unit_id);
        Ok(())
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
                let bundle = config_params
                    .wallet_app_attestation
                    .integrity_check
                    .ios
                    .as_ref()
                    .ok_or(WalletProviderError::AppIntegrityValidationError(
                        "Missing iOS app integrity config".to_string(),
                    ))?;
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
                let bundle = config_params
                    .wallet_app_attestation
                    .integrity_check
                    .android
                    .as_ref()
                    .ok_or(WalletProviderError::AppIntegrityValidationError(
                        "Missing Android app integrity config".to_string(),
                    ))?;
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
                    authentication_key_jwk: None,
                    attested_keys: None,
                },
            )
            .await?;

        let Some(organisation) = &wallet_unit.organisation else {
            return Err(ServiceError::MappingError(format!(
                "Missing organisation on wallet unit `{}`",
                wallet_unit.id
            )));
        };
        self.create_wallet_unit_history(
            &wallet_unit.id,
            wallet_unit.name.clone(),
            HistoryAction::Errored,
            Some(HistoryMetadata::ErrorMetadata(error_metadata)),
            organisation.id,
        )
        .await;
        Ok(())
    }

    pub async fn issue_attestation(
        &self,
        wallet_unit_id: WalletUnitId,
        bearer_token: &str,
        request: IssueWalletUnitAttestationRequestDTO,
    ) -> Result<IssueWalletUnitAttestationResponseDTO, ServiceError> {
        let wallet_unit = self
            .wallet_unit_repository
            .get_wallet_unit(
                &wallet_unit_id,
                &WalletUnitRelations {
                    organisation: Some(OrganisationRelations::default()),
                    attested_keys: Some(WalletUnitAttestedKeyRelations {
                        revocation: Some(Default::default()),
                    }),
                },
            )
            .await?
            .ok_or(EntityNotFoundError::WalletUnit(wallet_unit_id))?;

        if wallet_unit.status != WalletUnitStatus::Active {
            return Err(WalletProviderError::WalletUnitRevoked.into());
        }

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

        let revocation_method = config_params
            .wallet_unit_attestation
            .revocation_method
            .as_ref()
            .map(|revocation_method| {
                self.revocation_method_provider
                    .get_revocation_method(revocation_method)
                    .ok_or(MissingProviderError::RevocationMethod(
                        revocation_method.to_owned(),
                    ))
            })
            .transpose()?;

        let key = public_key_from_wallet_unit(&wallet_unit, &*self.key_algorithm_provider)?;
        let bearer_token = Jwt::<NoncePayload>::decompose_token(bearer_token)?;
        self.verify_device_signing_proof(
            &bearer_token,
            &key,
            config_params.device_auth_leeway,
            None,
        )
        .await?;

        let now = self.clock.now_utc();
        let (public_key_info, auth_fn) = self.get_key_info(issuer_identifier).await?;

        let mut app_attestations = vec![];
        for waa_request in request.waa {
            let holder_jwk = self
                .verify_pop(&waa_request.proof, config_params.device_auth_leeway)
                .await?;
            let attestation = self.create_waa(
                &wallet_unit.wallet_provider_name,
                &config_params,
                holder_jwk,
                &auth_fn,
                public_key_info.clone(),
            )?;
            let signed_attestation = attestation.tokenize(Some(&*auth_fn)).await?;
            app_attestations.push(signed_attestation);
        }

        let mut attested_keys =
            wallet_unit
                .attested_keys
                .to_owned()
                .ok_or(ServiceError::MappingError(format!(
                    "Missing attested keys on wallet unit `{}`",
                    wallet_unit.id
                )))?;

        let mut key_attestation_inputs = vec![];
        for wua_request in request.wua {
            let wua_expiration_date = now
                + Duration::seconds(config_params.wallet_unit_attestation.expiration_time as i64);

            let holder_jwk = self
                .verify_pop(&wua_request.proof, config_params.device_auth_leeway)
                .await?;
            let attested_key_input = if let Some(attested_key) = attested_keys
                .iter_mut()
                .find(|attested_key| attested_key.public_key_jwk == holder_jwk)
            {
                attested_key.last_modified = now;
                attested_key.expiration_date = wua_expiration_date;
                AttestedKeyInput::Reused(attested_key.revocation.to_owned())
            } else {
                let key = WalletUnitAttestedKey {
                    id: Uuid::new_v4().into(),
                    wallet_unit_id,
                    created_date: now,
                    last_modified: now,
                    expiration_date: wua_expiration_date,
                    public_key_jwk: holder_jwk.clone(),
                    revocation: None,
                };
                attested_keys.push(key.to_owned());
                AttestedKeyInput::NewlyCreated(key)
            };

            key_attestation_inputs.push(KeyAttestationInput {
                holder_jwk,
                security_level: wua_request.security_level,
                key: attested_key_input,
            });
        }

        let updated_attested_keys = (!key_attestation_inputs.is_empty()).then_some(attested_keys);

        let mut key_attestations = vec![];

        // DB update is only necessary if we either issued app or key attestation
        if !app_attestations.is_empty() || updated_attested_keys.is_some() {
            self.tx_manager
                .tx(async {
                    self.wallet_unit_repository
                        .update_wallet_unit(
                            &wallet_unit_id,
                            UpdateWalletUnitRequest {
                                last_issuance: Some(now),
                                attested_keys: updated_attested_keys,
                                ..Default::default()
                            },
                        )
                        .await?;

                    if !app_attestations.is_empty() {
                        self.create_wallet_unit_history(
                            &wallet_unit_id,
                            wallet_unit.name.clone(),
                            HistoryAction::Updated,
                            None,
                            organisation.id,
                        )
                        .await;
                    }

                    for key_attestation_input in key_attestation_inputs {
                        key_attestations.push(
                            self.issue_key_attestation(
                                &wallet_unit,
                                &config_params,
                                &auth_fn,
                                public_key_info.clone(),
                                organisation,
                                &revocation_method,
                                key_attestation_input,
                            )
                            .await?,
                        );
                    }
                    Ok::<_, ServiceError>(())
                }
                .boxed())
                .await??;
        }
        tracing::info!("Issued attestations for wallet unit {}", wallet_unit_id);
        Ok(IssueWalletUnitAttestationResponseDTO {
            waa: app_attestations,
            wua: key_attestations,
        })
    }

    #[expect(clippy::too_many_arguments)]
    async fn issue_key_attestation(
        &self,
        wallet_unit: &WalletUnit,
        config_params: &WalletProviderParams,
        auth_fn: &AuthenticationFn,
        issuer_public_key_info: JwtPublicKeyInfo,
        organisation: &Organisation,
        revocation_method: &Option<Arc<dyn RevocationMethod>>,
        input: KeyAttestationInput,
    ) -> Result<String, ServiceError> {
        let revocation_info = if let Some(revocation_method) = revocation_method {
            match &input.key {
                AttestedKeyInput::NewlyCreated(key) => {
                    Some(revocation_method.add_issued_attestation(key).await?)
                }
                AttestedKeyInput::Reused(None) => None,
                AttestedKeyInput::Reused(Some(info)) => Some(
                    revocation_method
                        .get_attestation_revocation_info(info)
                        .await?,
                ),
            }
        } else {
            None
        };

        let attestation = self.create_wua(
            &wallet_unit.wallet_provider_name,
            config_params,
            input.holder_jwk,
            input.security_level,
            auth_fn,
            issuer_public_key_info,
            revocation_info,
        )?;
        let signed_attestation = attestation.tokenize(Some(auth_fn.as_ref())).await?;
        let attestation_hash = SHA256
            .hash_base64(signed_attestation.as_bytes())
            .map_err(|e| {
                ServiceError::Other(format!("Could not hash wallet unit attestation: {e}"))
            })?;
        self.create_wallet_unit_history(
            &wallet_unit.id,
            wallet_unit.name.clone(),
            HistoryAction::Issued,
            Some(HistoryMetadata::WalletUnitJWT(attestation_hash)),
            organisation.id,
        )
        .await;
        Ok(signed_attestation)
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

        validate_revocation_method(self.config.as_ref(), &wallet_provider_config_params)?;

        Ok((wallet_provider_config, wallet_provider_config_params))
    }

    fn create_waa(
        &self,
        wallet_provider_name: &str,
        config_params: &WalletProviderParams,
        holder_binding_jwk: PublicKeyJwk,
        auth_fn: &AuthenticationFn,
        issuer_public_key_info: JwtPublicKeyInfo,
    ) -> Result<Jwt<WalletAppAttestationClaims>, ServiceError> {
        let now = self.clock.now_utc();
        let jose_alg = auth_fn.jose_alg().ok_or(KeyAlgorithmError::Failed(
            "No JOSE alg specified".to_string(),
        ))?;
        let key_id = auth_fn.get_key_id();

        Ok(Jwt::new(
            WAA_JWT_TYPE.to_string(),
            jose_alg,
            key_id,
            Some(issuer_public_key_info),
            JWTPayload {
                issued_at: Some(now),
                expires_at: Some(now.add(Duration::seconds(
                    config_params.wallet_app_attestation.expiration_time as i64,
                ))),
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
                        jwk: holder_binding_jwk.into(),
                    },
                }),
                custom: WalletAppAttestationClaims {
                    wallet_name: Some(config_params.wallet_name.clone()),
                    wallet_link: Some(config_params.wallet_link.clone()),
                    eudi_wallet_info: convert_inner(config_params.eudi_wallet_info.clone()),
                },
            },
        ))
    }

    #[expect(clippy::too_many_arguments)]
    fn create_wua(
        &self,
        wallet_provider_name: &str,
        config_params: &WalletProviderParams,
        holder_binding_jwk: PublicKeyJwk,
        key_storage_security_level: KeyStorageSecurityLevel,
        auth_fn: &AuthenticationFn,
        issuer_public_key_info: JwtPublicKeyInfo,
        revocation_info: Option<CredentialRevocationInfo>,
    ) -> Result<Jwt<WalletUnitAttestationClaims>, ServiceError> {
        let now = self.clock.now_utc();
        let jose_alg = auth_fn.jose_alg().ok_or(KeyAlgorithmError::Failed(
            "No JOSE alg specified".to_string(),
        ))?;
        let key_id = auth_fn.get_key_id();

        let status = revocation_info
            .and_then(|info| {
                let obj: serde_json::Value = info
                    .credential_status
                    .additional_fields
                    .into_iter()
                    .collect();
                serde_json::from_value(obj).ok()
            })
            .map(|status_list| SdJwtVcStatus {
                status_list,
                custom_claims: Default::default(),
            });

        Ok(Jwt::new(
            WUA_JWT_TYPE.to_string(),
            jose_alg,
            key_id,
            Some(issuer_public_key_info),
            JWTPayload {
                issued_at: Some(now),
                expires_at: Some(now.add(Duration::seconds(
                    config_params.wallet_unit_attestation.expiration_time as i64,
                ))),
                invalid_before: Some(now),
                issuer: config_params
                    .eudi_wallet_info
                    .as_ref()
                    .map(|info| info.provider_name.clone())
                    .or_else(|| self.base_url.clone()),
                subject: self
                    .base_url
                    .clone()
                    .map(|base_url| format!("{base_url}/{wallet_provider_name}")),
                audience: None,
                jwt_id: None,
                proof_of_possession_key: None,
                custom: WalletUnitAttestationClaims {
                    key_storage: vec![key_storage_security_level],
                    attested_keys: vec![holder_binding_jwk],
                    eudi_wallet_info: convert_inner(config_params.eudi_wallet_info.clone()),
                    status,
                },
            },
        ))
    }

    async fn get_key_info(
        &self,
        issuer_identifier_id: IdentifierId,
    ) -> Result<(JwtPublicKeyInfo, AuthenticationFn), ServiceError> {
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

        let public_key_info = match issuer_identifier.r#type {
            IdentifierType::Key | IdentifierType::Did => {
                let key_handle = self
                    .key_provider
                    .get_key_storage(&issuer_key.storage_type)
                    .ok_or(ServiceError::MappingError(format!(
                        "Key storage not found: {}",
                        issuer_key.storage_type
                    )))?
                    .key_handle(issuer_key)
                    .map_err(|e| {
                        ServiceError::MappingError(format!("Failed to get key handle: {e}"))
                    })?;
                JwtPublicKeyInfo::Jwk(key_handle.public_key_as_jwk()?.into())
            }
            IdentifierType::Certificate => {
                let cert = issuer_identifier
                    .certificates
                    .as_ref()
                    .ok_or(ServiceError::MappingError(format!(
                        "Missing certificates on certificate identifier {}",
                        issuer_identifier.id
                    )))?
                    .iter()
                    .find(|cert| cert.key.as_ref().is_some_and(|k| k.id == issuer_key.id))
                    .ok_or(ServiceError::MappingError(
                        "Cert with matching key not found".to_string(),
                    ))?;
                let x5c = pem_chain_into_x5c(&cert.chain).map_err(|e| {
                    ServiceError::MappingError(format!("Failed to create x5c: {e}"))
                })?;
                JwtPublicKeyInfo::X5c(x5c)
            }
        };
        Ok((public_key_info, auth_fn))
    }

    fn parse_jwk(
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

    pub(super) async fn verify_attestation_proof(
        &self,
        proof: &DecomposedJwt<NoncePayload>,
        public_key: &KeyHandle,
        wallet_unit_os: WalletUnitOs,
        integrity_check_enabled: bool,
        leeway: u64,
        nonce: Option<&str>,
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
        validate_proof_payload(proof, leeway, self.base_url.as_deref(), nonce)
    }

    pub(super) async fn verify_device_signing_proof(
        &self,
        proof: &DecomposedJwt<NoncePayload>,
        public_key: &KeyHandle,
        leeway: u64,
        nonce: Option<&str>,
    ) -> Result<(), ServiceError> {
        public_key
            .verify(proof.unverified_jwt.as_bytes(), &proof.signature)
            .map_err(|e| WalletProviderError::CouldNotVerifyProof(e.to_string()))?;
        validate_proof_payload(proof, leeway, self.base_url.as_deref(), nonce)
    }

    async fn verify_pop(&self, pop: &str, leeway: u64) -> Result<PublicKeyJwk, ServiceError> {
        let pop_token = Jwt::<NoncePayload>::decompose_token(pop)?;
        let jwk = pop_token
            .header
            .jwk
            .clone()
            .ok_or(WalletProviderError::CouldNotVerifyProof(
                "Missing jwk".to_string(),
            ))?
            .into();
        let key_handle = self.parse_jwk(&pop_token.header.algorithm, &jwk)?;
        key_handle
            .verify(pop_token.unverified_jwt.as_bytes(), &pop_token.signature)
            .map_err(|e| WalletProviderError::CouldNotVerifyProof(e.to_string()))?;
        validate_proof_payload(&pop_token, leeway, self.base_url.as_deref(), None)?;
        Ok(jwk)
    }

    pub async fn revoke_wallet_unit(&self, id: &WalletUnitId) -> Result<(), ServiceError> {
        let wallet_unit = self
            .wallet_unit_repository
            .get_wallet_unit(
                id,
                &WalletUnitRelations {
                    organisation: Some(OrganisationRelations::default()),
                    attested_keys: Some(WalletUnitAttestedKeyRelations {
                        revocation: Some(RevocationListRelations {
                            issuer_identifier: Some(IdentifierRelations {
                                did: Some(DidRelations {
                                    keys: Some(KeyRelations::default()),
                                    ..Default::default()
                                }),
                                key: Some(KeyRelations::default()),
                                certificates: Some(CertificateRelations {
                                    key: Some(KeyRelations::default()),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }),
                        }),
                    }),
                },
            )
            .await?
            .ok_or(EntityNotFoundError::WalletUnit(*id))?;

        if wallet_unit.status != WalletUnitStatus::Active {
            return Err(WalletProviderError::WalletUnitMustBeActive.into());
        }

        let Some(organisation) = &wallet_unit.organisation else {
            return Err(ServiceError::MappingError(format!(
                "Missing organisation on wallet unit `{}`",
                wallet_unit.id
            )));
        };

        let (_, config_params) =
            self.get_wallet_provider_config_params(&wallet_unit.wallet_provider_name)?;

        self.wallet_unit_repository
            .update_wallet_unit(
                id,
                UpdateWalletUnitRequest {
                    status: Some(WalletUnitStatus::Revoked),
                    ..Default::default()
                },
            )
            .await?;
        self.create_wallet_unit_history(
            id,
            wallet_unit.name,
            HistoryAction::Revoked,
            None,
            organisation.id,
        )
        .await;

        let Some(revocation_method) = &config_params.wallet_unit_attestation.revocation_method
        else {
            return Ok(());
        };

        let keys = wallet_unit
            .attested_keys
            .ok_or(ServiceError::MappingError(format!(
                "Missing attested_keys on wallet unit `{}`",
                wallet_unit.id
            )))?
            .into_iter()
            .filter_map(|key| key.revocation)
            .collect::<Vec<_>>();

        if !keys.is_empty() {
            let revocation_method = self
                .revocation_method_provider
                .get_revocation_method(revocation_method)
                .ok_or(MissingProviderError::RevocationMethod(
                    revocation_method.to_owned(),
                ))?;

            revocation_method
                .update_attestation_entries(keys, RevocationState::Revoked)
                .await?;
        }
        tracing::info!("Revoked wallet unit {}", id);
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
        tracing::info!("Deleted wallet unit {}", id);
        Ok(())
    }

    pub async fn get_wallet_provider_metadata(
        &self,
        wallet_provider: String,
    ) -> Result<WalletProviderMetadataResponseDTO, ServiceError> {
        let (_, params) = self.get_wallet_provider_config_params(&wallet_provider)?;
        let (enabled, required) = match params.wallet_registration {
            WalletRegistrationRequirement::Mandatory => (true, true),
            WalletRegistrationRequirement::Optional => (true, false),
            WalletRegistrationRequirement::Disabled => (false, false),
        };
        Ok(WalletProviderMetadataResponseDTO {
            wallet_unit_attestation: WalletUnitAttestationMetadataDTO {
                app_integrity_check_required: params.wallet_app_attestation.integrity_check.enabled,
                enabled,
                required,
            },
            name: wallet_provider,
            app_version: params.app_version,
        })
    }
}

struct KeyAttestationInput {
    holder_jwk: PublicKeyJwk,
    security_level: KeyStorageSecurityLevel,
    key: AttestedKeyInput,
}

#[expect(clippy::large_enum_variant)]
enum AttestedKeyInput {
    NewlyCreated(WalletUnitAttestedKey),
    Reused(Option<WalletUnitAttestedKeyRevocationInfo>),
}
