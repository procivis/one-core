use std::collections::HashMap;

use futures::FutureExt;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use one_crypto::utilities::generate_alphanumeric;
use one_dto_mapper::convert_inner;
use serde::Serialize;
use shared_types::{
    EntityId, IdentifierId, ManagedInstanceId, OrganisationId, RevocationListEntryId,
    RevocationMethodId,
};
use standardized_types::jwk::PublicJwk;
use time::Duration;
use uuid::Uuid;

use super::ManagedInstanceService;
use super::app_integrity::android::validate_attestation_android;
use super::app_integrity::ios::{validate_attestation_ios, webauthn_signed_jwt_to_msg_and_sig};
use super::dto::{
    AttestationStatus, DocumentSignerMetadataDTO, FeatureFlags, GetManagedInstanceListResponseDTO,
    GetManagedInstanceResponseDTO, IntegrityCheck, IssueWalletUnitAttestationRequestDTO,
    IssueWalletUnitAttestationResponseDTO, IssueWiaRequestDTO, IssueWuaRequestDTO,
    ManagedInstanceFilterParamsDTO, NoncePayload, RegisterWalletUnitRequestDTO,
    RegisterWalletUnitResponseDTO, UserAuthenticationParams, WalletInstanceAttestationClaims,
    WalletProviderMetadataResponseDTO, WalletProviderParams, WalletRegistrationRequirement,
    WalletUnitActivationRequestDTO, WalletUnitActivationResponseDTO, WalletUnitAttestationClaims,
    WalletUnitAttestationMetadataDTO,
};
use super::ecosystem_metadata::{
    EcosystemEntityRepositories, ecosystem_metadata, provider_trust_collections,
};
use super::error::ManagedInstanceError;
use super::mapper::{
    map_already_exists_error, params_into_display_names, public_key_from_wallet_unit,
    wallet_unit_from_request,
};
use super::validator::{validate_org_for_role, validate_proof_payload, validate_revocation_method};
use crate::config::ConfigValidationError;
use crate::config::core_config::{ConfigExt, Fields, KeyAlgorithmType, WalletProviderType};
use crate::error::{ContextWithErrorCode, ErrorCodeMixin, ErrorCodeMixinExt};
use crate::mapper::x509::pem_chain_into_x5c;
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryErrorMetadata, HistoryMetadata, HistorySource,
};
use crate::model::identifier::IdentifierData;
use crate::model::instance::{InstanceRole, InstanceStatus};
use crate::model::list_query::{ListPagination, ListSorting};
use crate::model::managed_instance::{
    ManagedInstance, ManagedInstanceListQuery, ManagedInstanceOs, SortableManagedInstanceColumn,
    UpdateManagedInstanceRequest,
};
use crate::model::managed_instance_attestation::{
    ManagedInstanceAttestation, ManagedInstanceAttestationRevocationInfo,
    UpdateManagedInstanceAttestationRequest,
};
use crate::model::organisation::Organisation;
use crate::model::wallet_instance_attestation::AttestationType;
use crate::proto::jwt::model::{
    DecomposedJwt, JWTPayload, ProofOfPossessionJwk, ProofOfPossessionKey,
};
use crate::proto::jwt::{Jwt, JwtPublicKeyInfo};
use crate::proto::session_provider::SessionExt;
use crate::proto::transaction_manager::IsolationLevel;
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::credential_formatter::sdjwtvc_formatter::model::SdJwtVcStatus;
use crate::provider::key_algorithm::error::KeyAlgorithmProviderError;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::revocation::model::RevocationState;
use crate::provider::verifier::model::AccessCertificateConfiguration;
use crate::service::common_dto::ListQueryDTO;
use crate::util::key_selection::KeyFilter;
use crate::validator::throw_if_org_id_not_matching_session;

const WIA_JWT_TYPE: &str = "oauth-client-attestation+jwt";
const WUA_JWT_TYPE: &str = "key-attestation+jwt";

impl ManagedInstanceService {
    /// Returns details of a wallet unit
    ///
    /// # Arguments
    ///
    /// * `id` - Wallet unit uuid
    pub async fn get_managed_instance(
        &self,
        id: &ManagedInstanceId,
    ) -> Result<GetManagedInstanceResponseDTO, ManagedInstanceError> {
        let result = self
            .managed_instance_repository
            .get(id)
            .await
            .error_while("getting wallet unit")?;
        throw_if_org_id_not_matching_session(result.organisation.id_ref(), &*self.session_provider)
            .error_while("checking session")?;

        Ok(self.build_instance_response(result))
    }

    /// Returns list of wallet units according to query
    ///
    /// # Arguments
    ///
    /// * `query` - query parameters
    pub async fn get_managed_instance_list(
        &self,
        filter_params: ListQueryDTO<SortableManagedInstanceColumn, ManagedInstanceFilterParamsDTO>,
    ) -> Result<GetManagedInstanceListResponseDTO, ManagedInstanceError> {
        throw_if_org_id_not_matching_session(
            &filter_params.filter.organisation_id,
            &*self.session_provider,
        )
        .error_while("checking session")?;

        // We can't use the From impl to convert the ListQueryDto to a ListQuery
        // because the filter param conversion involves computing a sha256 hash, which is faliable (unlike other cases)
        let filtering = filter_params
            .filter
            .try_into()
            .error_while("mapping filter query")?;

        let query = ManagedInstanceListQuery {
            pagination: Some(ListPagination {
                page: filter_params.page,
                page_size: filter_params.page_size,
            }),
            sorting: filter_params.sort.map(|column| ListSorting {
                column,
                direction: filter_params.sort_direction,
            }),
            filtering: Some(filtering),
            include: None,
        };

        let result = self
            .managed_instance_repository
            .get_list(query)
            .await
            .error_while("getting wallet units")?;

        Ok(GetManagedInstanceListResponseDTO {
            values: result
                .values
                .into_iter()
                .map(|instance| self.build_instance_response(instance))
                .collect(),
            total_pages: result.total_pages,
            total_items: result.total_items,
        })
    }

    fn resolve_provider_type(&self, instance: &ManagedInstance) -> String {
        match instance.role {
            InstanceRole::Wallet => self
                .config
                .wallet_provider
                .get_type(&instance.provider)
                .map(|r#type| r#type.to_string())
                .unwrap_or_else(|_| instance.provider.clone()),
            InstanceRole::Verifier => self
                .config
                .verifier_provider
                .get_type(&instance.provider)
                .map(|r#type| r#type.to_string())
                .unwrap_or_else(|_| instance.provider.clone()),
        }
    }

    fn build_instance_response(&self, instance: ManagedInstance) -> GetManagedInstanceResponseDTO {
        let provider_type = self.resolve_provider_type(&instance);
        GetManagedInstanceResponseDTO {
            id: instance.id,
            created_date: instance.created_date,
            last_modified: instance.last_modified,
            last_issuance: instance.last_issuance,
            name: instance.name,
            os: instance.os,
            status: instance.status,
            role: instance.role,
            provider_name: instance.provider,
            provider_type,
            authentication_key_jwk: instance.authentication_key_jwk,
            user_sub: instance.user_sub,
            verifier_csr: instance.verifier_csr,
        }
    }

    pub async fn register_instance(
        &self,
        request: RegisterWalletUnitRequestDTO,
    ) -> Result<RegisterWalletUnitResponseDTO, ManagedInstanceError> {
        let provider = request.provider.to_owned();

        let organisation = self
            .get_organisation_for_provider(request.role, &provider)
            .await?;
        validate_org_for_role(&organisation, request.role, &provider)
            .error_while("validating provider")?;
        let reg_params = self.get_provider_registration_params(request.role, &provider)?;

        let is_web = request.os == ManagedInstanceOs::Web;
        // Web instances cannot perform the user binding flow, so it is skipped for them. If the
        // provider mandates user authentication, web instances cannot be registered at all.
        if is_web
            && reg_params
                .user_authentication
                .as_ref()
                .is_some_and(|user_authentication| user_authentication.required)
        {
            return Err(ManagedInstanceError::UserAuthenticationNotSupported
                .error_while("validating request")
                .into());
        }
        let user_binding_required = reg_params.user_authentication.is_some() && !is_web;

        if !reg_params.integrity_check.enabled
            && request.proof.is_none()
            && request.public_key.is_none()
        {
            // If both, proof and public key are missing, the assumption is that the client is expecting
            // an app integrity check with a nonce --> return specific error code to cover that case.
            return Err(ManagedInstanceError::AppIntegrityCheckNotRequired
                .error_while("validating request")
                .into());
        }

        let result = if reg_params.integrity_check.enabled && !is_web {
            if request.public_key.is_some() || request.proof.is_some() {
                return Err(ManagedInstanceError::AppIntegrityCheckRequired
                    .error_while("validating request")
                    .into());
            }
            self.create_instance_with_nonce(
                request,
                organisation,
                &reg_params.name_label,
                user_binding_required,
            )
            .await
        } else {
            let proof = Jwt::<NoncePayload>::decompose_token(
                request
                    .proof
                    .as_ref()
                    .ok_or(ManagedInstanceError::MissingProof)
                    .error_while("validating request")?,
            )
            .error_while("parsing proof token")?;
            let public_key_jwk = request
                .public_key
                .clone()
                .ok_or(ManagedInstanceError::MissingPublicKey)
                .error_while("validating request")?;
            let public_key = self
                .parse_jwk(&proof.header.algorithm, &public_key_jwk)
                .error_while("parsing proof JWK")?;
            self.verify_device_signing_proof(
                &proof,
                &public_key,
                reg_params.device_auth_leeway,
                None,
            )
            .await?;
            self.create_instance_with_auth_key(
                request,
                organisation,
                &reg_params.name_label,
                public_key_jwk,
                user_binding_required,
            )
            .await
        }?;

        tracing::info!(
            "Created wallet unit {} (requires activation `{}`): provider `{provider}`",
            result.id,
            result.nonce.is_some() || result.user_nonce.is_some()
        );
        Ok(result)
    }

    async fn get_organisation_for_provider(
        &self,
        role: InstanceRole,
        provider: &str,
    ) -> Result<Organisation, ManagedInstanceError> {
        let (organisation, not_associated_error) = match role {
            InstanceRole::Wallet => (
                self.organisation_repository
                    .get_organisation_for_wallet_provider(provider)
                    .await,
                ManagedInstanceError::WalletProviderNotAssociatedWithOrganisation,
            ),
            InstanceRole::Verifier => (
                self.organisation_repository
                    .get_organisation_for_verifier_provider(provider)
                    .await,
                ManagedInstanceError::VerifierProviderNotAssociatedWithOrganisation,
            ),
        };
        let organisation = organisation.error_while("getting organisation")?;

        organisation.ok_or_else(|| {
            not_associated_error
                .error_while("getting organisation")
                .into()
        })
    }

    fn get_provider_registration_params(
        &self,
        role: InstanceRole,
        provider: &str,
    ) -> Result<ProviderRegistrationParams, ManagedInstanceError> {
        Ok(match role {
            InstanceRole::Wallet => {
                let (config, config_params) = self.get_wallet_provider_config_params(provider)?;
                ProviderRegistrationParams {
                    name_label: config.r#type.to_string(),
                    integrity_check: config_params.wallet_instance_attestation.integrity_check,
                    device_auth_leeway: config_params.device_auth_leeway_seconds,
                    user_authentication: config_params.user_authentication,
                    access_certificate_configuration: None,
                }
            }
            InstanceRole::Verifier => {
                let verifier_params = self
                    .verifier_provider
                    .get_by_id(provider)
                    .error_while("validating config")?;
                let integrity_check = verifier_params
                    .verifier_instance_attestation
                    .map(|attestation| attestation.integrity_check)
                    .unwrap_or(IntegrityCheck {
                        enabled: false,
                        ..IntegrityCheck::default()
                    });
                ProviderRegistrationParams {
                    name_label: provider.to_string(),
                    integrity_check,
                    device_auth_leeway: verifier_params.device_auth_leeway_seconds,
                    user_authentication: verifier_params.user_authentication,
                    access_certificate_configuration: verifier_params
                        .access_certificate_configuration,
                }
            }
        })
    }

    async fn create_instance_with_nonce(
        &self,
        request: RegisterWalletUnitRequestDTO,
        organisation: Organisation,
        provider_label: &str,
        user_binding_required: bool,
    ) -> Result<RegisterWalletUnitResponseDTO, ManagedInstanceError> {
        let now = crate::clock::now_utc();
        let nonce = generate_alphanumeric(44).to_owned();
        let user_nonce = user_binding_required.then(|| generate_alphanumeric(44));

        let wallet_unit = wallet_unit_from_request(
            request,
            organisation,
            provider_label,
            None,
            now,
            Some(nonce.clone()),
            user_nonce.clone(),
        )?;
        let wallet_unit_id = self
            .managed_instance_repository
            .create(wallet_unit.clone())
            .await
            .error_while("creating wallet unit")?;

        self.create_instance_history(&wallet_unit, HistoryAction::Pending, None)
            .await;

        Ok(RegisterWalletUnitResponseDTO {
            id: wallet_unit_id,
            nonce: Some(nonce),
            user_nonce,
        })
    }

    async fn create_instance_history(
        &self,
        managed_instance: &ManagedInstance,
        action: HistoryAction,
        metadata: Option<HistoryMetadata>,
    ) {
        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                action,
                name: managed_instance.name.to_owned(),
                source: HistorySource::Core,
                target: None,
                entity_id: Some(EntityId::from(managed_instance.id)),
                entity_type: HistoryEntityType::ManagedInstance,
                metadata,
                metadata_blob_id: None,
                organisation_id: Some(managed_instance.organisation.id()),
                user: self.session_provider.session().user(),
            })
            .await;
        if let Err(err) = result {
            tracing::warn!("Failed to write wallet unit history: {err}")
        };
    }

    async fn create_instance_with_auth_key(
        &self,
        request: RegisterWalletUnitRequestDTO,
        organisation: Organisation,
        provider_label: &str,
        public_key_jwk: PublicJwk,
        user_binding_required: bool,
    ) -> Result<RegisterWalletUnitResponseDTO, ManagedInstanceError> {
        let now = crate::clock::now_utc();
        let user_nonce = user_binding_required.then(|| generate_alphanumeric(44));
        let wallet_unit = wallet_unit_from_request(
            request,
            organisation,
            provider_label,
            Some(&public_key_jwk),
            now,
            None,
            user_nonce.clone(),
        )?;
        let wallet_unit_id = self
            .managed_instance_repository
            .create(wallet_unit.clone())
            .await
            .map_err(map_already_exists_error)?;
        self.create_instance_history(&wallet_unit, HistoryAction::Created, None)
            .await;

        Ok(RegisterWalletUnitResponseDTO {
            id: wallet_unit_id,
            nonce: None,
            user_nonce,
        })
    }

    pub async fn activate_instance(
        &self,
        wallet_unit_id: ManagedInstanceId,
        request: WalletUnitActivationRequestDTO,
    ) -> Result<WalletUnitActivationResponseDTO, ManagedInstanceError> {
        let wallet_unit = self
            .managed_instance_repository
            .get(&wallet_unit_id)
            .await
            .error_while("getting wallet unit")?;

        match wallet_unit.status {
            InstanceStatus::Pending => {} // OK
            InstanceStatus::Active | InstanceStatus::Unattested | InstanceStatus::Error => {
                return Err(ManagedInstanceError::InvalidWalletUnitState
                    .error_while("checking status")
                    .into());
            }
            InstanceStatus::Revoked => {
                return Err(ManagedInstanceError::WalletUnitRevoked
                    .error_while("checking status")
                    .into());
            }
        }

        let organisation = &wallet_unit.organisation.as_ref().await?;
        validate_org_for_role(
            organisation.as_ref(),
            wallet_unit.role,
            &wallet_unit.provider,
        )
        .error_while("validating provider")?;
        let reg_params =
            self.get_provider_registration_params(wallet_unit.role, &wallet_unit.provider)?;

        let is_web = wallet_unit.os == ManagedInstanceOs::Web;

        // User binding is skipped for web instances, so no user ID token is expected either.
        let user_sub = self
            .validate_user_id_token(
                request.user_id_token.as_deref(),
                reg_params.user_authentication.as_ref().filter(|_| !is_web),
                wallet_unit.user_nonce.as_deref(),
            )
            .await
            .error_while("validating user ID token")?;

        let integrity_check_enabled = reg_params.integrity_check.enabled && !is_web;

        let authentication_key_jwk = if integrity_check_enabled {
            let wallet_unit_nonce = wallet_unit
                .nonce
                .as_deref()
                .ok_or(ManagedInstanceError::MissingWalletUnitAttestationNonce)
                .error_while("validating nonce")?;

            let attestation = request
                .attestation
                .as_deref()
                .ok_or(ManagedInstanceError::MissingWalletUnitAttestation)?;

            if wallet_unit.last_modified + reg_params.integrity_check.timeout_seconds
                < crate::clock::now_utc()
            {
                let error = ManagedInstanceError::InvalidWalletUnitAttestationNonce;
                self.set_instance_to_error(
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
                return Err(error.error_while("validating time").into());
            }

            let attestation_result = self
                .validate_attestation(
                    attestation,
                    wallet_unit.os,
                    wallet_unit_nonce,
                    &reg_params.integrity_check,
                )
                .await;
            let attested_public_key = match attestation_result {
                Ok(key) => key,
                Err(err) => {
                    self.set_instance_to_error(
                        &wallet_unit,
                        HistoryErrorMetadata {
                            error_code: err.error_code(),
                            message: err.to_string(),
                        },
                    )
                    .await?;
                    return Err(err.error_while("validating attestation").into());
                }
            };

            let attestation_key_proof = Jwt::<NoncePayload>::decompose_token(
                request
                    .attestation_key_proof
                    .as_deref()
                    .ok_or(ManagedInstanceError::MissingProof)
                    .error_while("parsing attestation key proof token")?,
            )
            .error_while("parsing attestation key proof token")?;
            self.verify_attestation_proof(
                &attestation_key_proof,
                &attested_public_key,
                wallet_unit.os,
                true,
                reg_params.device_auth_leeway,
                Some(wallet_unit_nonce),
            )
            .await?;

            // Allow devices to have the attestation issued to some other key than the attestation
            // key. This is necessary as the attestation key might have limitations in regard to
            // general purpose crypto signatures.
            // E.g. on iOS the attestation key is only able to produce WebAuthn signatures.
            let jwk = if let Some(device_signing_key_proof) = &request.device_signing_key_proof {
                let device_signing_key_proof =
                    Jwt::<NoncePayload>::decompose_token(device_signing_key_proof)
                        .error_while("parsing device signing key proof token")?;
                let (_, alg) = self
                    .key_algorithm_provider
                    .key_algorithm_from_jose_alg(&device_signing_key_proof.header.algorithm)
                    .ok_or(KeyAlgorithmProviderError::MissingAlgorithmImplementation(
                        device_signing_key_proof.header.algorithm.clone(),
                    ))
                    .error_while("getting key algorithm")?;
                let device_signing_key = device_signing_key_proof.header.jwk.clone().ok_or(
                    ManagedInstanceError::MappingError(
                        "Missing JWK in device signing key header".to_string(),
                    ),
                )?;
                let device_signing_key_handle = alg
                    .parse_jwk(&device_signing_key)
                    .error_while("parsing device signing JWK")?;
                self.verify_device_signing_proof(
                    &device_signing_key_proof,
                    &device_signing_key_handle,
                    reg_params.device_auth_leeway,
                    Some(wallet_unit_nonce),
                )
                .await?;
                device_signing_key
            } else {
                attested_public_key
                    .public_key_as_jwk()
                    .error_while("creating JWK")?
            };

            Some(jwk)
        } else if let Some(proof_str) = &request.attestation_key_proof {
            // No integrity check: self-certify by verifying the JWT is signed by the key embedded
            // in its own header. No server-provided nonce is available in this path (none was
            // issued at registration), so replay protection relies solely on the JWT timestamp
            // bounds validated inside verify_attestation_proof.
            let proof = Jwt::<NoncePayload>::decompose_token(proof_str)
                .error_while("parsing attestation key proof token")?;
            let jwk = proof
                .header
                .jwk
                .clone()
                .ok_or(ManagedInstanceError::MappingError(
                    "Missing JWK in attestation key proof header".to_string(),
                ))?;
            let key_handle = self
                .parse_jwk(&proof.header.algorithm, &jwk)
                .error_while("parsing attestation key proof JWK")?;
            self.verify_attestation_proof(
                &proof,
                &key_handle,
                wallet_unit.os,
                false,
                reg_params.device_auth_leeway,
                None,
            )
            .await?;
            Some(jwk)
        } else {
            None
        };

        let provisioned_access_certificate = if let Some(verifier_access_certificate_csr) =
            request.verifier_access_certificate_csr
        {
            let Some(access_token) = request.user_access_token else {
                return Err(ManagedInstanceError::MissingUserAccessToken);
            };

            if wallet_unit.role != InstanceRole::Verifier {
                return Err(ManagedInstanceError::InvalidRole(wallet_unit.role));
            }

            let Some(access_certificate_configuration) =
                reg_params.access_certificate_configuration
            else {
                return Err(ManagedInstanceError::AccessCertificateProvisioningDisabled);
            };

            // store the userSub + CSR before calling BFF provider
            self.managed_instance_repository
                .update(
                    &wallet_unit_id,
                    UpdateManagedInstanceRequest {
                        user_sub: user_sub.clone(),
                        verifier_csr: Some(Some(verifier_access_certificate_csr)),
                        ..Default::default()
                    },
                )
                .await
                .error_while("setting CSR")?;

            let response: AccessCertificateProvisioningResponse = async {
                self.http_client
                    .post(&access_certificate_configuration.provider_url)
                    .bearer_auth(&access_token)
                    .json(&AccessCertificateProvisioningRequest {
                        provider: wallet_unit.provider.clone(),
                        managed_instance_id: wallet_unit_id,
                        verifier_provider_organisation_id: organisation.id,
                    })?
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
            }
            .await
            .error_while("requesting access certificate")?;

            Some(response)
        } else {
            None
        };

        let verifier_signature_ids = provisioned_access_certificate.as_ref().map(|ac| {
            let mut old_ids = wallet_unit
                .verifier_signature_ids
                .clone()
                .unwrap_or_default();
            old_ids.push(ac.signature_id.to_owned());
            old_ids
        });
        self.managed_instance_repository
            .update(
                &wallet_unit_id,
                UpdateManagedInstanceRequest {
                    status: Some(InstanceStatus::Active),
                    last_issuance: Some(crate::clock::now_utc()),
                    authentication_key_jwk,
                    user_sub,
                    verifier_csr: Some(None),
                    verifier_signature_ids,
                },
            )
            .await
            .error_while("updating wallet unit")?;

        self.create_instance_history(&wallet_unit, HistoryAction::Activated, None)
            .await;
        tracing::info!("Activated wallet unit {wallet_unit_id}");
        Ok(WalletUnitActivationResponseDTO {
            access_certificate: provisioned_access_certificate.map(|ac| ac.access_certificate),
        })
    }

    async fn validate_attestation(
        &self,
        attestation: &[String],
        os: ManagedInstanceOs,
        wallet_unit_nonce: &str,
        integrity_check: &IntegrityCheck,
    ) -> Result<KeyHandle, ManagedInstanceError> {
        match os {
            ManagedInstanceOs::Ios => {
                let attestation = attestation.first().ok_or(
                    ManagedInstanceError::AppIntegrityValidationError(
                        "Missing attestation".to_string(),
                    ),
                )?;
                let bundle = integrity_check.ios.as_ref().ok_or(
                    ManagedInstanceError::AppIntegrityValidationError(
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
                .map_err(|e| ManagedInstanceError::AppIntegrityValidationError(e.to_string()))
            }
            ManagedInstanceOs::Android => {
                if attestation.is_empty() {
                    return Err(ManagedInstanceError::AppIntegrityValidationError(
                        "Missing attestation".to_string(),
                    ));
                }
                let bundle = integrity_check.android.as_ref().ok_or(
                    ManagedInstanceError::AppIntegrityValidationError(
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
                .map_err(|e| ManagedInstanceError::AppIntegrityValidationError(e.to_string()))
            }
            ManagedInstanceOs::Web => Err(ManagedInstanceError::AppIntegrityValidationError(
                "Cannot integrity check wallet unit with os 'WEB'".to_string(),
            )),
        }
    }

    async fn set_instance_to_error(
        &self,
        wallet_unit: &ManagedInstance,
        error_metadata: HistoryErrorMetadata,
    ) -> Result<(), ManagedInstanceError> {
        self.managed_instance_repository
            .update(
                &wallet_unit.id,
                UpdateManagedInstanceRequest {
                    status: Some(InstanceStatus::Error),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating wallet unit")?;

        self.create_instance_history(
            wallet_unit,
            HistoryAction::Errored,
            Some(HistoryMetadata::ErrorMetadata(error_metadata)),
        )
        .await;
        Ok(())
    }

    pub async fn issue_attestation(
        &self,
        instance_id: ManagedInstanceId,
        bearer_token: &str,
        request: IssueWalletUnitAttestationRequestDTO,
    ) -> Result<IssueWalletUnitAttestationResponseDTO, ManagedInstanceError> {
        let managed_instance = self
            .managed_instance_repository
            .get(&instance_id)
            .await
            .error_while("getting wallet unit")?;

        let organisation = &managed_instance.organisation.as_ref().await?;

        let issuer_identifier = validate_org_for_role(
            organisation.as_ref(),
            managed_instance.role,
            &managed_instance.provider,
        )
        .error_while("validating provider")?;

        let authentication_key =
            public_key_from_wallet_unit(&managed_instance, &*self.key_algorithm_provider)?;
        let bearer_token = Jwt::<NoncePayload>::decompose_token(bearer_token)
            .error_while("parsing bearer token")?;

        let device_auth_leeway = self
            .get_provider_registration_params(managed_instance.role, &managed_instance.provider)?
            .device_auth_leeway;
        self.verify_device_signing_proof(
            &bearer_token,
            &authentication_key,
            device_auth_leeway,
            None,
        )
        .await?;

        if managed_instance.status != InstanceStatus::Active {
            return Err(ManagedInstanceError::WalletUnitRevoked
                .error_while("validating status")
                .into());
        }

        if request.wia.is_empty() && request.wua.is_empty() {
            tracing::info!("No attestations requested for wallet unit {instance_id}");
            return Ok(IssueWalletUnitAttestationResponseDTO::default());
        }

        if managed_instance.role != InstanceRole::Wallet {
            return Err(ManagedInstanceError::InvalidRole(managed_instance.role));
        }

        let (_, config_params) =
            self.get_wallet_provider_config_params(&managed_instance.provider)?;

        let issuer_key = self.get_issuer_key(issuer_identifier).await?;

        let mut result = IssueWalletUnitAttestationResponseDTO::default();
        // READ COMMITTED, so the status list index read includes entries committed while waiting for the lock
        self.tx_manager
            .tx_with_config(
                async {
                    for wia_request in request.wia {
                        result.wia.push(
                            self.create_wia(
                                wia_request,
                                &managed_instance,
                                &issuer_key,
                                &config_params,
                            )
                            .await?,
                        );
                    }

                    for wua_request in request.wua {
                        result.wua.push(
                            self.create_key_attestation(
                                wua_request,
                                &managed_instance,
                                &issuer_key,
                                &config_params,
                            )
                            .await?,
                        );
                    }

                    self.managed_instance_repository
                        .update(
                            &instance_id,
                            UpdateManagedInstanceRequest {
                                last_issuance: Some(crate::clock::now_utc()),
                                ..Default::default()
                            },
                        )
                        .await
                        .error_while("updating wallet unit")?;

                    Ok::<_, ManagedInstanceError>(())
                }
                .boxed(),
                Some(IsolationLevel::ReadCommitted),
                None,
            )
            .await
            .error_while("issuing attestations")??;

        tracing::info!("Issued attestations for wallet unit {instance_id}");
        Ok(result)
    }

    fn get_wallet_provider_config_params(
        &self,
        wallet_provider: &str,
    ) -> Result<(&Fields<WalletProviderType>, WalletProviderParams), ManagedInstanceError> {
        let wallet_provider_config = self
            .config
            .wallet_provider
            .get_if_enabled(wallet_provider)
            .map_err(ManagedInstanceError::WalletProviderDisabled)
            .error_while("validating config")?;

        let wallet_provider_config_params = wallet_provider_config
            .deserialize::<WalletProviderParams>()
            .map_err(|source| ConfigValidationError::FieldsDeserialization {
                key: wallet_provider.to_string(),
                source,
            })
            .error_while("parsing config")?;

        validate_revocation_method(
            self.config.as_ref(),
            &wallet_provider_config_params,
            AttestationType::WalletInstanceAttestation,
        )
        .error_while("validating revocation")?;
        validate_revocation_method(
            self.config.as_ref(),
            &wallet_provider_config_params,
            AttestationType::KeyAttestation,
        )
        .error_while("validating revocation")?;

        Ok((wallet_provider_config, wallet_provider_config_params))
    }

    async fn create_key_attestation(
        &self,
        wua_request: IssueWuaRequestDTO,
        managed_instance: &ManagedInstance,
        issuer_key: &IssuerKey,
        config_params: &WalletProviderParams,
    ) -> Result<String, ManagedInstanceError> {
        let holder_jwk = self
            .verify_pop(&wua_request.proof, config_params.device_auth_leeway_seconds)
            .await
            .error_while("verifying WUA request pop")?;

        let attestation_params = &config_params.wallet_key_attestation;
        let revocation_method = attestation_params
            .revocation_method
            .as_ref()
            .map(|revocation_method| {
                self.revocation_method_provider
                    .get_revocation_method(revocation_method)
            })
            .transpose()?;

        let now = crate::clock::now_utc();
        let ka_expiration_date = now + attestation_params.expiration_seconds;
        let status_expiration_date = if revocation_method.is_some() {
            ka_expiration_date + attestation_params.status_period_seconds
        } else {
            ka_expiration_date
        };
        let attestation = ManagedInstanceAttestation {
            id: Uuid::new_v4().into(),
            instance_id: managed_instance.id,
            created_date: now,
            last_modified: now,
            expiration_date: status_expiration_date,
            r#type: AttestationType::KeyAttestation,
            attestation_content_hash: None,
            revocation: None,
        };
        self.managed_instance_attestation_repository
            .create_attestation(attestation.to_owned())
            .await
            .error_while("creating attestation")?;

        let revocation_info = if let Some(revocation_method) = revocation_method {
            Some(
                revocation_method
                    .add_issued_attestation(&attestation)
                    .await
                    .error_while("adding attestation")?,
            )
        } else {
            None
        };

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

        let signed_attestation = issuer_key
            .sign_jwt(
                WUA_JWT_TYPE.to_string(),
                JWTPayload {
                    issued_at: Some(now),
                    expires_at: Some(ka_expiration_date),
                    invalid_before: Some(now),
                    issuer: None,
                    subject: self
                        .base_url
                        .clone()
                        .map(|base_url| format!("{base_url}/{}", managed_instance.provider)),
                    audience: None,
                    jwt_id: None,
                    proof_of_possession_key: None,
                    custom: WalletUnitAttestationClaims {
                        certification: Some(config_params.wallet_certification.to_owned()),
                        key_storage: vec![wua_request.security_level],
                        attested_keys: vec![holder_jwk],
                        eudi_wallet_info: convert_inner(config_params.eudi_wallet_info.to_owned()),
                        key_storage_status: status.map(|status| AttestationStatus {
                            status,
                            expires_at: status_expiration_date,
                        }),
                        status: None,
                    },
                },
            )
            .await?;

        self.managed_instance_attestation_repository
            .update_attestation(
                &attestation.id,
                UpdateManagedInstanceAttestationRequest {
                    attestation_content_hash: Some(Some(signed_attestation.hash)),
                },
            )
            .await
            .error_while("updating attestation")?;

        self.create_instance_history(
            managed_instance,
            HistoryAction::KaCreated,
            Some(HistoryMetadata::ManagedInstanceAttestation(attestation.id)),
        )
        .await;

        Ok(signed_attestation.jwt)
    }

    async fn create_wia(
        &self,
        wia_request: IssueWiaRequestDTO,
        managed_instance: &ManagedInstance,
        issuer_key: &IssuerKey,
        config_params: &WalletProviderParams,
    ) -> Result<String, ManagedInstanceError> {
        let holder_binding_jwk = self
            .verify_pop(&wia_request.proof, config_params.device_auth_leeway_seconds)
            .await
            .error_while("verifying WIA request pop")?;

        let attestation_params = &config_params.wallet_instance_attestation;
        let revocation_method = attestation_params
            .revocation_method
            .as_ref()
            .map(|revocation_method| {
                self.revocation_method_provider
                    .get_revocation_method(revocation_method)
            })
            .transpose()?;

        let now = crate::clock::now_utc();
        let wia_expiration_date = now + attestation_params.expiration_seconds;
        let status_expiration_date = if revocation_method.is_some() {
            wia_expiration_date + attestation_params.status_period_seconds
        } else {
            wia_expiration_date
        };
        let attestation = ManagedInstanceAttestation {
            id: Uuid::new_v4().into(),
            instance_id: managed_instance.id,
            created_date: now,
            last_modified: now,
            expiration_date: status_expiration_date,
            r#type: AttestationType::WalletInstanceAttestation,
            attestation_content_hash: None,
            revocation: None,
        };
        self.managed_instance_attestation_repository
            .create_attestation(attestation.to_owned())
            .await
            .error_while("creating attestation")?;

        let revocation_info = if let Some(revocation_method) = revocation_method {
            Some(
                revocation_method
                    .add_issued_attestation(&attestation)
                    .await
                    .error_while("adding attestation")?,
            )
        } else {
            None
        };

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

        let signed_attestation = issuer_key
            .sign_jwt(
                WIA_JWT_TYPE.to_string(),
                JWTPayload {
                    issued_at: Some(now),
                    expires_at: Some(wia_expiration_date),
                    invalid_before: Some(now),
                    issuer: None,
                    // As per https://drafts.oauth.net/draft-ietf-oauth-attestation-based-client-auth/draft-ietf-oauth-attestation-based-client-auth.html#section-5.1
                    // sub: REQUIRED. The sub (subject) claim MUST specify client_id value of the OAuth Client.
                    subject: Some(config_params.wallet_client_id.clone()),
                    audience: None,
                    jwt_id: None,
                    proof_of_possession_key: Some(ProofOfPossessionKey {
                        key_id: None,
                        jwk: ProofOfPossessionJwk::Jwk {
                            jwk: holder_binding_jwk,
                        },
                    }),
                    custom: WalletInstanceAttestationClaims {
                        wallet_name: Some(config_params.wallet_name.clone()),
                        wallet_link: Some(config_params.wallet_link.clone()),
                        wallet_solution_certification_information: Some(
                            config_params.wallet_certification.to_owned(),
                        ),
                        eudi_wallet_info: convert_inner(config_params.eudi_wallet_info.clone()),
                        client_status: status.map(|status| AttestationStatus {
                            status,
                            expires_at: status_expiration_date,
                        }),
                    },
                },
            )
            .await?;

        self.managed_instance_attestation_repository
            .update_attestation(
                &attestation.id,
                UpdateManagedInstanceAttestationRequest {
                    attestation_content_hash: Some(Some(signed_attestation.hash)),
                },
            )
            .await
            .error_while("updating attestation")?;

        self.create_instance_history(
            managed_instance,
            HistoryAction::WiaCreated,
            Some(HistoryMetadata::ManagedInstanceAttestation(attestation.id)),
        )
        .await;

        Ok(signed_attestation.jwt)
    }

    async fn get_issuer_key(
        &self,
        issuer_identifier_id: IdentifierId,
    ) -> Result<IssuerKey, ManagedInstanceError> {
        let issuer_identifier = self
            .identifier_repository
            .get(issuer_identifier_id)
            .await
            .error_while("getting identifier")?;

        let selection = issuer_identifier
            .select_key(KeyFilter::algorithms(vec![KeyAlgorithmType::Ecdsa]).into())
            .await
            .error_while("selecting key")?;
        let issuer_key = selection.key();

        let key_id = if let IdentifierData::Did(issuer_did) = &issuer_identifier.data {
            let issuer_did = issuer_did.as_ref().await?;

            let key = issuer_did
                .find_key(
                    &issuer_key.id,
                    &KeyFilter::algorithms(vec![KeyAlgorithmType::Ecdsa]),
                )
                .await
                .error_while("finding key")?;

            Some(issuer_did.verification_method_id(&key))
        } else {
            None
        };

        let auth_fn = self.key_provider.get_signature_provider(
            issuer_key,
            key_id,
            self.key_algorithm_provider.clone(),
        )?;

        let public_key_info = match &issuer_identifier.data {
            IdentifierData::Key(_) | IdentifierData::Did(_) => {
                let key_handle = self
                    .key_provider
                    .get_key_storage(&issuer_key.storage_type)?
                    .key_handle(issuer_key)
                    .error_while("getting issuer key handle")?;
                JwtPublicKeyInfo::Jwk(key_handle.public_key_as_jwk().error_while("creating JWK")?)
            }
            IdentifierData::Certificate(certificates) => {
                let certificates = certificates.as_ref().await?;
                let cert = certificates
                    .iter()
                    .find(|cert| cert.key.as_ref().is_some_and(|k| k.id() == issuer_key.id))
                    .ok_or(ManagedInstanceError::MappingError(
                        "Cert with matching key not found".to_string(),
                    ))?;
                let x5c = pem_chain_into_x5c(&cert.chain).error_while("parsing PEM chain")?;
                JwtPublicKeyInfo::X5c(x5c)
            }
            IdentifierData::CertificateAuthority(_) => {
                return Err(ManagedInstanceError::MappingError(format!(
                    "Invalid issuer identifier type {}",
                    issuer_identifier.data.r#type()
                )));
            }
        };

        Ok(IssuerKey {
            public_key_info,
            auth_fn,
        })
    }

    fn parse_jwk(
        &self,
        key_algorithm: &str,
        jwk: &PublicJwk,
    ) -> Result<KeyHandle, ManagedInstanceError> {
        let (_, key_algorithm) = self
            .key_algorithm_provider
            .key_algorithm_from_jose_alg(key_algorithm)
            .ok_or(ManagedInstanceError::CouldNotVerifyProof(format!(
                "Missing key algorithm for {key_algorithm}"
            )))?;

        key_algorithm
            .parse_jwk(jwk)
            .map_err(|e| ManagedInstanceError::CouldNotVerifyProof(e.to_string()))
    }

    async fn verify_attestation_proof(
        &self,
        proof: &DecomposedJwt<NoncePayload>,
        public_key: &KeyHandle,
        wallet_unit_os: ManagedInstanceOs,
        integrity_check_enabled: bool,
        leeway: Duration,
        nonce: Option<&str>,
    ) -> Result<(), ManagedInstanceError> {
        let (msg, signature) = match (integrity_check_enabled, wallet_unit_os) {
            (true, ManagedInstanceOs::Ios) => webauthn_signed_jwt_to_msg_and_sig(proof)
                .error_while("verifying iOS attestation")?,
            _ => (
                proof.unverified_jwt.as_bytes().to_vec(),
                proof.signature.clone(),
            ),
        };

        public_key
            .verify(&msg, &signature)
            .map_err(|e| ManagedInstanceError::CouldNotVerifyProof(e.to_string()))
            .error_while("verifying attestation proof signature")?;
        validate_proof_payload(proof, leeway, self.base_url.as_deref(), nonce)
    }

    async fn verify_device_signing_proof(
        &self,
        proof: &DecomposedJwt<NoncePayload>,
        public_key: &KeyHandle,
        leeway: Duration,
        nonce: Option<&str>,
    ) -> Result<(), ManagedInstanceError> {
        public_key
            .verify(proof.unverified_jwt.as_bytes(), &proof.signature)
            .map_err(|e| ManagedInstanceError::CouldNotVerifyProof(e.to_string()))
            .error_while("verifying device singing proof signature")?;
        validate_proof_payload(proof, leeway, self.base_url.as_deref(), nonce)
    }

    async fn verify_pop(
        &self,
        pop: &str,
        leeway: Duration,
    ) -> Result<PublicJwk, ManagedInstanceError> {
        let pop_token =
            Jwt::<NoncePayload>::decompose_token(pop).error_while("parsing pop token")?;
        let jwk = pop_token
            .header
            .jwk
            .clone()
            .ok_or(ManagedInstanceError::CouldNotVerifyProof(
                "Missing jwk".to_string(),
            ))
            .error_while("validating PoP header")?;
        let key_handle = self
            .parse_jwk(&pop_token.header.algorithm, &jwk)
            .error_while("parsing JWK")?;
        key_handle
            .verify(pop_token.unverified_jwt.as_bytes(), &pop_token.signature)
            .map_err(|e| ManagedInstanceError::CouldNotVerifyProof(e.to_string()))
            .error_while("verifying PoP signature")?;
        validate_proof_payload(&pop_token, leeway, self.base_url.as_deref(), None)?;
        Ok(jwk)
    }

    pub async fn revoke_managed_instance(
        &self,
        id: &ManagedInstanceId,
    ) -> Result<(), ManagedInstanceError> {
        let managed_instance = self
            .managed_instance_repository
            .get(id)
            .await
            .error_while("getting wallet unit")?;

        if managed_instance.status != InstanceStatus::Active {
            return Err(ManagedInstanceError::WalletUnitMustBeActive
                .error_while("checking status")
                .into());
        }

        self.tx_manager
            .tx(async move {
                match managed_instance.role {
                    InstanceRole::Verifier => {
                        self.revoke_verifier_access_certificates(&managed_instance)
                            .await?;
                    }
                    InstanceRole::Wallet => {
                        // revoke all revocable (and non-expired) attestations
                        let mut attestation_to_revoke_per_revocation_method: HashMap<
                            RevocationMethodId,
                            Vec<ManagedInstanceAttestationRevocationInfo>,
                        > = HashMap::new();
                        let now = crate::clock::now_utc();
                        for attestation_to_revoke in managed_instance
                            .attestations
                            .as_ref()
                            .await?
                            .into_iter()
                            .filter(|attestation| attestation.expiration_date > now)
                            .filter_map(|attestation| attestation.revocation.as_ref())
                        {
                            let attestation = attestation_to_revoke.as_ref().await?.to_owned();
                            let revocation_method = attestation
                                .revocation_list
                                .as_ref()
                                .await?
                                .r#type
                                .to_owned();

                            attestation_to_revoke_per_revocation_method
                                .entry(revocation_method)
                                .or_default()
                                .push(attestation);
                        }

                        for (revocation_method_id, attestation_entries) in
                            attestation_to_revoke_per_revocation_method
                        {
                            let revocation_method = self
                                .revocation_method_provider
                                .get_revocation_method(&revocation_method_id)?;

                            revocation_method
                                .update_attestation_entries(
                                    attestation_entries,
                                    RevocationState::Revoked,
                                )
                                .await
                                .error_while("revoking attestations")?;
                        }
                    }
                };

                self.managed_instance_repository
                    .update(
                        id,
                        UpdateManagedInstanceRequest {
                            status: Some(InstanceStatus::Revoked),
                            ..Default::default()
                        },
                    )
                    .await
                    .error_while("updating wallet unit")?;
                self.create_instance_history(&managed_instance, HistoryAction::Revoked, None)
                    .await;

                Ok::<_, ManagedInstanceError>(())
            }
            .boxed())
            .await
            .error_while("revoking instance")??;

        tracing::info!("Revoked managed instance {}", id);
        Ok(())
    }

    /// Revokes every access certificate signature linked to a verifier managed instance.
    async fn revoke_verifier_access_certificates(
        &self,
        instance: &ManagedInstance,
    ) -> Result<(), ManagedInstanceError> {
        let Some(signature_ids) = &instance.verifier_signature_ids else {
            return Ok(());
        };

        for signature_id in signature_ids {
            let (_, signer) = self
                .signer_provider
                .get_for_signature_id((*signature_id).into())
                .await
                .error_while("getting signer for access certificate signature")?;

            let Some(revocation_method) = signer
                .revocation_method()
                .error_while("getting signer revocation method")?
            else {
                continue;
            };

            revocation_method
                .revoke_signature(*signature_id)
                .await
                .error_while("revoking access certificate signature")?;
        }
        Ok(())
    }

    pub async fn delete_managed_instance(
        &self,
        id: &ManagedInstanceId,
    ) -> Result<(), ManagedInstanceError> {
        let wallet_unit = self
            .managed_instance_repository
            .get(id)
            .await
            .error_while("getting wallet unit")?;

        if wallet_unit.status != InstanceStatus::Pending {
            return Err(ManagedInstanceError::WalletUnitMustBePending
                .error_while("checking status")
                .into());
        }

        // Revoke linked access certificates before deleting the instance: once deleted, its
        // verifier_signature_ids are gone and a failure here could no longer be retried.
        if wallet_unit.role == InstanceRole::Verifier {
            self.revoke_verifier_access_certificates(&wallet_unit)
                .await?;
        }

        self.managed_instance_repository
            .delete(id)
            .await
            .error_while("deleting wallet unit")?;
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
    ) -> Result<WalletProviderMetadataResponseDTO, ManagedInstanceError> {
        let (_, params) = self.get_wallet_provider_config_params(&wallet_provider)?;
        let (enabled, required) = match params.wallet_registration {
            WalletRegistrationRequirement::Mandatory => (true, true),
            WalletRegistrationRequirement::Optional => (true, false),
            WalletRegistrationRequirement::Disabled => (false, false),
        };

        // The advertised ecosystems, and the entities belonging to them, are the
        // ones of the organisation owning this provider.
        let organisation = self
            .organisation_repository
            .get_organisation_for_wallet_provider(&wallet_provider)
            .await
            .error_while("getting wallet provider organisation")?;

        if organisation.is_none() {
            tracing::warn!(
                "Wallet provider `{wallet_provider}` is not associated with any organisation"
            );
        }

        let ecosystems = ecosystem_metadata(
            &self.config,
            organisation.as_ref(),
            EcosystemEntityRepositories {
                trust_collections: &*self.trust_collection_repository,
                credential_schemas: &*self.credential_schema_repository,
                proof_schemas: None,
            },
        )
        .await?;

        let document_signers = params
            .document_signers
            .into_iter()
            .map(|name| {
                let metadata = self
                    .document_signer_provider
                    .metadata(&name)
                    .error_while("getting document signer metadata")?;

                Ok(DocumentSignerMetadataDTO {
                    name,
                    r#type: metadata.r#type,
                    display_name: params_into_display_names(metadata.display_name),
                    description: params_into_display_names(metadata.description),
                    logo: metadata.logo,
                })
            })
            .collect::<Result<Vec<_>, ManagedInstanceError>>()?;

        Ok(WalletProviderMetadataResponseDTO {
            wallet_unit_attestation: WalletUnitAttestationMetadataDTO {
                app_integrity_check_required: params
                    .wallet_instance_attestation
                    .integrity_check
                    .enabled,
                enabled,
                required,
            },
            name: wallet_provider,
            app_version: params.app_version,
            trust_collections: provider_trust_collections(&ecosystems),
            feature_flags: FeatureFlags {
                ecosystems_enabled: params.feature_flags.ecosystems_enabled,
                refresh_credential_batch_enabled: params
                    .feature_flags
                    .refresh_credential_batch_enabled,
                document_signing_enabled: params.feature_flags.document_signing_enabled,
                ecosystems_enforcement_enabled: params.feature_flags.ecosystems_enforcement_enabled,
            },
            user_authentication: convert_inner(params.user_authentication),
            document_signers,
            ecosystems,
        })
    }

    pub(super) async fn validate_user_id_token(
        &self,
        user_id_token: Option<&str>,
        user_authentication: Option<&UserAuthenticationParams>,
        user_nonce: Option<&str>,
    ) -> Result<Option<String>, ManagedInstanceError> {
        let Some(user_id_token) = user_id_token else {
            if user_authentication.is_some_and(|ua| ua.required) {
                return Err(ManagedInstanceError::MissingUserIdToken);
            }
            return Ok(None);
        };

        let Some(user_auth) = user_authentication else {
            return Err(ManagedInstanceError::UserIdTokenNotExpected);
        };

        let token = Jwt::<UserIdTokenClaims>::decompose_token(user_id_token)
            .map_err(|e| ManagedInstanceError::InvalidUserIdToken(e.to_string()))
            .error_while("parsing user ID token")?;

        let jwks: UserIdTokenJwks = self
            .http_client
            .get(&user_auth.token_validation.jwks_uri)
            .header("Accept", "application/json")
            .send()
            .await
            .error_while("fetching JWKS")?
            .error_for_status()
            .error_while("fetchin JWKS returned error")?
            .json()
            .error_while("deserializing JWKS")?;

        let kid = token.header.key_id.as_deref();
        let matching_jwk = jwks
            .keys
            .iter()
            .find(|k| kid.is_none() || k.kid() == kid)
            .ok_or_else(|| {
                ManagedInstanceError::InvalidUserIdToken(
                    "No matching key found in JWKS".to_string(),
                )
            })?;

        let (_, alg) = self
            .key_algorithm_provider
            .key_algorithm_from_jose_alg(&token.header.algorithm)
            .ok_or_else(|| {
                ManagedInstanceError::InvalidUserIdToken(format!(
                    "Unsupported algorithm: {}",
                    token.header.algorithm
                ))
            })?;

        let key_handle = alg
            .parse_jwk(matching_jwk)
            .map_err(|e| ManagedInstanceError::InvalidUserIdToken(e.to_string()))
            .error_while("parsing JWKS key")?;

        key_handle
            .verify(token.unverified_jwt.as_bytes(), &token.signature)
            .map_err(|e| ManagedInstanceError::InvalidUserIdToken(e.to_string()))
            .error_while("verifying user ID token signature")?;

        if token.payload.issuer.as_deref() != Some(&user_auth.token_validation.iss) {
            return Err(
                ManagedInstanceError::InvalidUserIdToken("Invalid issuer".to_string())
                    .error_while("validating iss")
                    .into(),
            );
        }

        let aud_matches = token
            .payload
            .audience
            .as_ref()
            .is_some_and(|aud| aud.iter().any(|a| a == &user_auth.token_validation.aud));
        if !aud_matches {
            return Err(
                ManagedInstanceError::InvalidUserIdToken("Invalid audience".to_string())
                    .error_while("validating aud")
                    .into(),
            );
        }

        let expected_nonce = user_nonce.ok_or_else(|| {
            ManagedInstanceError::InvalidUserIdToken(
                "Missing user nonce in wallet instance".to_string(),
            )
        })?;
        let token_nonce = token.payload.custom.nonce.as_deref().unwrap_or("");
        if token_nonce != expected_nonce {
            return Err(
                ManagedInstanceError::InvalidUserIdToken("Invalid nonce".to_string())
                    .error_while("validating nonce")
                    .into(),
            );
        }

        let sub = token
            .payload
            .subject
            .ok_or_else(|| ManagedInstanceError::InvalidUserIdToken("Missing sub".to_string()))?;

        Ok(Some(sub))
    }
}

#[derive(serde::Deserialize)]
struct UserIdTokenJwks {
    keys: Vec<PublicJwk>,
}

#[derive(Debug, serde::Deserialize, Default)]
struct UserIdTokenClaims {
    nonce: Option<String>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessCertificateProvisioningRequest {
    provider: String,
    managed_instance_id: ManagedInstanceId,
    verifier_provider_organisation_id: OrganisationId,
}

#[derive(Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccessCertificateProvisioningResponse {
    access_certificate: String,
    signature_id: RevocationListEntryId,
}

/// Registration/activation parameters normalized across wallet and verifier providers.
struct ProviderRegistrationParams {
    name_label: String,
    integrity_check: IntegrityCheck,
    device_auth_leeway: Duration,
    user_authentication: Option<UserAuthenticationParams>,
    /// Only ever set for `InstanceRole::Verifier`.
    access_certificate_configuration: Option<AccessCertificateConfiguration>,
}

struct IssuerKey {
    public_key_info: JwtPublicKeyInfo,
    auth_fn: AuthenticationFn,
}

struct SignedAttestation {
    jwt: String,
    hash: String,
}

impl IssuerKey {
    async fn sign_jwt<CustomPayload: Serialize>(
        &self,
        r#type: String,
        payload: JWTPayload<CustomPayload>,
    ) -> Result<SignedAttestation, ManagedInstanceError> {
        let jose_alg = self
            .auth_fn
            .jose_alg()
            .error_while("preparing attestation header")?;
        let key_id = self.auth_fn.get_key_id();

        let jwt = Jwt::new(
            r#type,
            jose_alg,
            key_id,
            Some(self.public_key_info.to_owned()),
            payload,
        );
        let jwt = jwt
            .tokenize(Some(self.auth_fn.as_ref()))
            .await
            .error_while("creating WUA token")?;

        let hash = SHA256.hash_base64(jwt.as_bytes()).map_err(|e| {
            ManagedInstanceError::MappingError(format!(
                "Could not hash wallet unit attestation: {e}"
            ))
        })?;

        Ok(SignedAttestation { jwt, hash })
    }
}
