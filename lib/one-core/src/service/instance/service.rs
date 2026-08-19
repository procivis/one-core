use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;

use shared_types::{EcosystemId, InstanceId, ManagedInstanceId};
use standardized_types::jwk::PublicJwk;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use super::InstanceService;
use super::dto::{
    HolderActivateInstanceRequestDTO, HolderActivateInstanceResponseDTO, HolderInstanceResponseDTO,
    HolderRegisterInstanceRequestDTO, HolderRegisterInstanceResponseDTO, NoncePayload,
};
use super::error::HolderInstanceError;
use super::mapper::{instance_to_detail_dto, key_from_generated_key};
use crate::config::core_config::{KeyAlgorithmType, KeyStorageType};
use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, ErrorCodeMixinExt};
use crate::model::certificate::CertificateRole;
use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::model::instance::{
    Instance, InstanceRole, InstanceStatus, UpdateInstanceRequest, WalletProviderType,
};
use crate::model::key::Key;
use crate::model::managed_instance::ManagedInstanceOs;
use crate::model::organisation::{Organisation, UpdateOrganisationRequest};
use crate::proto::csr_creator::{CsrRequestProfile, CsrRequestSubject, GenerateCsrRequest};
use crate::proto::identifier_creator::CreateLocalIdentifierRequest;
use crate::proto::jwt::model::JWTPayload;
use crate::proto::jwt::{Jwt, JwtPublicKeyInfo};
use crate::proto::session_provider::SessionExt;
use crate::proto::wallet_instance::WalletUnitStatusCheckResponse;
use crate::proto::wallet_provider_client::dto::MetadataTarget;
use crate::proto::wallet_provider_client::error::WalletProviderClientError;
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::key_storage::KeyStorage;
use crate::provider::key_storage::error::KeyStorageError;
use crate::repository::error::DataLayerError;
use crate::service::certificate::dto::CreateCertificateRequestDTO;
use crate::service::managed_instance::dto::{
    ActivateWalletUnitRequestDTO, EcosystemMetadataDTO, RegisterWalletUnitRequestDTO,
    RegisterWalletUnitResponseDTO, UserAuthenticationDTO, WalletUnitAttestationMetadataDTO,
};
use crate::service::managed_instance::ecosystem_metadata::remote_trust_collections;
use crate::validator::throw_if_org_id_not_matching_session;

/// Provider metadata relevant for instance registration, unified over the
/// wallet-provider and verifier-provider metadata endpoints.
pub(super) struct ProviderMetadata {
    pub name: String,
    pub attestation: WalletUnitAttestationMetadataDTO,
    pub user_authentication: Option<UserAuthenticationDTO>,
    pub ecosystems: Vec<EcosystemMetadataDTO>,
    pub credential_schemas: Vec<String>,
    pub proof_schemas: Vec<String>,
    pub access_certificate_provisioning_enabled: bool,
    /// Whether the provider requires the instances it backs to enforce the ecosystems it
    /// advertises.
    pub ecosystems_enforcement_enabled: bool,
}

pub(crate) fn provider_metadata_url(
    provider_url: &str,
    provider_name: &str,
    role: InstanceRole,
) -> String {
    match role {
        InstanceRole::Wallet => {
            format!("{provider_url}/ssi/wallet-provider/v1/{provider_name}")
        }
        InstanceRole::Verifier => {
            format!("{provider_url}/ssi/verifier-provider/v1/{provider_name}")
        }
    }
}

impl InstanceService {
    pub async fn register_instance(
        &self,
        request: HolderRegisterInstanceRequestDTO,
    ) -> Result<HolderRegisterInstanceResponseDTO, HolderInstanceError> {
        throw_if_org_id_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("checking session")?;
        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id)
            .await
            .error_while("getting organisation")?;

        if organisation.deactivated_at.is_some() {
            return Err(HolderInstanceError::OrganisationIsDeactivated(
                request.organisation_id,
            ));
        }

        let existing_instance = self
            .instance_repository
            .get_by_role(request.role, organisation.id)
            .await
            .error_while("checking presence of instance")?;
        if let Some(existing_instance) = existing_instance {
            if existing_instance.status != InstanceStatus::Error {
                return Err(HolderInstanceError::WalletInstanceAlreadyExists(
                    existing_instance.id,
                ));
            }
            // A failed (Error) instance is left behind when registration is aborted (e.g.
            // expired nonce). Remove it so the holder can restart registration
            self.instance_repository
                .delete(&existing_instance.id)
                .await
                .error_while("deleting failed instance")?;
        }

        let (os, key_storage_id) = self.resolve_os_and_key_storage().await?;
        let key_type = self.parse_and_validate_key_type(&request.key_type)?;

        let provider_url = Url::from_str(&request.provider.url)
            .map_err(HolderInstanceError::InvalidWalletProviderUrl)?
            .origin()
            .ascii_serialization();
        let metadata = self
            .fetch_provider_metadata_for_url(
                request.role,
                &request.provider.url,
                request.provider.r#type,
            )
            .await?;
        let provider_info = ProviderInfo {
            name: metadata.name.clone(),
            url: provider_url.clone(),
        };

        self.schema_importer
            .import_schemas(
                &metadata.credential_schemas,
                &metadata.proof_schemas,
                &organisation,
            )
            .await;

        let is_web = os == ManagedInstanceOs::Web;
        let is_integrity_check_required =
            metadata.attestation.app_integrity_check_required && !is_web;
        // Web instances cannot perform the user binding flow, so it is skipped for them. If the
        // provider mandates user authentication, web instances cannot be registered at all.
        if is_web
            && metadata
                .user_authentication
                .as_ref()
                .is_some_and(|user_authentication| user_authentication.required)
        {
            return Err(HolderInstanceError::UserAuthenticationNotSupported);
        }
        let is_authentication_required = metadata.user_authentication.is_some() && !is_web;

        let registration_status = match (is_authentication_required, is_integrity_check_required) {
            (true, true) => {
                self.register_pending_integrity_check(&provider_info, os, request.role)
                    .await?
            }
            (true, false) => {
                self.register_pending_no_integrity_check(
                    &provider_info,
                    key_storage_id,
                    key_type,
                    os,
                    organisation.clone(),
                    request.role,
                )
                .await?
            }
            (false, true) => {
                self.register_and_activate_with_integrity_check(
                    &provider_info,
                    key_storage_id,
                    key_type,
                    os,
                    organisation.clone(),
                    request.role,
                )
                .await?
            }
            (false, false) => {
                self.register_active(
                    &provider_info,
                    key_storage_id,
                    key_type,
                    os,
                    organisation.clone(),
                    request.role,
                )
                .await?
            }
        };

        let instance =
            registration_status.map_to_instance(&request, &organisation, provider_url, &metadata);
        let user_nonce = instance.user_nonce.clone();
        let status = instance.status;

        let instance_id = self
            .instance_repository
            .create(instance)
            .await
            .error_while("creating holder wallet unit")?;

        let now = crate::clock::now_utc();
        let name = format!(
            "{}-{}-{}",
            request.provider.r#type,
            os,
            now.unix_timestamp()
        );
        let success_log = format!(
            "Registered instance `{name}`({instance_id}) using provider `{}`, with status {status}",
            request.provider.url
        );
        self.history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: now,
                action: HistoryAction::Created,
                name,
                source: HistorySource::Core,
                target: None,
                entity_id: Some(instance_id.into()),
                entity_type: HistoryEntityType::WalletUnit,
                metadata: None,
                metadata_blob_id: None,
                organisation_id: Some(organisation.id),
                user: self.session_provider.session().user(),
            })
            .await
            .error_while("creating history")?;

        self.trust_collection_manager
            .create_empty_trust_collections(
                &request.provider.url,
                remote_trust_collections(&metadata.ecosystems),
                organisation.id,
            )
            .await
            .error_while("creating empty trust collections")?;

        self.align_organisation_configuration(&organisation, &metadata, request.role)
            .await?;

        tracing::info!(message = success_log);
        Ok(HolderRegisterInstanceResponseDTO {
            id: instance_id,
            status,
            user_nonce,
        })
    }

    /// Brings the configuration of the organisation the instance was registered for in line
    /// with the settings of the provider backing it: ecosystems the provider does not
    /// advertise are deselected, and enforcement of the selected ecosystems is turned on when
    /// the provider mandates it.
    ///
    /// Enforcement is only turned on for the role the registered instance covers - a wallet
    /// instance acts as holder, a verifier instance as verifier - and never turned off: a
    /// provider not mandating it leaves the choice to the organisation.
    async fn align_organisation_configuration(
        &self,
        organisation: &Organisation,
        metadata: &ProviderMetadata,
        role: InstanceRole,
    ) -> Result<(), HolderInstanceError> {
        let mut configuration = organisation.configuration.clone();

        let advertised: HashSet<&EcosystemId> = metadata
            .ecosystems
            .iter()
            .map(|ecosystem| &ecosystem.name)
            .collect();
        configuration.selected_ecosystems.retain(|ecosystem| {
            let advertised = advertised.contains(ecosystem);
            if !advertised {
                tracing::info!(
                    "Deselecting ecosystem `{ecosystem}` of organisation `{}`: not advertised by provider `{}`",
                    organisation.id,
                    metadata.name,
                );
            }
            advertised
        });

        if metadata.ecosystems_enforcement_enabled {
            match role {
                InstanceRole::Wallet => configuration.enforce_ecosystem_as_holder = true,
                InstanceRole::Verifier => configuration.enforce_ecosystem_as_verifier = true,
            }
        }

        if configuration == organisation.configuration {
            return Ok(());
        }

        self.organisation_repository
            .update_organisation(
                &organisation.id,
                UpdateOrganisationRequest {
                    configuration: Some(configuration),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating organisation configuration")?;

        Ok(())
    }

    pub async fn holder_activate(
        &self,
        id: InstanceId,
        request: HolderActivateInstanceRequestDTO,
    ) -> Result<HolderActivateInstanceResponseDTO, HolderInstanceError> {
        let holder_wallet_instance = self
            .instance_repository
            .get(&id)
            .await
            .error_while("getting holder wallet instance")?;

        let organisation_id = holder_wallet_instance.organisation.id();
        throw_if_org_id_not_matching_session(&organisation_id, &*self.session_provider)
            .error_while("checking session")?;

        let organisation = self
            .organisation_repository
            .get_organisation(&organisation_id)
            .await
            .error_while("getting organisation")?;

        if holder_wallet_instance.status != InstanceStatus::Pending {
            return Err(HolderInstanceError::WalletUnitNotPending);
        }

        let metadata_url = provider_metadata_url(
            &holder_wallet_instance.provider_url,
            &holder_wallet_instance.provider_name,
            holder_wallet_instance.role,
        );
        let metadata = self
            .fetch_provider_metadata_for_url(
                holder_wallet_instance.role,
                &metadata_url,
                holder_wallet_instance.provider_type,
            )
            .await?;

        let Some(user_authentication) = metadata.user_authentication else {
            return Err(HolderInstanceError::UserAuthenticationNotConfigured);
        };

        let user_id_token = request.user_id_token;
        // The id token is optional at activate. Fail early (without calling the wallet provider)
        // only when authentication is required but no token was supplied.
        if user_authentication.required && user_id_token.is_none() {
            return Err(HolderInstanceError::UserAuthenticationRequired);
        }

        let key_type = self.parse_and_validate_key_type(&request.key_type)?;

        let user_access_token = request.user_access_token;
        let (verifier_access_certificate_csr, access_certificate_key) =
            if metadata.access_certificate_provisioning_enabled && user_access_token.is_some() {
                let (csr, key) = self
                    .prepare_csr_for_access_cert_provisioning(key_type, &organisation)
                    .await?;
                (Some(csr), Some(key))
            } else {
                (None, None)
            };

        let activation_status = if let Some(nonce) = holder_wallet_instance.nonce {
            let (os, key_storage_id) = self.resolve_os_and_key_storage().await?;

            let provider_info = ProviderInfo {
                name: holder_wallet_instance.provider_name.clone(),
                url: holder_wallet_instance.provider_url.clone(),
            };

            match self
                .activate_with_integrity_check(
                    &provider_info,
                    key_storage_id,
                    key_type,
                    os,
                    organisation.clone(),
                    holder_wallet_instance.provider_instance_id,
                    nonce,
                    user_id_token,
                    user_access_token,
                    verifier_access_certificate_csr,
                )
                .await
            {
                Ok(RegistrationStatus::Active {
                    key,
                    access_certificate,
                    ..
                }) => Ok((InstanceStatus::Active, Some(key.id), access_certificate)),
                Ok(
                    RegistrationStatus::PendingNoIntegrityCheck { .. }
                    | RegistrationStatus::PendingIntegrityCheck { .. }
                    | RegistrationStatus::Unattested { .. },
                ) => Ok((InstanceStatus::Unattested, None, None)),
                Err(err) => Err(err),
            }
        } else {
            let activate_request = ActivateWalletUnitRequestDTO {
                attestation: None,
                attestation_key_proof: None,
                device_signing_key_proof: None,
                user_id_token,
                user_access_token,
                verifier_access_certificate_csr,
            };

            match self
                .wallet_provider_client
                .activate(
                    &holder_wallet_instance.provider_url,
                    holder_wallet_instance.provider_instance_id,
                    activate_request,
                )
                .await
            {
                Ok(result) => Ok((InstanceStatus::Active, None, result.access_certificate)),
                Err(WalletProviderClientError::WalletUnitNonceExpired) => {
                    Err(HolderInstanceError::WalletUnitRegistrationExpired)
                }
                Err(err) if err.error_code() == ErrorCode::BR_0395 => {
                    tracing::warn!("Activation request failed: {err}");
                    Ok((InstanceStatus::Unattested, None, None))
                }
                Err(err) => Err(err.error_while("activating wallet unit").into()),
            }
        };

        let (status, authentication_key_id, access_certificate) = match activation_status {
            Err(HolderInstanceError::WalletUnitRegistrationExpired) => {
                // The registration nonce has expired. Mark the instance failed (out of PENDING)
                // so the wallet restarts registration from scratch instead of re-activating
                // against the dead nonce.
                self.instance_repository
                    .update(
                        &id,
                        UpdateInstanceRequest {
                            status: Some(InstanceStatus::Error),
                            ..Default::default()
                        },
                    )
                    .await
                    .error_while("marking holder wallet instance failed")?;
                return Err(HolderInstanceError::WalletUnitRegistrationExpired);
            }
            other => other.error_while("activating wallet unit")?,
        };

        self.instance_repository
            .update(
                &id,
                UpdateInstanceRequest {
                    status: Some(status),
                    authentication_key_id,
                    ..Default::default()
                },
            )
            .await
            .error_while("updating holder wallet instance status")?;

        let access_certificate_identifier_id = match (access_certificate, access_certificate_key) {
            (Some(pem_chain), Some(key)) => {
                self.store_key(&key).await?;
                let name = format!("provisioned-AC-{}", key.id);
                let identifier = self
                    .identifier_creator
                    .create_local_identifier(
                        name.to_owned(),
                        CreateLocalIdentifierRequest::Certificate(vec![
                            CreateCertificateRequestDTO {
                                name: Some(name),
                                chain: Some(pem_chain),
                                key_id: key.id,
                                content: None,
                                roles: vec![
                                    CertificateRole::AssertionMethod,
                                    CertificateRole::Authentication,
                                ],
                            },
                        ]),
                        organisation,
                    )
                    .await
                    .error_while("creating local identifier")?;
                Some(identifier.id)
            }
            _ => None,
        };

        Ok(HolderActivateInstanceResponseDTO {
            access_certificate_identifier_id,
        })
    }

    async fn generate_attestation_key(
        &self,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        organisation: Organisation,
        nonce: Option<String>,
    ) -> Result<Option<Key>, HolderInstanceError> {
        let key_storage = self.key_provider.get_key_storage(key_storage_id)?;

        let key_id = Uuid::new_v4().into();
        let attestation_key = match key_storage.generate_attestation_key(key_id, nonce).await {
            Ok(key) => key,
            Err(KeyStorageError::NotSupported(description)) => {
                tracing::info!("Attestation keys not supported: {description}");
                return Ok(None);
            }
            Err(err) => return Err(err.error_while("getting attestation key").into()),
        };
        let attestation_key = key_from_generated_key(
            key_id,
            key_storage_id,
            key_type.as_ref(),
            organisation,
            attestation_key,
        );
        self.store_key(&attestation_key).await?;
        Ok(Some(attestation_key))
    }

    pub async fn holder_get_instance_details(
        &self,
        id: InstanceId,
    ) -> Result<HolderInstanceResponseDTO, HolderInstanceError> {
        Ok(instance_to_detail_dto(
            self.instance_repository
                .get(&id)
                .await
                .error_while("getting holder wallet unit")?,
        )
        .await
        .error_while("converting model")?)
    }

    async fn fetch_provider_metadata_for_url(
        &self,
        role: InstanceRole,
        metadata_url: &str,
        provider_type: WalletProviderType,
    ) -> Result<ProviderMetadata, HolderInstanceError> {
        Ok(match role {
            InstanceRole::Wallet => self
                .wallet_provider_client
                .get_wallet_provider_metadata(MetadataTarget {
                    r#type: provider_type,
                    metadata_url: metadata_url.to_string(),
                })
                .await
                .error_while("getting wallet provider metadata")?
                .into(),
            InstanceRole::Verifier => self
                .verifier_provider_client
                .get_verifier_provider_metadata(metadata_url)
                .await
                .error_while("getting verifier provider metadata")?
                .into(),
        })
    }

    pub async fn holder_instance_status(&self, id: InstanceId) -> Result<(), HolderInstanceError> {
        let holder_wallet_unit = self
            .instance_repository
            .get(&id)
            .await
            .error_while("getting holder wallet unit")?;

        if holder_wallet_unit.status != InstanceStatus::Active {
            return Ok(());
        }

        let wallet_unit_status = self
            .wallet_unit_proto
            .check_wallet_unit_status(&holder_wallet_unit)
            .await
            .error_while("checking wallet unit status")?;

        if wallet_unit_status == WalletUnitStatusCheckResponse::Revoked {
            self.instance_repository
                .update(
                    &id,
                    UpdateInstanceRequest {
                        status: Some(InstanceStatus::Revoked),
                        ..Default::default()
                    },
                )
                .await
                .error_while("updating holder wallet unit")?;

            self.history_repository
                .create_history(History {
                    id: Uuid::new_v4().into(),
                    action: HistoryAction::Revoked,
                    name: holder_wallet_unit.provider_name.clone(),
                    source: HistorySource::Core,
                    target: None,
                    entity_id: Some(id.into()),
                    entity_type: HistoryEntityType::WalletUnit,
                    metadata: None,
                    metadata_blob_id: None,
                    organisation_id: Some(holder_wallet_unit.organisation.id()),
                    user: self.session_provider.session().user(),
                    created_date: crate::clock::now_utc(),
                })
                .await
                .error_while("creating history")?;
        }
        Ok(())
    }

    /// Authentication required, integrity check required: register without a key (the attestation
    /// key is generated during activation) and store both nonces. Stays pending until activation.
    async fn register_pending_integrity_check(
        &self,
        provider_info: &ProviderInfo,
        os: ManagedInstanceOs,
        role: InstanceRole,
    ) -> Result<RegistrationStatus, HolderInstanceError> {
        let register_response = self
            .register(
                &provider_info.url,
                RegisterWalletUnitRequestDTO {
                    provider: provider_info.name.clone(),
                    role,
                    os,
                    public_key: None,
                    proof: None,
                },
            )
            .await
            .error_while("registering")?;
        let Some(user_nonce) = register_response.user_nonce else {
            // authentication check was expected but is not required
            return Err(HolderInstanceError::UserAuthenticationNotRequired);
        };
        let Some(nonce) = register_response.nonce else {
            // integrity check was expected but is not required
            return Err(HolderInstanceError::AppIntegrityCheckNotRequired);
        };
        Ok(RegistrationStatus::PendingIntegrityCheck {
            wallet_instance_id: register_response.id,
            user_nonce,
            nonce,
        })
    }

    /// Authentication required, no integrity check: register with a key right away and store the
    /// user nonce. Stays pending until the user authenticates during activation.
    async fn register_pending_no_integrity_check(
        &self,
        provider_info: &ProviderInfo,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        os: ManagedInstanceOs,
        organisation: Organisation,
        role: InstanceRole,
    ) -> Result<RegistrationStatus, HolderInstanceError> {
        let (key, register_response) = self
            .register_without_integrity_check(
                provider_info,
                key_storage_id,
                key_type,
                os,
                organisation,
                role,
            )
            .await?;
        let Some(user_nonce) = register_response.user_nonce else {
            // authentication check was expected but is not required
            return Err(HolderInstanceError::UserAuthenticationNotRequired);
        };
        if register_response.nonce.is_some() {
            // integrity check was not expected but is required
            return Err(HolderInstanceError::AppIntegrityCheckRequired);
        }
        Ok(RegistrationStatus::PendingNoIntegrityCheck {
            wallet_instance_id: register_response.id,
            user_nonce,
            key,
        })
    }

    /// No authentication, integrity check required: register without a key, then activate
    /// immediately with the attestation (no user token).
    async fn register_and_activate_with_integrity_check(
        &self,
        provider_info: &ProviderInfo,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        os: ManagedInstanceOs,
        organisation: Organisation,
        role: InstanceRole,
    ) -> Result<RegistrationStatus, HolderInstanceError> {
        let register_response = self
            .register(
                &provider_info.url,
                RegisterWalletUnitRequestDTO {
                    provider: provider_info.name.clone(),
                    role,
                    os,
                    public_key: None,
                    proof: None,
                },
            )
            .await
            .error_while("registering")?;
        if register_response.user_nonce.is_some() {
            // authentication was not expected but is required
            return Err(HolderInstanceError::UserAuthenticationRequired);
        }
        let Some(nonce) = register_response.nonce else {
            // integrity check was expected but is not required
            return Err(HolderInstanceError::AppIntegrityCheckNotRequired);
        };
        self.activate_with_integrity_check(
            provider_info,
            key_storage_id,
            key_type,
            os,
            organisation,
            register_response.id,
            nonce,
            None,
            None,
            None,
        )
        .await
    }

    /// No authentication, no integrity check: register with a key and activate in a single step.
    async fn register_active(
        &self,
        provider_info: &ProviderInfo,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        os: ManagedInstanceOs,
        organisation: Organisation,
        role: InstanceRole,
    ) -> Result<RegistrationStatus, HolderInstanceError> {
        let (key, register_response) = self
            .register_without_integrity_check(
                provider_info,
                key_storage_id,
                key_type,
                os,
                organisation,
                role,
            )
            .await?;
        if register_response.user_nonce.is_some() {
            // authentication was not expected but is required
            return Err(HolderInstanceError::UserAuthenticationRequired);
        }
        if register_response.nonce.is_some() {
            // integrity check was not expected but is required
            return Err(HolderInstanceError::AppIntegrityCheckRequired);
        }
        Ok(RegistrationStatus::Active {
            wallet_instance_id: register_response.id,
            key,
            access_certificate: None,
        })
    }

    async fn register_without_integrity_check(
        &self,
        provider_info: &ProviderInfo,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        os: ManagedInstanceOs,
        organisation: Organisation,
        role: InstanceRole,
    ) -> Result<(Key, RegisterWalletUnitResponseDTO), HolderInstanceError> {
        let (key, signed_proof) = self
            .generate_key_and_proof(key_storage_id, key_type, organisation, provider_info, None)
            .await?;

        let key_storage = self.key_provider.get_key_storage(key_storage_id)?;
        let key_handle = key_storage
            .key_handle(&key)
            .error_while("getting key handle")?;

        let register_request = RegisterWalletUnitRequestDTO {
            provider: provider_info.name.clone(),
            role,
            os,
            public_key: Some(key_handle.public_key_as_jwk().error_while("creating JWK")?),
            proof: Some(signed_proof),
        };

        let response = self
            .register(&provider_info.url, register_request)
            .await
            .error_while("registering")?;
        Ok((key, response))
    }

    #[expect(clippy::too_many_arguments)]
    async fn activate_with_integrity_check(
        &self,
        provider_info: &ProviderInfo,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        os: ManagedInstanceOs,
        organisation: Organisation,
        wallet_instance_id: ManagedInstanceId,
        nonce: String,
        user_id_token: Option<String>,
        user_access_token: Option<String>,
        verifier_access_certificate_csr: Option<String>,
    ) -> Result<RegistrationStatus, HolderInstanceError> {
        let attestations_key = self
            .generate_attestation_key(
                key_storage_id,
                key_type,
                organisation.clone(),
                Some(nonce.clone()),
            )
            .await?;

        let proofs = if let Some(attestations_key) = attestations_key {
            self.build_attestation_proofs(
                attestations_key,
                key_storage_id,
                key_type,
                organisation,
                provider_info,
                Some(nonce),
                os,
            )
            .await?
        } else {
            return Ok(RegistrationStatus::Unattested { wallet_instance_id });
        };

        let activate_request = ActivateWalletUnitRequestDTO {
            attestation: Some(proofs.attestation),
            attestation_key_proof: Some(proofs.attestation_key_proof),
            device_signing_key_proof: proofs.device_sig_pop,
            user_id_token,
            user_access_token,
            verifier_access_certificate_csr,
        };

        let access_certificate = match self
            .wallet_provider_client
            .activate(&provider_info.url, wallet_instance_id, activate_request)
            .await
        {
            Ok(result) => result.access_certificate,
            Err(WalletProviderClientError::WalletUnitNonceExpired) => {
                return Err(HolderInstanceError::WalletUnitRegistrationExpired);
            }
            Err(err)
                if err.error_code() == ErrorCode::BR_0395
                    || matches!(err, WalletProviderClientError::InsufficientSecurityLevel) =>
            {
                tracing::warn!("Activation request failed: {err}");
                return Ok(RegistrationStatus::Unattested { wallet_instance_id });
            }
            Err(err) => return Err(err.error_while("activating wallet unit").into()),
        };

        Ok(RegistrationStatus::Active {
            wallet_instance_id,
            key: proofs.key,
            access_certificate,
        })
    }

    async fn new_key(
        &self,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        organisation: Organisation,
        key_storage: &Arc<dyn KeyStorage>,
    ) -> Result<Key, HolderInstanceError> {
        let key_id = Uuid::new_v4().into();
        let key = key_storage
            .generate(key_id, key_type, serde_json::json!({}))
            .await
            .error_while("generating key")?;
        let key =
            key_from_generated_key(key_id, key_storage_id, key_type.as_ref(), organisation, key);
        self.store_key(&key).await?;
        Ok(key)
    }

    #[expect(clippy::too_many_arguments)]
    async fn build_attestation_proofs(
        &self,
        attestation_key: Key,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        organisation: Organisation,
        provider_info: &ProviderInfo,
        nonce: Option<String>,
        os: ManagedInstanceOs,
    ) -> Result<AttestationProofs, HolderInstanceError> {
        let key_storage = self.key_provider.get_key_storage(key_storage_id)?;

        let attestation = key_storage
            .generate_attestation(&attestation_key, nonce.clone())
            .await
            .error_while("getting attestation")?;

        // Use SignatureProvider that uses the attestation key and the key_storage.sign_with_attestation_key method
        let auth_fn = self.key_provider.get_attestation_signature_provider(
            &attestation_key,
            None,
            self.key_algorithm_provider.clone(),
        )?;
        let attestation_key_proof = self
            .create_signed_key_possession_proof(
                crate::clock::now_utc(),
                &provider_info.name,
                auth_fn,
                &provider_info.url,
                nonce.clone(),
            )
            .await?;

        let (device_sig_pop, device_sig_key) = if os == ManagedInstanceOs::Ios {
            let device_signing_key = self
                .new_key(key_storage_id, key_type, organisation, &key_storage)
                .await?;

            let key_handle = key_storage
                .key_handle(&device_signing_key)
                .error_while("getting key handle")?;

            let auth_fn = self.key_provider.get_signature_provider(
                &device_signing_key,
                None,
                self.key_algorithm_provider.clone(),
            )?;
            let signed_proof = self
                .create_device_signing_key_pop(
                    crate::clock::now_utc(),
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

        Ok(AttestationProofs {
            attestation,
            attestation_key_proof,
            device_sig_pop,
            key: device_sig_key.unwrap_or(attestation_key),
        })
    }

    async fn resolve_os_and_key_storage(
        &self,
    ) -> Result<(ManagedInstanceOs, &str), HolderInstanceError> {
        let os = ManagedInstanceOs::from(self.os_info_provider.get_os_name().await);
        let key_storage_type = match os {
            ManagedInstanceOs::Android | ManagedInstanceOs::Ios => KeyStorageType::SecureElement,
            ManagedInstanceOs::Web => KeyStorageType::Internal,
        };
        let key_storage_id = self
            .config
            .key_storage
            .iter()
            .filter(|(_, v)| v.enabled && v.r#type == key_storage_type)
            .map(|(k, _)| k)
            .next()
            .ok_or_else(|| {
                HolderInstanceError::NoMatchingKeyStorage(format!(
                    "No enabled key storage of type {key_storage_type}"
                ))
            })?;
        Ok((os, key_storage_id))
    }

    fn parse_and_validate_key_type(
        &self,
        key_type: &str,
    ) -> Result<KeyAlgorithmType, HolderInstanceError> {
        let parsed = KeyAlgorithmType::from_str(key_type)
            .map_err(|err| HolderInstanceError::InvalidKeyAlgorithm(err.to_string()))?;
        if let Some(key_algorithm) = self.config.key_algorithm.get(&parsed) {
            if !key_algorithm.enabled {
                return Err(HolderInstanceError::InvalidKeyAlgorithm(
                    key_type.to_owned(),
                ));
            }
        } else {
            return Err(HolderInstanceError::InvalidKeyAlgorithm(
                key_type.to_owned(),
            ));
        }
        Ok(parsed)
    }

    async fn generate_key_and_proof(
        &self,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        organisation: Organisation,
        provider_info: &ProviderInfo,
        nonce: Option<String>,
    ) -> Result<(Key, String), HolderInstanceError> {
        let key_storage = self.key_provider.get_key_storage(key_storage_id)?;
        let key = self
            .new_key(key_storage_id, key_type, organisation, &key_storage)
            .await?;
        let auth_fn = self.key_provider.get_signature_provider(
            &key,
            None,
            self.key_algorithm_provider.clone(),
        )?;
        let proof = self
            .create_signed_key_possession_proof(
                crate::clock::now_utc(),
                &provider_info.name,
                auth_fn,
                &provider_info.url,
                nonce,
            )
            .await?;
        Ok((key, proof))
    }

    async fn register(
        &self,
        url: &str,
        register_request: RegisterWalletUnitRequestDTO,
    ) -> Result<RegisterWalletUnitResponseDTO, HolderInstanceError> {
        Ok(self
            .wallet_provider_client
            .register(url, register_request)
            .await
            .error_while("registering wallet unit")?)
    }

    async fn store_key(&self, key: &Key) -> Result<(), HolderInstanceError> {
        self.key_repository
            .create_key(key.clone())
            .await
            .map_err(|err| match err {
                DataLayerError::AlreadyExists => HolderInstanceError::KeyAlreadyExists,
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
    ) -> Result<String, HolderInstanceError> {
        let proof = Jwt::new(
            "jwt".to_string(),
            auth_fn
                .jose_alg()
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
        nonce: Option<String>,
    ) -> Result<String, HolderInstanceError> {
        let proof = Jwt::new(
            "jwt".to_string(),
            auth_fn
                .jose_alg()
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
                custom: NoncePayload { nonce },
            },
        );

        let signed_proof = proof
            .tokenize(Some(&*auth_fn))
            .await
            .error_while("creating device signing proof token")?;
        Ok(signed_proof)
    }

    async fn prepare_csr_for_access_cert_provisioning(
        &self,
        key_type: KeyAlgorithmType,
        organisation: &Organisation,
    ) -> Result<(String, Key), HolderInstanceError> {
        let (key_storage_id, key_storage) = self
            .config
            .key_storage
            .iter()
            .filter(|(_, v)| v.enabled)
            .filter(|(_, v)| {
                v.r#type == KeyStorageType::Internal || v.r#type == KeyStorageType::SecureElement
            })
            .filter_map(|(k, _)| {
                let key_storage = self.key_provider.get_key_storage(k).ok()?;
                key_storage
                    .get_capabilities()
                    .algorithms
                    .contains(&key_type)
                    .then_some((k.to_string(), key_storage))
            })
            .next()
            .ok_or_else(|| {
                HolderInstanceError::NoMatchingKeyStorage(format!(
                    "No enabled key storage for key algorithm: {key_type}"
                ))
            })?;

        let key_id = Uuid::new_v4().into();
        let key = key_storage
            .generate(key_id, key_type, Default::default())
            .await
            .error_while("generating key")?;

        let key = key_from_generated_key(
            key_id,
            &key_storage_id,
            key_type.as_ref(),
            organisation.to_owned(),
            key,
        );

        let csr = self
            .csr_creator
            .create_csr(
                key.clone(),
                GenerateCsrRequest {
                    profile: CsrRequestProfile::Generic,
                    subject: CsrRequestSubject {
                        ..Default::default()
                    },
                    subject_alternative_name: None,
                },
            )
            .await
            .error_while("generating CSR")?;

        Ok((csr, key))
    }
}

struct ProviderInfo {
    name: String,
    url: String,
}

enum RegistrationStatus {
    PendingNoIntegrityCheck {
        wallet_instance_id: ManagedInstanceId,
        user_nonce: String,
        key: Key,
    },
    PendingIntegrityCheck {
        wallet_instance_id: ManagedInstanceId,
        user_nonce: String,
        nonce: String,
    },
    Active {
        wallet_instance_id: ManagedInstanceId,
        key: Key,
        access_certificate: Option<String>,
    },
    Unattested {
        wallet_instance_id: ManagedInstanceId,
    },
}

impl RegistrationStatus {
    fn map_to_instance(
        self,
        request: &HolderRegisterInstanceRequestDTO,
        organisation: &Organisation,
        provider_url: String,
        metadata: &ProviderMetadata,
    ) -> Instance {
        let (status, provider_instance_id, user_nonce, nonce, authentication_key) = match self {
            RegistrationStatus::PendingNoIntegrityCheck {
                wallet_instance_id,
                user_nonce,
                key,
            } => (
                InstanceStatus::Pending,
                wallet_instance_id,
                Some(user_nonce),
                None,
                Some(key),
            ),

            RegistrationStatus::PendingIntegrityCheck {
                wallet_instance_id,
                user_nonce,
                nonce,
            } => (
                InstanceStatus::Pending,
                wallet_instance_id,
                Some(user_nonce),
                Some(nonce),
                None,
            ),
            RegistrationStatus::Active {
                wallet_instance_id,
                key,
                ..
            } => (
                InstanceStatus::Active,
                wallet_instance_id,
                None,
                None,
                Some(key),
            ),
            RegistrationStatus::Unattested { wallet_instance_id } => (
                InstanceStatus::Unattested,
                wallet_instance_id,
                None,
                None,
                None,
            ),
        };

        let now = crate::clock::now_utc();
        Instance {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            status,
            role: request.role,
            provider_url,
            provider_type: request.provider.r#type,
            provider_name: metadata.name.clone(),
            organisation: organisation.clone().into(),
            authentication_key: authentication_key.map(Into::into),
            provider_instance_id,
            nonce,
            user_nonce,
            wallet_unit_attestations: Default::default(),
        }
    }
}

struct AttestationProofs {
    attestation: Vec<String>,
    attestation_key_proof: String,
    device_sig_pop: Option<String>,
    key: Key,
}
