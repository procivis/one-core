use std::sync::Arc;

use model::{Params, WalletRegistrationRequirement};
use one_dto_mapper::convert_inner;
use proc_macros::Provider;
use shared_types::IdentifierId;
use validator::validate_params;

use super::WalletProvider;
use super::dto::{
    CreatedAttestation, WalletProviderCapabilities, WalletProviderRegistrationParams,
};
use super::error::WalletProviderError;
use crate::config::core_config::CoreConfig;
use crate::error::ContextWithErrorCode;
use crate::model::managed_instance::ManagedInstance;
use crate::provider::document_signer::provider::DocumentSignerProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::provider_directory::InitializationError;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::managed_instance_attestation_repository::ManagedInstanceAttestationRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::service::managed_instance::dto::{
    DocumentSignerMetadataDTO, FeatureFlags, IssueWiaRequestDTO, IssueWuaRequestDTO,
    WalletProviderMetadataResponseDTO, WalletUnitAttestationMetadataDTO,
};
use crate::service::managed_instance::ecosystem_metadata::{
    EcosystemEntityRepositories, ecosystem_metadata, provider_trust_collections,
};
use crate::service::managed_instance::mapper::params_into_display_names;

mod attestation;
mod mapper;
mod model;
mod validator;

#[derive(Provider)]
pub struct ProcivisWalletProvider {
    config_name: String,
    config: Arc<CoreConfig>,
    params: Params,
    core_base_url: Option<String>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    document_signer_provider: Arc<dyn DocumentSignerProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    managed_instance_attestation_repository: Arc<dyn ManagedInstanceAttestationRepository>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    key_provider: Arc<dyn KeyProvider>,
}

impl ProcivisWalletProvider {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        config_name: String,
        config: Arc<CoreConfig>,
        params: serde_json::Value,
        core_base_url: Option<String>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        trust_collection_repository: Arc<dyn TrustCollectionRepository>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        document_signer_provider: Arc<dyn DocumentSignerProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        managed_instance_attestation_repository: Arc<dyn ManagedInstanceAttestationRepository>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        key_provider: Arc<dyn KeyProvider>,
    ) -> Result<Self, InitializationError> {
        let params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: config_name.to_string(),
                source: err,
            })?;

        validate_params(config.as_ref(), &params)
            .error_while(format!("validating params for: {config_name}"))?;

        Ok(Self {
            config_name,
            config,
            params,
            core_base_url,
            organisation_repository,
            trust_collection_repository,
            credential_schema_repository,
            document_signer_provider,
            revocation_method_provider,
            managed_instance_attestation_repository,
            key_algorithm_provider,
            identifier_repository,
            key_provider,
        })
    }
}

#[async_trait::async_trait]
impl WalletProvider for ProcivisWalletProvider {
    fn get_capabilities(&self) -> WalletProviderCapabilities {
        WalletProviderCapabilities {
            signer_identifier_types: self.params.signer_identifier_types.to_owned(),
        }
    }

    async fn issue_instance_attestation(
        &self,
        request: IssueWiaRequestDTO,
        issuer: IdentifierId,
        managed_instance: &ManagedInstance,
    ) -> Result<CreatedAttestation, WalletProviderError> {
        self.create_wia(request, issuer, managed_instance).await
    }

    async fn issue_key_attestation(
        &self,
        request: IssueWuaRequestDTO,
        issuer: IdentifierId,
        managed_instance: &ManagedInstance,
    ) -> Result<CreatedAttestation, WalletProviderError> {
        self.create_key_attestation(request, issuer, managed_instance)
            .await
    }

    fn get_registration_params(
        &self,
    ) -> Result<WalletProviderRegistrationParams, WalletProviderError> {
        Ok(WalletProviderRegistrationParams {
            name_label: self.config_name.to_owned(),
            integrity_check: self.params.integrity_check.to_owned(),
            device_auth_leeway: self.params.device_auth_leeway_seconds,
            user_authentication: self.params.user_authentication.to_owned(),
        })
    }

    async fn get_metadata(&self) -> Result<WalletProviderMetadataResponseDTO, WalletProviderError> {
        let (enabled, required) = match self.params.wallet_registration {
            WalletRegistrationRequirement::Mandatory => (true, true),
            WalletRegistrationRequirement::Optional => (true, false),
            WalletRegistrationRequirement::Disabled => (false, false),
        };

        // The advertised ecosystems, and the entities belonging to them, are the
        // ones of the organisation owning this provider.
        let organisation = self
            .organisation_repository
            .get_organisation_for_wallet_provider(&self.config_name)
            .await
            .error_while("getting wallet provider organisation")?;

        if organisation.is_none() {
            tracing::warn!(
                "Wallet provider `{}` is not associated with any organisation",
                self.config_name
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

        let document_signers = self
            .params
            .document_signers
            .iter()
            .map(|name| {
                let metadata = self
                    .document_signer_provider
                    .metadata(name)
                    .error_while("getting document signer metadata")?;

                Ok(DocumentSignerMetadataDTO {
                    name: name.to_string(),
                    r#type: metadata.r#type,
                    display_name: params_into_display_names(metadata.display_name),
                    description: params_into_display_names(metadata.description),
                    logo: metadata.logo,
                })
            })
            .collect::<Result<Vec<_>, WalletProviderError>>()?;

        Ok(WalletProviderMetadataResponseDTO {
            wallet_unit_attestation: WalletUnitAttestationMetadataDTO {
                app_integrity_check_required: self.params.integrity_check.enabled,
                enabled,
                required,
            },
            name: self.config_name.to_owned(),
            app_version: self.params.app_version.to_owned(),
            trust_collections: provider_trust_collections(&ecosystems),
            feature_flags: FeatureFlags {
                ecosystems_enabled: self.params.feature_flags.ecosystems_enabled,
                refresh_credential_batch_enabled: self
                    .params
                    .feature_flags
                    .refresh_credential_batch_enabled,
                document_signing_enabled: self.params.feature_flags.document_signing_enabled,
                ecosystems_enforcement_enabled: self
                    .params
                    .feature_flags
                    .ecosystems_enforcement_enabled,
            },
            user_authentication: convert_inner(self.params.user_authentication.to_owned()),
            document_signers,
            ecosystems,
        })
    }

    fn config_name(&self) -> &str {
        &self.config_name
    }
}
