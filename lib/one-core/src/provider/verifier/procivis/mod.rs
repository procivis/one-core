use std::sync::Arc;

use model::Params;
use one_dto_mapper::convert_inner;
use proc_macros::Provider;

use super::VerifierProvider;
use super::dto::{AccessCertificateProvisioningResponse, VerifierProviderCapabilities};
use super::error::VerifierProviderError;
use super::procivis::model::AccessCertificateProvisioningRequest;
use crate::config::core_config::CoreConfig;
use crate::error::ContextWithErrorCode;
use crate::model::managed_instance::{ManagedInstance, UpdateManagedInstanceRequest};
use crate::proto::http_client::HttpClient;
use crate::provider::provider_directory::InitializationError;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::managed_instance_repository::ManagedInstanceRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::proof_schema_repository::ProofSchemaRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::service::managed_instance::dto::{
    EcosystemMetadataDTO, IntegrityCheck, ProviderRegistrationParams,
    WalletUnitAttestationMetadataDTO,
};
use crate::service::managed_instance::ecosystem_metadata::{
    EcosystemEntityRepositories, ecosystem_metadata, provider_trust_collections,
};
use crate::service::verifier_provider::dto::{FeatureFlags, VerifierProviderMetadataResponseDTO};

mod model;

#[derive(Provider)]
pub struct ProcivisVerifierProvider {
    config_name: String,
    config: Arc<CoreConfig>,
    params: Params,
    organisation_repository: Arc<dyn OrganisationRepository>,
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    managed_instance_repository: Arc<dyn ManagedInstanceRepository>,
    http_client: Arc<dyn HttpClient>,
}

impl ProcivisVerifierProvider {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        config_name: String,
        config: Arc<CoreConfig>,
        params: serde_json::Value,
        organisation_repository: Arc<dyn OrganisationRepository>,
        trust_collection_repository: Arc<dyn TrustCollectionRepository>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        proof_schema_repository: Arc<dyn ProofSchemaRepository>,
        managed_instance_repository: Arc<dyn ManagedInstanceRepository>,
        http_client: Arc<dyn HttpClient>,
    ) -> Result<Self, InitializationError> {
        let params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: config_name.to_string(),
                source: err,
            })?;

        Ok(Self {
            config_name,
            config,
            params,
            organisation_repository,
            trust_collection_repository,
            credential_schema_repository,
            proof_schema_repository,
            managed_instance_repository,
            http_client,
        })
    }
}

#[async_trait::async_trait]
impl VerifierProvider for ProcivisVerifierProvider {
    fn get_capabilities(&self) -> VerifierProviderCapabilities {
        VerifierProviderCapabilities {
            signer_identifier_types: self.params.signer_identifier_types.to_owned(),
        }
    }

    fn get_registration_params(&self) -> Result<ProviderRegistrationParams, VerifierProviderError> {
        let integrity_check = self
            .params
            .integrity_check
            .clone()
            .unwrap_or(IntegrityCheck {
                enabled: false,
                ..Default::default()
            });

        Ok(ProviderRegistrationParams {
            name_label: self.config_name.to_owned(),
            integrity_check,
            device_auth_leeway: self.params.device_auth_leeway_seconds,
            user_authentication: self.params.user_authentication.to_owned(),
        })
    }

    async fn get_metadata(
        &self,
    ) -> Result<VerifierProviderMetadataResponseDTO, VerifierProviderError> {
        let verifier_app_attestation = {
            let (enabled, app_integrity_check_required) = match &self.params.integrity_check {
                Some(integrity_check) => (true, integrity_check.enabled),
                None => (false, false),
            };
            WalletUnitAttestationMetadataDTO {
                app_integrity_check_required,
                enabled,
                required: false,
            }
        };

        // The advertised ecosystems, and the entities belonging to them, are the
        // ones of the organisation owning this provider.
        let organisation = self
            .organisation_repository
            .get_organisation_for_verifier_provider(&self.config_name)
            .await
            .error_while("getting verifier provider organisation")?;
        if organisation.is_none() {
            tracing::warn!(
                "Verifier provider `{}` is not associated with any organisation",
                self.config_name
            );
        }

        let ecosystems = ecosystem_metadata(
            &self.config,
            organisation.as_ref(),
            EcosystemEntityRepositories {
                trust_collections: &*self.trust_collection_repository,
                credential_schemas: &*self.credential_schema_repository,
                proof_schemas: Some(&*self.proof_schema_repository),
            },
        )
        .await?;

        let credential_schemas =
            flatten_schemas(&ecosystems, |ecosystem| &ecosystem.credential_schemas);
        let proof_schemas = flatten_schemas(&ecosystems, |ecosystem| &ecosystem.proof_schemas);

        Ok(VerifierProviderMetadataResponseDTO {
            name: self.config_name.to_string(),
            app_version: self.params.app_version.to_owned(),
            trust_collections: provider_trust_collections(&ecosystems),
            verifier_app_attestation,
            user_authentication: convert_inner(self.params.user_authentication.to_owned()),
            feature_flags: FeatureFlags {
                ecosystems_enabled: self.params.feature_flags.ecosystems_enabled,
                access_certificate_provisioning_enabled: self
                    .params
                    .access_certificate_configuration
                    .is_some(),
                ecosystems_enforcement_enabled: self
                    .params
                    .feature_flags
                    .ecosystems_enforcement_enabled,
            },
            credential_schemas,
            proof_schemas,
            ecosystems,
        })
    }

    async fn provision_access_certificate(
        &self,
        managed_instance: &ManagedInstance,
        access_token: &str,
        user_sub: Option<String>,
        verifier_csr: String,
    ) -> Result<AccessCertificateProvisioningResponse, VerifierProviderError> {
        let Some(access_certificate_configuration) = &self.params.access_certificate_configuration
        else {
            return Err(VerifierProviderError::AccessCertificateProvisioningDisabled);
        };

        // store the userSub + CSR before calling BFF provider
        self.managed_instance_repository
            .update(
                &managed_instance.id,
                UpdateManagedInstanceRequest {
                    user_sub,
                    verifier_csr: Some(Some(verifier_csr)),
                    ..Default::default()
                },
            )
            .await
            .error_while("setting CSR")?;

        let response: AccessCertificateProvisioningResponse = async {
            self.http_client
                .post(&access_certificate_configuration.provider_url)
                .bearer_auth(access_token)
                .json(&AccessCertificateProvisioningRequest {
                    provider: self.config_name.clone(),
                    managed_instance_id: managed_instance.id,
                    verifier_provider_organisation_id: managed_instance.organisation.id(),
                })?
                .send()
                .await?
                .error_for_status()?
                .json()
        }
        .await
        .error_while("requesting access certificate")?;

        Ok(response)
    }

    fn config_name(&self) -> &str {
        &self.config_name
    }
}

/// The deprecated flat schema lists, kept for verifier apps that do not
/// understand `ecosystems` yet.
fn flatten_schemas(
    ecosystems: &[EcosystemMetadataDTO],
    schemas: impl Fn(&EcosystemMetadataDTO) -> &Vec<String>,
) -> Option<Vec<String>> {
    let result: Vec<String> = ecosystems
        .iter()
        .flat_map(|ecosystem| schemas(ecosystem).to_owned())
        .collect();

    (!result.is_empty()).then_some(result)
}
