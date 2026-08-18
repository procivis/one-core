use std::sync::Arc;

use dto::VerifierProviderMetadataResponseDTO;
use error::VerifierProviderError;
use one_dto_mapper::convert_inner;

use crate::config::core_config::CoreConfig;
use crate::error::ContextWithErrorCode;
use crate::provider::verifier::provider::VerifierProvider;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::proof_schema_repository::ProofSchemaRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::service::managed_instance::dto::{
    EcosystemMetadataDTO, WalletUnitAttestationMetadataDTO,
};
use crate::service::managed_instance::ecosystem_metadata::{
    EcosystemEntityRepositories, ecosystem_metadata, provider_trust_collections,
};
use crate::service::verifier_provider::dto::FeatureFlags;

pub mod dto;
pub mod error;

pub struct VerifierProviderService {
    verifier_provider: Arc<dyn VerifierProvider>,
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    config: Arc<CoreConfig>,
}

impl VerifierProviderService {
    pub(crate) fn new(
        verifier_provider: Arc<dyn VerifierProvider>,
        trust_collection_repository: Arc<dyn TrustCollectionRepository>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        proof_schema_repository: Arc<dyn ProofSchemaRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        config: Arc<CoreConfig>,
    ) -> Self {
        Self {
            verifier_provider,
            trust_collection_repository,
            credential_schema_repository,
            proof_schema_repository,
            organisation_repository,
            config,
        }
    }

    pub async fn get_verifier_by_id(
        &self,
        id: &str,
    ) -> Result<VerifierProviderMetadataResponseDTO, VerifierProviderError> {
        let verifier = self
            .verifier_provider
            .get_by_id(id)
            .error_while("getting verifier provider")?;

        let verifier_app_attestation = {
            let (enabled, app_integrity_check_required) =
                match verifier.verifier_instance_attestation {
                    Some(attestation) => (true, attestation.integrity_check.enabled),
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
            .get_organisation_for_verifier_provider(id)
            .await
            .error_while("getting verifier provider organisation")?;

        if organisation.is_none() {
            tracing::warn!("Verifier provider `{id}` is not associated with any organisation");
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
            name: id.to_string(),
            app_version: verifier.app_version,
            trust_collections: provider_trust_collections(&ecosystems),
            verifier_app_attestation,
            user_authentication: convert_inner(verifier.user_authentication),
            feature_flags: FeatureFlags {
                ecosystems_enabled: verifier.feature_flags.ecosystems_enabled,
                access_certificate_provisioning_enabled: verifier
                    .access_certificate_configuration
                    .is_some(),
                ecosystems_enforcement_enabled: verifier
                    .feature_flags
                    .ecosystems_enforcement_enabled,
            },
            credential_schemas,
            proof_schemas,
            ecosystems,
        })
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
