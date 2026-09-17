use std::sync::Arc;

use super::VerifierProvider;
use super::procivis::ProcivisVerifierProvider;
use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, Fields, VerifierProviderType};
use crate::error::{ContextWithErrorCode, NestedError};
use crate::proto::http_client::HttpClient;
use crate::provider::provider_directory::ProviderDirectory;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::managed_instance_repository::ManagedInstanceRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::proof_schema_repository::ProofSchemaRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub(crate) trait VerifierProviderDirectory: Send + Sync {
    fn get_provider(&self, provider_id: &str) -> Result<Arc<dyn VerifierProvider>, NestedError>;
}

impl VerifierProviderDirectory
    for ProviderDirectory<String, Fields<VerifierProviderType>, dyn VerifierProvider>
{
    fn get_provider(&self, provider_id: &str) -> Result<Arc<dyn VerifierProvider>, NestedError> {
        self.provider(provider_id)
    }
}

pub(crate) fn verifier_provider_directory_from_config(
    config: &mut CoreConfig,
    organisation_repository: Arc<dyn OrganisationRepository>,
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    managed_instance_repository: Arc<dyn ManagedInstanceRepository>,
    http_client: Arc<dyn HttpClient>,
) -> Result<Arc<dyn VerifierProviderDirectory>, ConfigValidationError> {
    let core_config = Arc::new(config.to_owned());

    let directory = ProviderDirectory::initialize(
        config.verifier_provider.iter_mut(),
        |name: &String, fields: &Fields<VerifierProviderType>| {
            let provider: Arc<dyn VerifierProvider> = match fields.r#type {
                VerifierProviderType::ProcivisOne => Arc::new(ProcivisVerifierProvider::new(
                    name.to_string(),
                    core_config.clone(),
                    fields.merge_fields(),
                    organisation_repository.clone(),
                    trust_collection_repository.clone(),
                    credential_schema_repository.clone(),
                    proof_schema_repository.clone(),
                    managed_instance_repository.clone(),
                    http_client.clone(),
                )?),
            };

            Ok(provider)
        },
    )
    .error_while("initializing verifier providers")?;

    Ok(Arc::new(directory))
}
