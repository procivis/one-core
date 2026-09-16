use std::sync::Arc;

use super::WalletProvider;
use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, Fields, WalletProviderType};
use crate::error::{ContextWithErrorCode, NestedError};
use crate::provider::document_signer::provider::DocumentSignerProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::provider_directory::ProviderDirectory;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::wallet::procivis::ProcivisWalletProvider;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::managed_instance_attestation_repository::ManagedInstanceAttestationRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub(crate) trait WalletProviderDirectory: Send + Sync {
    fn get_provider(&self, provider_id: &str) -> Result<Arc<dyn WalletProvider>, NestedError>;
}

impl WalletProviderDirectory
    for ProviderDirectory<String, Fields<WalletProviderType>, dyn WalletProvider>
{
    fn get_provider(&self, provider_id: &str) -> Result<Arc<dyn WalletProvider>, NestedError> {
        self.provider(provider_id)
    }
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn wallet_provider_directory_from_config(
    config: &mut CoreConfig,
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
) -> Result<Arc<dyn WalletProviderDirectory>, ConfigValidationError> {
    let core_config = Arc::new(config.to_owned());

    let directory = ProviderDirectory::initialize(
        config.wallet_provider.iter_mut(),
        |name: &String, fields: &Fields<WalletProviderType>| {
            let provider: Arc<dyn WalletProvider> = match fields.r#type {
                WalletProviderType::ProcivisOne => Arc::new(ProcivisWalletProvider::new(
                    name.to_string(),
                    core_config.clone(),
                    fields.merge_fields(),
                    core_base_url.clone(),
                    organisation_repository.clone(),
                    trust_collection_repository.clone(),
                    credential_schema_repository.clone(),
                    document_signer_provider.clone(),
                    revocation_method_provider.clone(),
                    managed_instance_attestation_repository.clone(),
                    key_algorithm_provider.clone(),
                    identifier_repository.clone(),
                    key_provider.clone(),
                )?),
            };

            Ok(provider)
        },
    )
    .error_while("initializing wallet providers")?;

    Ok(Arc::new(directory))
}
