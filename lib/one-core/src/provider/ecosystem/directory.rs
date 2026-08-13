use std::sync::Arc;

use shared_types::EcosystemId;

use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, EcosystemProviderType, Fields};
use crate::error::{ContextWithErrorCode, NestedError};
use crate::proto::session_provider::SessionProvider;
use crate::proto::wrp_validator::WRPValidator;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::ecosystem::Ecosystem;
use crate::provider::ecosystem::eudi::EudiEcosystem;
use crate::provider::provider_directory::ProviderDirectory;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_schema_repository::ProofSchemaRepository;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub(crate) trait EcosystemDirectory: Send + Sync {
    fn get(&self, name: &EcosystemId) -> Result<Arc<dyn Ecosystem>, NestedError>;
}

impl EcosystemDirectory
    for ProviderDirectory<EcosystemId, Fields<EcosystemProviderType>, dyn Ecosystem>
{
    fn get(&self, name: &EcosystemId) -> Result<Arc<dyn Ecosystem>, NestedError> {
        self.provider(name)
    }
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn ecosystem_directory_from_config(
    config: &mut CoreConfig,
    history_repository: Arc<dyn HistoryRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    wrp_validator: Arc<dyn WRPValidator>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    session_provider: Arc<dyn SessionProvider>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
) -> Result<Arc<dyn EcosystemDirectory>, ConfigValidationError> {
    let config_clone = config.clone();
    let directory = ProviderDirectory::initialize(
        config.ecosystem.iter_mut(),
        move |name: &EcosystemId, fields: &Fields<EcosystemProviderType>| {
            let ecosystem: Arc<dyn Ecosystem> = match fields.r#type {
                EcosystemProviderType::Eudi => Arc::new(EudiEcosystem::new(
                    name.clone(),
                    fields.merge_fields(),
                    config_clone.clone(),
                    history_repository.clone(),
                    interaction_repository.clone(),
                    wrp_validator.clone(),
                    blob_storage_provider.clone(),
                    session_provider.clone(),
                    formatter_provider.clone(),
                    credential_schema_repository.clone(),
                    proof_schema_repository.clone(),
                )?),
            };

            Ok(ecosystem)
        },
    )
    .error_while("initializing ecosystem providers")?;

    Ok(Arc::new(directory))
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use similar_asserts::assert_eq;

    use super::*;
    use crate::config::core_config::{ConfigEntryDisplay, Params};
    use crate::error::{ErrorCode, ErrorCodeMixin};
    use crate::proto::session_provider::NoSessionProvider;
    use crate::proto::wrp_validator::MockWRPValidator;
    use crate::provider::blob_storage::provider::MockBlobStorageProvider;
    use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
    use crate::provider::ecosystem::model::EcosystemRole;
    use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
    use crate::repository::history_repository::MockHistoryRepository;
    use crate::repository::interaction_repository::MockInteractionRepository;
    use crate::repository::proof_schema_repository::MockProofSchemaRepository;

    fn fields() -> Fields<EcosystemProviderType> {
        Fields {
            r#type: EcosystemProviderType::Eudi,
            display: ConfigEntryDisplay::from("ecosystem.eudi"),
            order: Some(1),
            priority: None,
            enabled: false,
            capabilities: None,
            params: Some(Params {
                public: Some(json!({ "logo": "logo", "description": { "en": "EUDI ecosystem" } })),
                private: None,
            }),
        }
    }

    fn config() -> CoreConfig {
        let mut config = CoreConfig::default();
        config.ecosystem.insert("EUDI".into(), fields());
        config
    }

    #[test]
    fn disabled_ecosystem_rejects_interactions() {
        let mut config = config();

        let directory = ecosystem_directory_from_config(
            &mut config,
            Arc::new(MockHistoryRepository::new()),
            Arc::new(MockInteractionRepository::new()),
            Arc::new(MockWRPValidator::new()),
            Arc::new(MockBlobStorageProvider::new()),
            Arc::new(NoSessionProvider),
            Arc::new(MockCredentialFormatterProvider::new()),
            Arc::new(MockCredentialSchemaRepository::new()),
            Arc::new(MockProofSchemaRepository::new()),
        )
        .unwrap();

        let ecosystem = directory.get(&"EUDI".into()).unwrap();
        assert_eq!(
            ecosystem.lifecycle_hook().unwrap_err().error_code(),
            ErrorCode::BR_0431
        );
        assert_eq!(
            ecosystem.get_capabilities().ecosystem_roles.first(),
            Some(&EcosystemRole::Holder)
        );
    }
}
