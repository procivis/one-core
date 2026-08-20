use std::collections::HashMap;
use std::sync::Arc;

use shared_types::RevocationMethodId;

use super::RevocationMethod;
use super::bitstring_status_list::BitstringStatusList;
use super::bitstring_status_list::resolver::StatusListCachingLoader;
use super::crl::CRLRevocation;
use super::decorators::CapabilityChecked;
use super::mdoc_mso_update_suspension::MdocMsoUpdateSuspensionRevocation;
use super::status_list_2021::StatusList2021;
use super::token_status_list::TokenStatusList;
use crate::config::ConfigValidationError;
use crate::config::core_config::{
    CacheEntitiesConfig, CacheEntityCacheType, CoreConfig, Fields, RevocationType,
};
use crate::error::{ContextWithErrorCode, NestedError};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::http_client::HttpClient;
use crate::proto::transaction_manager::TransactionManager;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::provider_directory::{InitializationError, ProviderDirectory};
use crate::provider::remote_entity_storage::db_storage::DbStorage;
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::provider::remote_entity_storage::{RemoteEntityStorage, RemoteEntityType};
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::managed_instance_repository::ManagedInstanceRepository;
use crate::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait RevocationMethodProvider: Send + Sync {
    fn get_revocation_method(
        &self,
        revocation_method_id: &RevocationMethodId,
    ) -> Result<Arc<dyn RevocationMethod>, NestedError>;

    fn get_revocation_method_by_status_type(
        &self,
        credential_status_type: &str,
    ) -> Option<(Arc<dyn RevocationMethod>, RevocationMethodId)>;
}

impl RevocationMethodProvider
    for ProviderDirectory<RevocationMethodId, Fields<RevocationType>, dyn RevocationMethod>
{
    fn get_revocation_method(
        &self,
        revocation_method_id: &RevocationMethodId,
    ) -> Result<Arc<dyn RevocationMethod>, NestedError> {
        self.provider(revocation_method_id)
    }

    fn get_revocation_method_by_status_type(
        &self,
        credential_status_type: &str,
    ) -> Option<(Arc<dyn RevocationMethod>, RevocationMethodId)> {
        let result = self
            .iter()
            .find(|(_id, method)| method.get_status_type() == credential_status_type)?;

        Some((result.1.to_owned(), result.0.to_owned()))
    }
}

#[expect(clippy::too_many_arguments)]
fn initialize_provider(
    name: &RevocationMethodId,
    fields: &Fields<RevocationType>,
    config: &CoreConfig,
    core_base_url: &Option<String>,
    credential_formatter_provider: &Arc<dyn CredentialFormatterProvider>,
    key_provider: &Arc<dyn KeyProvider>,
    certificate_validator: &Arc<dyn CertificateValidator>,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: &Arc<dyn DidMethodProvider>,
    transaction_manager: &Arc<dyn TransactionManager>,
    revocation_list_repository: &Arc<dyn RevocationListRepository>,
    remote_entity_cache_repository: &Arc<dyn RemoteEntityCacheRepository>,
    wallet_unit_repository: &Arc<dyn ManagedInstanceRepository>,
    identifier_repository: &Arc<dyn IdentifierRepository>,
    client: &Arc<dyn HttpClient>,
) -> Result<Arc<dyn RevocationMethod>, InitializationError> {
    let revocation_method: Arc<dyn RevocationMethod> = match fields.r#type {
        RevocationType::MdocMsoUpdateSuspension => Arc::new(MdocMsoUpdateSuspensionRevocation {
            config_id: name.to_owned(),
        }),
        RevocationType::BitstringStatusList => Arc::new(BitstringStatusList::new(
            name.to_owned(),
            core_base_url.clone(),
            key_algorithm_provider.clone(),
            did_method_provider.clone(),
            key_provider.clone(),
            initialize_statuslist_loader(
                &config.cache_entities,
                remote_entity_cache_repository.clone(),
            ),
            credential_formatter_provider.clone(),
            certificate_validator.clone(),
            revocation_list_repository.clone(),
            transaction_manager.clone(),
            client.clone(),
            fields.merge_fields(),
        )?),
        RevocationType::TokenStatusList => Arc::new(TokenStatusList::new(
            name.to_owned(),
            core_base_url.clone(),
            key_algorithm_provider.clone(),
            did_method_provider.clone(),
            key_provider.clone(),
            initialize_statuslist_loader(
                &config.cache_entities,
                remote_entity_cache_repository.clone(),
            ),
            credential_formatter_provider.clone(),
            certificate_validator.clone(),
            client.clone(),
            revocation_list_repository.clone(),
            wallet_unit_repository.clone(),
            identifier_repository.clone(),
            transaction_manager.clone(),
            client.clone(),
            fields.merge_fields(),
        )?),
        RevocationType::CRL => Arc::new(CRLRevocation::new(
            name.to_owned(),
            core_base_url.clone(),
            revocation_list_repository.clone(),
            transaction_manager.clone(),
            key_provider.clone(),
            fields.merge_fields(),
        )?),
    };
    Ok(Arc::new(CapabilityChecked(revocation_method)))
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn revocation_method_provider_from_config(
    config: &mut CoreConfig,
    core_base_url: Option<String>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    transaction_manager: Arc<dyn TransactionManager>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>,
    wallet_unit_repository: Arc<dyn ManagedInstanceRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    client: Arc<dyn HttpClient>,
) -> Result<Arc<dyn RevocationMethodProvider>, ConfigValidationError> {
    let config_copy = config.clone();
    let mut directory = ProviderDirectory::initialize(
        config.revocation.iter_mut(),
        |name: &RevocationMethodId, fields: &Fields<RevocationType>| {
            initialize_provider(
                name,
                fields,
                &config_copy,
                &core_base_url,
                &credential_formatter_provider,
                &key_provider,
                &certificate_validator,
                &key_algorithm_provider,
                &did_method_provider,
                &transaction_manager,
                &revocation_list_repository,
                &remote_entity_cache_repository,
                &wallet_unit_repository,
                &identifier_repository,
                &client,
            )
        },
    )
    .error_while("initializing revocation providers")?;

    // we keep `STATUSLIST2021` only for validation
    let status_list_2021_id: RevocationMethodId = "STATUSLIST2021".into();
    directory.insert_non_config(
        status_list_2021_id.clone(),
        Arc::new(StatusList2021 {
            key_algorithm_provider: key_algorithm_provider.clone(),
            did_method_provider: did_method_provider.clone(),
            certificate_validator: certificate_validator.clone(),
            client,
            config_name: status_list_2021_id,
        }) as _,
    );

    Ok(Arc::new(directory))
}

fn initialize_statuslist_loader(
    cache_entities_config: &CacheEntitiesConfig,
    remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>,
) -> StatusListCachingLoader {
    let config = cache_entities_config
        .entities
        .get("STATUS_LIST_CREDENTIAL")
        .cloned()
        .unwrap_or_default();

    let storage: Arc<dyn RemoteEntityStorage> = match config.cache_type {
        CacheEntityCacheType::Db => Arc::new(DbStorage::new(remote_entity_cache_repository)),
        CacheEntityCacheType::InMemory => Arc::new(InMemoryStorage::new(HashMap::new())),
    };

    StatusListCachingLoader::new(
        RemoteEntityType::StatusListCredential,
        storage,
        config.cache_size as usize,
        config.cache_refresh_timeout_seconds,
        config.refresh_after_seconds,
    )
}
