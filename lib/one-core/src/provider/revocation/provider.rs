use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;
use shared_types::RevocationMethodId;
use time::Duration;

use super::bitstring_status_list::BitstringStatusList;
use super::bitstring_status_list::resolver::StatusListCachingLoader;
use super::lvvc::LvvcProvider;
use super::mdoc_mso_update_suspension::MdocMsoUpdateSuspensionRevocation;
use super::none::NoneRevocation;
use super::status_list_2021::StatusList2021;
use super::token_status_list::TokenStatusList;
use crate::config::ConfigValidationError;
use crate::config::core_config::{
    CacheEntitiesConfig, CacheEntityCacheType, CacheEntityConfig, CoreConfig, RevocationType,
};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::http_client::HttpClient;
use crate::proto::transaction_manager::TransactionManager;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::remote_entity_storage::db_storage::DbStorage;
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::provider::remote_entity_storage::{RemoteEntityStorage, RemoteEntityType};
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::crl::CRLRevocation;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::repository::wallet_unit_repository::WalletUnitRepository;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait RevocationMethodProvider: Send + Sync {
    fn get_revocation_method(
        &self,
        revocation_method_id: &RevocationMethodId,
    ) -> Option<Arc<dyn RevocationMethod>>;

    fn get_revocation_method_by_status_type(
        &self,
        credential_status_type: &str,
    ) -> Option<(Arc<dyn RevocationMethod>, RevocationMethodId)>;
}

struct RevocationMethodProviderImpl {
    revocation_methods: HashMap<RevocationMethodId, Arc<dyn RevocationMethod>>,
}

impl RevocationMethodProvider for RevocationMethodProviderImpl {
    fn get_revocation_method(
        &self,
        revocation_method_id: &RevocationMethodId,
    ) -> Option<Arc<dyn RevocationMethod>> {
        self.revocation_methods.get(revocation_method_id).cloned()
    }

    fn get_revocation_method_by_status_type(
        &self,
        credential_status_type: &str,
    ) -> Option<(Arc<dyn RevocationMethod>, RevocationMethodId)> {
        let result = self
            .revocation_methods
            .iter()
            .find(|(_id, method)| method.get_status_type() == credential_status_type)?;

        Some((result.1.to_owned(), result.0.to_owned()))
    }
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
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
    transaction_manager: Arc<dyn TransactionManager>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>,
    wallet_unit_repository: Arc<dyn WalletUnitRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    client: Arc<dyn HttpClient>,
) -> Result<Arc<dyn RevocationMethodProvider>, ConfigValidationError> {
    let mut revocation_methods: HashMap<RevocationMethodId, Arc<dyn RevocationMethod>> =
        HashMap::new();

    for (key, fields) in config.revocation.iter() {
        if !fields.enabled {
            continue;
        }

        let revocation_method: Arc<dyn RevocationMethod> = match fields.r#type {
            RevocationType::None => Arc::new(NoneRevocation {}),
            RevocationType::MdocMsoUpdateSuspension => {
                Arc::new(MdocMsoUpdateSuspensionRevocation {})
            }
            RevocationType::BitstringStatusList => {
                let params = config.revocation.get(key)?;

                Arc::new(BitstringStatusList::new(
                    key.to_owned(),
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
                    Some(params),
                ))
            }
            RevocationType::Lvvc => {
                let params = config.revocation.get(key)?;
                Arc::new(LvvcProvider::new(
                    core_base_url.clone(),
                    credential_formatter_provider.clone(),
                    validity_credential_repository.clone(),
                    key_provider.clone(),
                    key_algorithm_provider.clone(),
                    client.clone(),
                    params,
                ))
            }
            RevocationType::TokenStatusList => {
                let params = config.revocation.get(key)?;
                Arc::new(
                    TokenStatusList::new(
                        key.to_owned(),
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
                        wallet_unit_repository.clone(),
                        identifier_repository.clone(),
                        transaction_manager.clone(),
                        client.clone(),
                        Some(params),
                    )
                    .map_err(|e| ConfigValidationError::EntryNotFound(e.to_string()))?,
                )
            }
            RevocationType::CRL => {
                let params = config.revocation.get(key)?;
                Arc::new(CRLRevocation::new(
                    key.to_owned(),
                    core_base_url.clone(),
                    revocation_list_repository.clone(),
                    transaction_manager.clone(),
                    key_provider.clone(),
                    params,
                ))
            }
        };

        revocation_methods.insert(key.to_owned(), revocation_method);
    }

    for (key, value) in config.revocation.iter_mut() {
        if let Some(entity) = revocation_methods.get(key) {
            value.capabilities = Some(json!(entity.get_capabilities()));
        }
    }

    // we keep `STATUSLIST2021` only for validation
    revocation_methods.insert(
        "STATUSLIST2021".into(),
        Arc::new(StatusList2021 {
            key_algorithm_provider: key_algorithm_provider.clone(),
            did_method_provider: did_method_provider.clone(),
            certificate_validator: certificate_validator.clone(),
            client,
        }) as _,
    );

    Ok(Arc::new(RevocationMethodProviderImpl {
        revocation_methods,
    }))
}

fn initialize_statuslist_loader(
    cache_entities_config: &CacheEntitiesConfig,
    remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>,
) -> StatusListCachingLoader {
    let config = cache_entities_config
        .entities
        .get("STATUS_LIST_CREDENTIAL")
        .cloned()
        .unwrap_or(CacheEntityConfig {
            cache_refresh_timeout: Duration::days(1),
            cache_size: 100,
            cache_type: CacheEntityCacheType::Db,
            refresh_after: Duration::minutes(5),
        });

    let storage: Arc<dyn RemoteEntityStorage> = match config.cache_type {
        CacheEntityCacheType::Db => Arc::new(DbStorage::new(remote_entity_cache_repository)),
        CacheEntityCacheType::InMemory => Arc::new(InMemoryStorage::new(HashMap::new())),
    };

    StatusListCachingLoader::new(
        RemoteEntityType::StatusListCredential,
        storage,
        config.cache_size as usize,
        config.cache_refresh_timeout,
        config.refresh_after,
    )
}
