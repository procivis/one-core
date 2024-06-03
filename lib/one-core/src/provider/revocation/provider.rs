use std::{collections::HashMap, sync::Arc};

use serde_json::json;

use crate::{
    config::{
        core_config::{RevocationConfig, RevocationType},
        ConfigError,
    },
    provider::{
        credential_formatter::provider::CredentialFormatterProvider,
        did_method::provider::DidMethodProvider, key_algorithm::provider::KeyAlgorithmProvider,
        key_storage::provider::KeyProvider,
    },
    repository::{
        credential_repository::CredentialRepository,
        revocation_list_repository::RevocationListRepository,
        validity_credential_repository::ValidityCredentialRepository,
    },
};

use super::{
    bitstring_status_list::BitstringStatusList, lvvc::LvvcProvider, none::NoneRevocation,
    status_list_2021::StatusList2021, RevocationMethod,
};

#[cfg_attr(test, mockall::automock)]
pub(crate) trait RevocationMethodProvider: Send + Sync {
    fn get_revocation_method(
        &self,
        revocation_method_id: &str,
    ) -> Option<Arc<dyn RevocationMethod>>;

    fn get_revocation_method_by_status_type(
        &self,
        credential_status_type: &str,
    ) -> Option<(Arc<dyn RevocationMethod>, String)>;
}

pub(crate) struct RevocationMethodProviderImpl {
    revocation_methods: HashMap<String, Arc<dyn RevocationMethod>>,
}

impl RevocationMethodProviderImpl {
    pub fn new(revocation_methods: HashMap<String, Arc<dyn RevocationMethod>>) -> Self {
        Self { revocation_methods }
    }
}

impl RevocationMethodProvider for RevocationMethodProviderImpl {
    fn get_revocation_method(
        &self,
        revocation_method_id: &str,
    ) -> Option<Arc<dyn RevocationMethod>> {
        self.revocation_methods.get(revocation_method_id).cloned()
    }
    fn get_revocation_method_by_status_type(
        &self,
        credential_status_type: &str,
    ) -> Option<(Arc<dyn RevocationMethod>, String)> {
        let result = self
            .revocation_methods
            .iter()
            .find(|(_id, method)| method.get_status_type() == credential_status_type)?;

        Some((result.1.to_owned(), result.0.to_owned()))
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn from_config(
    config: &mut RevocationConfig,
    core_base_url: Option<String>,
    credential_repository: Arc<dyn CredentialRepository>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    lvvc_repository: Arc<dyn ValidityCredentialRepository>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    client: reqwest::Client,
) -> Result<HashMap<String, Arc<dyn RevocationMethod>>, ConfigError> {
    let mut providers: HashMap<String, Arc<dyn RevocationMethod>> = HashMap::new();

    for (key, fields) in config.iter() {
        if fields.disabled() {
            continue;
        }

        let revocation_method = match fields.r#type {
            RevocationType::None => Arc::new(NoneRevocation {}) as _,
            RevocationType::BitstringStatusList => Arc::new(BitstringStatusList {
                core_base_url: core_base_url.clone(),
                credential_repository: credential_repository.clone(),
                revocation_list_repository: revocation_list_repository.clone(),
                key_provider: key_provider.clone(),
                key_algorithm_provider: key_algorithm_provider.clone(),
                did_method_provider: did_method_provider.clone(),
                client: client.clone(),
            }) as _,
            RevocationType::Lvvc => {
                ({
                    let params = config.get(key)?;
                    Arc::new(LvvcProvider::new(
                        core_base_url.clone(),
                        credential_repository.clone(),
                        lvvc_repository.clone(),
                        credential_formatter_provider.clone(),
                        key_provider.clone(),
                        did_method_provider.clone(),
                        client.clone(),
                        params,
                    ))
                }) as _
            }
        };

        providers.insert(key.to_string(), revocation_method);
    }

    for (key, value) in config.iter_mut() {
        if let Some(entity) = providers.get(key) {
            value.capabilities = Some(json!(entity.get_capabilities()));
        }
    }

    // we keep `STATUSLIST2021` only for validation
    providers.insert(
        "STATUSLIST2021".to_string(),
        Arc::new(StatusList2021 {
            key_algorithm_provider,
            did_method_provider,
            client,
        }) as _,
    );

    Ok(providers)
}
