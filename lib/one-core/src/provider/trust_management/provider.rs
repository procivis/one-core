use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;

use super::simple_list::SimpleList;
use super::{simple_list, TrustManagement};
use crate::config::core_config::{TrustManagementConfig, TrustManagementType};
use crate::config::ConfigError;
use crate::model::credential::Credential;
use crate::model::interaction::Interaction;
use crate::model::trust_entity::TrustEntityRole;

#[cfg_attr(test, mockall::automock)]
pub trait TrustManagementProvider: Send + Sync {
    fn get(&self, name: &str) -> Option<Arc<dyn TrustManagement>>;
    fn get_by_credential(&self, credential: &Credential) -> Option<Arc<dyn TrustManagement>>;
    fn get_by_interaction(
        &self,
        interaction: &Interaction,
        role: &TrustEntityRole,
    ) -> Option<Arc<dyn TrustManagement>>;
}

pub struct TrustManagementProviderImpl {
    trust_managers: HashMap<String, Arc<dyn TrustManagement>>,
}

impl TrustManagementProviderImpl {
    pub fn new(trust_managers: HashMap<String, Arc<dyn TrustManagement>>) -> Self {
        Self { trust_managers }
    }
}

impl TrustManagementProvider for TrustManagementProviderImpl {
    fn get(&self, name: &str) -> Option<Arc<dyn TrustManagement>> {
        self.trust_managers.get(name).cloned()
    }

    fn get_by_credential(&self, _credential: &Credential) -> Option<Arc<dyn TrustManagement>> {
        unimplemented!()
    }

    fn get_by_interaction(
        &self,
        _interaction: &Interaction,
        _role: &TrustEntityRole,
    ) -> Option<Arc<dyn TrustManagement>> {
        unimplemented!()
    }
}

pub(crate) fn from_config(
    config: &mut TrustManagementConfig,
) -> Result<HashMap<String, Arc<dyn TrustManagement>>, ConfigError> {
    let mut providers: HashMap<String, Arc<dyn TrustManagement>> = HashMap::new();

    for (key, fields) in config.iter() {
        if fields.disabled() {
            continue;
        }

        let management = match fields.r#type {
            TrustManagementType::SimpleTrustList => {
                let params: simple_list::Params = config.get(key)?;
                Arc::new(SimpleList { params }) as _
            }
        };

        providers.insert(key.to_string(), management);
    }

    for (key, value) in config.iter_mut() {
        if let Some(entity) = providers.get(key) {
            value.capabilities = Some(json!(entity.get_capabilities()));
        }
    }

    Ok(providers)
}
