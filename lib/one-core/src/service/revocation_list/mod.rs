use std::sync::Arc;

use crate::config::core_config;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::revocation_list_repository::RevocationListRepository;

pub mod dto;
pub mod service;

mod mapper;
mod validator;

#[derive(Clone)]
pub struct RevocationListService {
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    config: Arc<core_config::CoreConfig>,
}

impl RevocationListService {
    pub(crate) fn new(
        revocation_list_repository: Arc<dyn RevocationListRepository>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        config: Arc<core_config::CoreConfig>,
    ) -> Self {
        Self {
            revocation_list_repository,
            revocation_method_provider,
            config,
        }
    }
}

#[cfg(test)]
mod test;
