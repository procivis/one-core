use std::sync::Arc;

use crate::{
    config::data_structure::CoreConfig,
    provider::did_method::provider::DidMethodProvider,
    repository::{did_repository::DidRepository, key_repository::KeyRepository},
};

pub mod service;

pub mod dto;

pub(crate) mod mapper;
pub(crate) mod validator;

#[derive(Clone)]
pub struct DidService {
    did_repository: Arc<dyn DidRepository + Send + Sync>,
    key_repository: Arc<dyn KeyRepository + Send + Sync>,
    did_method_provider: Arc<dyn DidMethodProvider + Send + Sync>,
    config: Arc<CoreConfig>,
}

impl DidService {
    pub fn new(
        did_repository: Arc<dyn DidRepository + Send + Sync>,
        key_repository: Arc<dyn KeyRepository + Send + Sync>,
        did_method_provider: Arc<dyn DidMethodProvider + Send + Sync>,
        config: Arc<CoreConfig>,
    ) -> Self {
        Self {
            did_repository,
            key_repository,
            did_method_provider,
            config,
        }
    }
}

#[cfg(test)]
mod test;
