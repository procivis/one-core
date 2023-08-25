use std::sync::Arc;

use crate::{config::data_structure::CoreConfig, repository::did_repository::DidRepository};

pub mod service;

pub mod dto;

pub(crate) mod mapper;
pub(crate) mod validator;

#[derive(Clone)]
pub struct DidService {
    did_repository: Arc<dyn DidRepository + Send + Sync>,
    config: Arc<CoreConfig>,
}

impl DidService {
    pub fn new(repository: Arc<dyn DidRepository + Send + Sync>, config: Arc<CoreConfig>) -> Self {
        Self {
            did_repository: repository,
            config,
        }
    }
}
