use std::sync::Arc;

use one_providers::did::provider::DidMethodProvider;
use one_providers::key_algorithm::provider::KeyAlgorithmProvider;

use super::error::ErrorCode;
use crate::config::core_config;
use crate::repository::did_repository::DidRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::organisation_repository::OrganisationRepository;

pub mod service;

pub mod dto;

pub(crate) mod mapper;
pub(crate) mod validator;

#[derive(Clone)]
pub struct DidService {
    did_repository: Arc<dyn DidRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    key_repository: Arc<dyn KeyRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    config: Arc<core_config::CoreConfig>,
}

impl DidService {
    pub fn new(
        did_repository: Arc<dyn DidRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        key_repository: Arc<dyn KeyRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        config: Arc<core_config::CoreConfig>,
    ) -> Self {
        Self {
            did_repository,
            history_repository,
            key_repository,
            organisation_repository,
            did_method_provider,
            key_algorithm_provider,
            config,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum DidDeactivationError {
    #[error("DID {method} already has the same value `{value}` for deactivated field")]
    DeactivatedSameValue { value: bool, method: String },
    #[error("DID method {method} cannot be deactivated")]
    CannotBeDeactivated { method: String },
    #[error("Remote DID cannot be deactivated")]
    RemoteDid,
}

impl DidDeactivationError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::DeactivatedSameValue { .. } => ErrorCode::BR_0027,
            Self::CannotBeDeactivated { .. } | Self::RemoteDid => ErrorCode::BR_0029,
        }
    }
}

#[cfg(test)]
mod test;
