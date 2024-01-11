use std::sync::Arc;

use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::{
    config::core_config,
    provider::did_method::provider::DidMethodProvider,
    repository::{
        did_repository::DidRepository, key_repository::KeyRepository,
        organisation_repository::OrganisationRepository,
    },
};

use super::error::ErrorCode;

pub mod service;

pub mod dto;

pub(crate) mod mapper;
pub(crate) mod validator;

#[derive(Clone)]
pub struct DidService {
    did_repository: Arc<dyn DidRepository>,
    key_repository: Arc<dyn KeyRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    config: Arc<core_config::CoreConfig>,
}

impl DidService {
    pub fn new(
        did_repository: Arc<dyn DidRepository>,
        key_repository: Arc<dyn KeyRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        config: Arc<core_config::CoreConfig>,
    ) -> Self {
        Self {
            did_repository,
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
            Self::DeactivatedSameValue { .. } => ErrorCode::DidDeactivated,
            Self::CannotBeDeactivated { .. } => ErrorCode::DidCannotDeactivate,
            Self::RemoteDid => ErrorCode::DidCannotDeactivate,
        }
    }
}

#[cfg(test)]
mod test;
