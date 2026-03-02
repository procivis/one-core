use std::sync::Arc;

use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::session_provider::SessionProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::repository::did_repository::DidRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::organisation_repository::OrganisationRepository;

pub mod dto;
pub mod error;
pub(crate) mod mapper;
pub mod service;
pub(crate) mod validator;

#[derive(Clone)]
pub struct DidService {
    did_repository: Arc<dyn DidRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    identifier_creator: Arc<dyn IdentifierCreator>,
    session_provider: Arc<dyn SessionProvider>,
}

impl DidService {
    pub(crate) fn new(
        did_repository: Arc<dyn DidRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        identifier_creator: Arc<dyn IdentifierCreator>,
        session_provider: Arc<dyn SessionProvider>,
    ) -> Self {
        Self {
            did_repository,
            identifier_repository,
            organisation_repository,
            did_method_provider,
            key_algorithm_provider,
            identifier_creator,
            session_provider,
        }
    }
}

#[cfg(test)]
mod test;
