pub mod dto;
pub mod mapper;
pub mod service;

pub(crate) mod validator;

use std::sync::Arc;

use crate::config::data_structure::CoreConfig;

use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;

#[derive(Clone)]
pub struct CredentialService {
    credential_repository: Arc<dyn CredentialRepository + Send + Sync>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository + Send + Sync>,
    did_repository: Arc<dyn DidRepository + Send + Sync>,
    revocation_list_repository: Arc<dyn RevocationListRepository + Send + Sync>,
    config: Arc<CoreConfig>,
}

impl CredentialService {
    pub(crate) fn new(
        repository: Arc<dyn CredentialRepository + Send + Sync>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository + Send + Sync>,
        did_repository: Arc<dyn DidRepository + Send + Sync>,
        revocation_list_repository: Arc<dyn RevocationListRepository + Send + Sync>,
        config: Arc<CoreConfig>,
    ) -> Self {
        Self {
            credential_repository: repository,
            credential_schema_repository,
            did_repository,
            revocation_list_repository,
            config,
        }
    }
}

#[cfg(test)]
mod test;
