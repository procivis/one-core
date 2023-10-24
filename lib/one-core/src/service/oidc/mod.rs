use std::sync::Arc;

use crate::repository::credential_schema_repository::CredentialSchemaRepository;

pub mod dto;
pub mod mapper;
pub mod service;

#[derive(Clone)]
pub struct OIDCService {
    pub(crate) core_base_url: Option<String>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository + Send + Sync>,
}

impl OIDCService {
    pub(crate) fn new(
        core_base_url: Option<String>,
        repository: Arc<dyn CredentialSchemaRepository + Send + Sync>,
    ) -> Self {
        Self {
            credential_schema_repository: repository,
            core_base_url,
        }
    }
}

#[cfg(test)]
mod test;
