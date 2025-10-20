use std::sync::Arc;

use crate::config::core_config;
use crate::proto::certificate_validator::CertificateValidator;
use crate::provider::blob_storage_provider::BlobStorageProvider;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::issuance_protocol::openid4vci_final1_0::service::get_protocol_base_url;
use crate::provider::issuance_protocol::provider::IssuanceProtocolProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;

pub mod dto;
pub mod mapper;
mod nonce;
pub mod service;
pub mod validator;

#[derive(Clone)]
pub struct OID4VCIFinal1_0Service {
    protocol_base_url: Option<String>,
    protocol_id: String,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    credential_repository: Arc<dyn CredentialRepository>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    key_repository: Arc<dyn KeyRepository>,
    config: Arc<core_config::CoreConfig>,
    protocol_provider: Arc<dyn IssuanceProtocolProvider>,
    key_provider: Arc<dyn KeyProvider>,
    did_repository: Arc<dyn DidRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    base_url: Option<String>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
}

#[allow(clippy::too_many_arguments)]
impl OID4VCIFinal1_0Service {
    pub(crate) fn new(
        core_base_url: Option<String>,
        protocol_id: String,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        credential_repository: Arc<dyn CredentialRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        revocation_list_repository: Arc<dyn RevocationListRepository>,
        validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
        key_repository: Arc<dyn KeyRepository>,
        config: Arc<core_config::CoreConfig>,
        protocol_provider: Arc<dyn IssuanceProtocolProvider>,
        key_provider: Arc<dyn KeyProvider>,
        did_repository: Arc<dyn DidRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
    ) -> Self {
        let protocol_base_url = core_base_url.as_ref().map(|url| get_protocol_base_url(url));
        Self {
            protocol_base_url,
            protocol_id,
            credential_schema_repository,
            credential_repository,
            interaction_repository,
            revocation_list_repository,
            validity_credential_repository,
            key_repository,
            identifier_repository,
            config,
            protocol_provider,
            key_provider,
            did_repository,
            did_method_provider,
            key_algorithm_provider,
            formatter_provider,
            revocation_method_provider,
            certificate_validator,
            base_url: core_base_url,
            blob_storage_provider,
        }
    }
}

#[cfg(test)]
mod test;
