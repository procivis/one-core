pub mod dto;
pub mod service;

use std::sync::Arc;

use crate::config::core_config;
use crate::config::core_config::IssuanceProtocolType;
use crate::proto::certificate_validator::CertificateValidator;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::issuance_protocol::openid4vci_draft13_swiyu::OID4VCI_DRAFT13_SWIYU_VERSION;
use crate::provider::issuance_protocol::provider::IssuanceProtocolProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::key_repository::KeyRepository;
use crate::service::oid4vci_draft13::OID4VCIDraft13Service;

#[derive(Clone)]
pub struct OID4VCIDraft13SwiyuService {
    inner: OID4VCIDraft13Service,
}

impl OID4VCIDraft13SwiyuService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        core_base_url: Option<String>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        credential_repository: Arc<dyn CredentialRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        key_repository: Arc<dyn KeyRepository>,
        config: Arc<core_config::CoreConfig>,
        protocol_provider: Arc<dyn IssuanceProtocolProvider>,
        did_repository: Arc<dyn DidRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
    ) -> Self {
        let protocol_base_url = core_base_url
            .as_ref()
            .map(|url| format!("{url}/ssi/openid4vci/{OID4VCI_DRAFT13_SWIYU_VERSION}"));
        Self {
            inner: OID4VCIDraft13Service::new_with_custom_protocol(
                protocol_base_url,
                IssuanceProtocolType::OpenId4VciDraft13Swiyu,
                credential_schema_repository,
                credential_repository,
                interaction_repository,
                key_repository,
                config,
                protocol_provider,
                did_repository,
                identifier_repository,
                did_method_provider,
                key_algorithm_provider,
                formatter_provider,
                revocation_method_provider,
                certificate_validator,
            ),
        }
    }
}
