pub mod service;

use std::sync::Arc;

use crate::config::core_config;
use crate::config::core_config::IssuanceProtocolType;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::issuance_protocol::openid4vci_draft13_swiyu::OID4VCI_DRAFT13_SWIYU_VERSION;
use crate::provider::issuance_protocol::provider::IssuanceProtocolProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::interaction_repository::InteractionRepository;
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
        config: Arc<core_config::CoreConfig>,
        protocol_provider: Arc<dyn IssuanceProtocolProvider>,
        did_repository: Arc<dyn DidRepository>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
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
                config,
                protocol_provider,
                did_repository,
                did_method_provider,
                key_algorithm_provider,
                formatter_provider,
            ),
        }
    }
}
