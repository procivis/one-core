mod service;

use std::sync::Arc;

use crate::provider::credential_formatter::json_ld::context::caching_loader::ContextCache;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::repository::did_repository::DidRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::service::certificate::validator::CertificateValidator;

pub mod dto;
pub mod mapper;
mod validation;

pub struct VCAPIService {
    credential_formatter: Arc<dyn CredentialFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    did_repository: Arc<dyn DidRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    jsonld_ctx_cache: ContextCache,
    base_url: Option<String>,
    certificate_validator: Arc<dyn CertificateValidator>,
}
