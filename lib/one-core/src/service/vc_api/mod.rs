mod service;

use std::sync::Arc;

use crate::proto::certificate_validator::CertificateValidator;
use crate::provider::caching_loader::json_ld_context::ContextCache;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::repository::did_repository::DidRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;

pub mod dto;
pub mod mapper;
pub mod model;
mod validation;

#[expect(dead_code)]
pub struct VCAPIService {
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
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
