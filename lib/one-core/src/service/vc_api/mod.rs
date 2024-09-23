mod service;

use std::sync::Arc;

use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::repository::did_repository::DidRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;

pub mod dto;
pub mod mapper;
mod validation;

pub struct VCAPIService {
    credential_formatter: Arc<dyn CredentialFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    did_repository: Arc<dyn DidRepository>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    base_url: Option<String>,
}
