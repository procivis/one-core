mod service;

use std::sync::Arc;

use one_providers::credential_formatter::provider::CredentialFormatterProvider;
use one_providers::did::provider::DidMethodProvider;
use one_providers::key_algorithm::provider::KeyAlgorithmProvider;
use one_providers::key_storage::provider::KeyProvider;

use crate::repository::did_repository::DidRepository;

pub mod dto;
pub mod mapper;
mod validation;

pub struct VCAPIService {
    credential_formatter: Arc<dyn CredentialFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    did_repository: Arc<dyn DidRepository>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}
