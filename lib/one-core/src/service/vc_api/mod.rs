mod service;

use std::sync::Arc;

use crate::repository::did_repository::DidRepository;
use one_providers::{
    credential_formatter::provider::CredentialFormatterProvider, did::provider::DidMethodProvider,
    key_algorithm::provider::KeyAlgorithmProvider, key_storage::provider::KeyProvider,
};

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
