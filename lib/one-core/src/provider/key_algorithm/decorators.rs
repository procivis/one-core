use std::fmt::Display;
use std::sync::Arc;

use coset::CoseKey;
use secrecy::SecretSlice;
use standardized_types::jwk::{JwkUse, PrivateJwk, PublicJwk};

use crate::config::core_config::KeyAlgorithmType;
use crate::provider::Provider;
use crate::provider::disabled_provider::DisabledProvider;
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::model::{GeneratedKey, KeyAlgorithmCapabilities};
use crate::provider::provider_directory::WithDisabledDecorator;

impl WithDisabledDecorator for dyn KeyAlgorithm {
    fn decorate(self: Arc<dyn KeyAlgorithm>) -> Arc<dyn KeyAlgorithm> {
        Arc::new(DisabledProvider::new(self))
    }
}

#[async_trait::async_trait]
impl<T: Provider + KeyAlgorithm + Display + ?Sized> KeyAlgorithm for DisabledProvider<T> {
    fn algorithm_type(&self) -> KeyAlgorithmType {
        self.inner().algorithm_type()
    }

    fn get_capabilities(&self) -> KeyAlgorithmCapabilities {
        KeyAlgorithmCapabilities::default()
    }

    fn generate_key(&self) -> Result<GeneratedKey, KeyAlgorithmError> {
        self.disabled_error()
    }

    fn reconstruct_key(
        &self,
        _public_key: &[u8],
        _private_key: Option<SecretSlice<u8>>,
        _use: Option<JwkUse>,
    ) -> Result<KeyHandle, KeyAlgorithmError> {
        self.disabled_error()
    }

    fn issuance_jose_alg_id(&self) -> String {
        self.inner().issuance_jose_alg_id()
    }

    fn verification_jose_alg_ids(&self) -> Vec<String> {
        vec![]
    }

    fn cose_alg_id(&self) -> Option<i64> {
        None
    }

    fn parse_jwk(&self, _key: &PublicJwk) -> Result<KeyHandle, KeyAlgorithmError> {
        self.disabled_error()
    }

    fn parse_private_jwk(&self, _jwk: PrivateJwk) -> Result<GeneratedKey, KeyAlgorithmError> {
        self.disabled_error()
    }

    fn parse_multibase(&self, _multibase: &str) -> Result<KeyHandle, KeyAlgorithmError> {
        self.disabled_error()
    }

    fn parse_der(&self, _public_key_der: &[u8]) -> Result<KeyHandle, KeyAlgorithmError> {
        self.disabled_error()
    }

    fn parse_cose(&self, _cose_key: &CoseKey) -> Result<KeyHandle, KeyAlgorithmError> {
        self.disabled_error()
    }
}
