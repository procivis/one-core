use std::cmp::Reverse;
use std::sync::Arc;

use coset::CoseKey;
use itertools::Itertools;
use secrecy::SecretSlice;
use standardized_types::jwk::{JwkUse, PublicJwk};

use super::KeyAlgorithm;
use super::bbs::BBS;
use super::ecdsa::Ecdsa;
use super::eddsa::Eddsa;
use super::error::KeyAlgorithmProviderError;
use super::key::KeyHandle;
use super::ml_dsa::MlDsa;
use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, KeyAlgorithmFields, KeyAlgorithmType};
use crate::error::{ContextWithErrorCode, NestedError};
use crate::model::key::Key;
use crate::provider::provider_directory::{InitializationError, ProviderDirectory};

#[derive(Clone)]
pub struct ParsedKey {
    pub algorithm_type: KeyAlgorithmType,
    pub key: KeyHandle,
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait KeyAlgorithmProvider: Send + Sync {
    fn key_algorithm_from_type(
        &self,
        algorithm: KeyAlgorithmType,
    ) -> Result<Arc<dyn KeyAlgorithm>, NestedError>;

    fn key_algorithm_from_key(
        &self,
        key: &Key,
    ) -> Result<Arc<dyn KeyAlgorithm>, KeyAlgorithmProviderError>;

    fn key_algorithm_from_jose_alg(
        &self,
        jose_alg: &str,
    ) -> Option<(KeyAlgorithmType, Arc<dyn KeyAlgorithm>)>;
    fn key_algorithm_from_cose_alg(
        &self,
        cose_alg: i64,
    ) -> Option<(KeyAlgorithmType, Arc<dyn KeyAlgorithm>)>;

    fn parse_jwk(&self, key: &PublicJwk) -> Result<ParsedKey, KeyAlgorithmProviderError>;
    fn parse_multibase(&self, multibase: &str) -> Result<ParsedKey, KeyAlgorithmProviderError>;
    fn parse_cose(&self, cose_key: &CoseKey) -> Result<ParsedKey, KeyAlgorithmProviderError>;

    fn reconstruct_key(
        &self,
        algorithm: KeyAlgorithmType,
        public_key: &[u8],
        private_key: Option<SecretSlice<u8>>,
        r#use: Option<JwkUse>,
    ) -> Result<KeyHandle, KeyAlgorithmProviderError>;

    fn supported_verification_jose_alg_ids(&self) -> Vec<String>;
    fn ordered_by_holder_priority(&self) -> Vec<(KeyAlgorithmType, Arc<dyn KeyAlgorithm>)>;

    /// All configured key algorithms, including the disabled ones.
    fn algorithms(&self) -> Vec<(KeyAlgorithmType, Arc<dyn KeyAlgorithm>)>;
}

struct KeyAlgorithmProviderImpl {
    directory: ProviderDirectory<KeyAlgorithmType, KeyAlgorithmFields, dyn KeyAlgorithm>,
}

impl KeyAlgorithmProvider for KeyAlgorithmProviderImpl {
    fn key_algorithm_from_type(
        &self,
        algorithm: KeyAlgorithmType,
    ) -> Result<Arc<dyn KeyAlgorithm>, NestedError> {
        self.directory.provider(&algorithm)
    }

    fn key_algorithm_from_key(
        &self,
        key: &Key,
    ) -> Result<Arc<dyn KeyAlgorithm>, KeyAlgorithmProviderError> {
        let key_type = key
            .key_algorithm_type()
            .error_while("getting key algorithm type")?;
        self.directory.provider(&key_type).map_err(Into::into)
    }

    fn key_algorithm_from_jose_alg(
        &self,
        jose_alg: &str,
    ) -> Option<(KeyAlgorithmType, Arc<dyn KeyAlgorithm>)> {
        self.directory
            .iter()
            .find(|(_, alg)| {
                alg.verification_jose_alg_ids()
                    .iter()
                    .any(|v| v == jose_alg)
            })
            .map(|(id, alg)| (id.to_owned(), alg.clone()))
    }

    fn key_algorithm_from_cose_alg(
        &self,
        cose_alg: i64,
    ) -> Option<(KeyAlgorithmType, Arc<dyn KeyAlgorithm>)> {
        self.directory
            .iter()
            .find(|(_, alg)| alg.cose_alg_id().is_some_and(|alg| alg == cose_alg))
            .map(|(id, alg)| (id.to_owned(), alg.clone()))
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "info"))]
    fn parse_jwk(&self, key: &PublicJwk) -> Result<ParsedKey, KeyAlgorithmProviderError> {
        for (_, algorithm) in self.directory.iter() {
            if let Ok(public_key) = algorithm.parse_jwk(key) {
                return Ok(ParsedKey {
                    algorithm_type: algorithm.algorithm_type(),
                    key: public_key,
                });
            }
        }

        Err(KeyAlgorithmProviderError::MissingAlgorithmImplementation(
            "None of the algorithms supports given key".to_string(),
        ))
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "info"))]
    fn parse_multibase(&self, multibase: &str) -> Result<ParsedKey, KeyAlgorithmProviderError> {
        for (_, algorithm) in self.directory.iter() {
            if let Ok(public_key) = algorithm.parse_multibase(multibase) {
                return Ok(ParsedKey {
                    algorithm_type: algorithm.algorithm_type(),
                    key: public_key,
                });
            }
        }

        Err(KeyAlgorithmProviderError::MissingAlgorithmImplementation(
            "None of the algorithms supports given key".to_string(),
        ))
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "info"))]
    fn parse_cose(&self, cose_key: &CoseKey) -> Result<ParsedKey, KeyAlgorithmProviderError> {
        for (_, algorithm) in self.directory.iter() {
            if let Ok(public_key) = algorithm.parse_cose(cose_key) {
                return Ok(ParsedKey {
                    algorithm_type: algorithm.algorithm_type(),
                    key: public_key,
                });
            }
        }

        Err(KeyAlgorithmProviderError::MissingAlgorithmImplementation(
            "None of the algorithms supports given key".to_string(),
        ))
    }

    fn reconstruct_key(
        &self,
        algorithm: KeyAlgorithmType,
        public_key: &[u8],
        private_key: Option<SecretSlice<u8>>,
        r#use: Option<JwkUse>,
    ) -> Result<KeyHandle, KeyAlgorithmProviderError> {
        let algorithm = self.key_algorithm_from_type(algorithm)?;
        Ok(algorithm
            .reconstruct_key(public_key, private_key, r#use)
            .error_while("reconstructing key")?)
    }

    fn supported_verification_jose_alg_ids(&self) -> Vec<String> {
        self.directory
            .iter()
            .flat_map(|(_, key_alg)| key_alg.verification_jose_alg_ids())
            .collect()
    }

    fn ordered_by_holder_priority(&self) -> Vec<(KeyAlgorithmType, Arc<dyn KeyAlgorithm>)> {
        let get_holder_priority = |r#type: &KeyAlgorithmType| -> u32 {
            self.directory
                .config(r#type)
                .ok()
                .iter()
                .flat_map(|config| config.enabled.then_some(config.holder_priority))
                .next()
                .unwrap_or(0)
        };

        self.directory
            .iter()
            .sorted_by_key(|(k, _)| Reverse(get_holder_priority(k)))
            .map(|(k, v)| (*k, v.to_owned()))
            .collect()
    }

    fn algorithms(&self) -> Vec<(KeyAlgorithmType, Arc<dyn KeyAlgorithm>)> {
        self.directory
            .iter()
            .map(|(r#type, algorithm)| (*r#type, algorithm.to_owned()))
            .collect()
    }
}

pub(crate) fn key_algorithm_provider_from_config(
    config: &mut CoreConfig,
) -> Result<Arc<dyn KeyAlgorithmProvider>, ConfigValidationError> {
    let directory =
        ProviderDirectory::initialize(config.key_algorithm.iter_mut(), initialize_provider)
            .error_while("initializing key algorithm providers")?;
    Ok(Arc::new(KeyAlgorithmProviderImpl { directory }))
}

fn initialize_provider(
    r#type: &KeyAlgorithmType,
    _field: &KeyAlgorithmFields,
) -> Result<Arc<dyn KeyAlgorithm>, InitializationError> {
    let provider: Arc<dyn KeyAlgorithm> = match r#type {
        KeyAlgorithmType::Eddsa => Arc::new(Eddsa),
        KeyAlgorithmType::Ecdsa => Arc::new(Ecdsa),
        KeyAlgorithmType::BbsPlus => Arc::new(BBS),
        KeyAlgorithmType::MlDsa => Arc::new(MlDsa),
    };
    Ok(provider)
}
