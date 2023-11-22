use std::collections::HashMap;
use std::sync::Arc;

pub mod eddsa;
pub mod es256;
pub mod provider;

use eddsa::Eddsa;
use es256::Es256;

use crate::config::{
    core_config::{KeyAlgorithmConfig, KeyAlgorithmType},
    ConfigValidationError,
};

pub struct GeneratedKey {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

#[cfg_attr(test, mockall::automock)]
pub trait KeyAlgorithm {
    /// related crypto signer ID
    fn get_signer_algorithm_id(&self) -> String;

    /// base58-btc representation of the public key (following did:key spec)
    fn get_multibase(&self, public_key: &[u8]) -> String;

    /// generate a new in-memory key-pair
    fn generate_key_pair(&self) -> GeneratedKey;
}

pub fn key_algorithms_from_config(
    config: &KeyAlgorithmConfig,
) -> Result<HashMap<String, Arc<dyn KeyAlgorithm + Send + Sync>>, ConfigValidationError> {
    let mut key_algorithms: HashMap<String, Arc<dyn KeyAlgorithm + Send + Sync>> = HashMap::new();

    for (algorithm_type, fields) in config.as_inner() {
        // skip disabled algorithms
        if fields.disabled.is_some_and(|is_disabled| is_disabled) {
            continue;
        }

        match algorithm_type {
            KeyAlgorithmType::Eddsa => {
                let params = config.get(algorithm_type)?;
                let algorithm = Eddsa::new(params);

                key_algorithms.insert(algorithm_type.to_string(), Arc::new(algorithm) as _);
            }
            KeyAlgorithmType::Es256 => {
                let params = config.get(algorithm_type)?;
                let algorithm = Es256::new(params);

                key_algorithms.insert(algorithm_type.to_string(), Arc::new(algorithm) as _);
            }
            KeyAlgorithmType::Ecdsa => unimplemented!(),
            KeyAlgorithmType::BbsPlus => unimplemented!(),
        }
    }

    Ok(key_algorithms)
}
