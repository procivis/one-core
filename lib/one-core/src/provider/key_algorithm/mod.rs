use std::collections::HashMap;
use std::sync::Arc;

pub mod eddsa;
pub mod es256;
pub mod ml_dsa;
pub mod provider;

use eddsa::Eddsa;
use es256::Es256;
use ml_dsa::MlDsa;

use crate::config::{
    core_config::{KeyAlgorithmConfig, KeyAlgorithmType},
    ConfigValidationError,
};

use crate::service::error::ServiceError;

use super::did_method::dto::PublicKeyJwkDTO;

pub struct GeneratedKey {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

#[cfg_attr(test, mockall::automock)]
pub trait KeyAlgorithm: Send + Sync {
    /// related crypto signer ID
    fn get_signer_algorithm_id(&self) -> String;

    /// base58-btc representation of the public key (following did:key spec)
    fn get_multibase(&self, public_key: &[u8]) -> String;

    /// generate a new in-memory key-pair
    fn generate_key_pair(&self) -> GeneratedKey;

    fn bytes_to_jwk(&self, bytes: &[u8]) -> Result<PublicKeyJwkDTO, ServiceError>;

    fn jwk_to_bytes(&self, jwk: &PublicKeyJwkDTO) -> Result<Vec<u8>, ServiceError>;
}

pub fn key_algorithms_from_config(
    config: &KeyAlgorithmConfig,
) -> Result<HashMap<String, Arc<dyn KeyAlgorithm>>, ConfigValidationError> {
    let mut key_algorithms: HashMap<String, Arc<dyn KeyAlgorithm>> = HashMap::new();

    for (name, field) in config.iter() {
        let key_algorithm = match &field.r#type {
            KeyAlgorithmType::Eddsa => {
                let params = config.get(name)?;
                Arc::new(Eddsa::new(params)) as _
            }
            KeyAlgorithmType::Es256 => {
                let params = config.get(name)?;
                Arc::new(Es256::new(params)) as _
            }
            KeyAlgorithmType::Ecdsa => continue,
            KeyAlgorithmType::BbsPlus => continue,
            KeyAlgorithmType::MlDsa => {
                let params = config.get(name)?;
                Arc::new(MlDsa::new(params)) as _
            }
        };
        key_algorithms.insert(name.to_owned(), key_algorithm);
    }

    Ok(key_algorithms)
}
