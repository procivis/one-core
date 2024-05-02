use std::collections::HashMap;
use std::sync::Arc;

pub mod bbs;
pub mod eddsa;
pub mod es256;
pub mod ml_dsa;
pub mod provider;

use bbs::BBS;
use eddsa::Eddsa;
use es256::Es256;
use ml_dsa::MlDsa;
use zeroize::Zeroizing;

use crate::{
    config::{
        core_config::{KeyAlgorithmConfig, KeyAlgorithmType},
        ConfigValidationError,
    },
    crypto::signer::error::SignerError,
    service::error::ServiceError,
};

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
    fn get_multibase(&self, public_key: &[u8]) -> Result<String, SignerError>;

    /// generate a new in-memory key-pair
    fn generate_key_pair(&self) -> GeneratedKey;

    fn bytes_to_jwk(
        &self,
        bytes: &[u8],
        r#use: Option<String>,
    ) -> Result<PublicKeyJwkDTO, ServiceError>;

    fn jwk_to_bytes(&self, jwk: &PublicKeyJwkDTO) -> Result<Vec<u8>, ServiceError>;

    fn private_key_as_jwk(
        &self,
        _secret_key: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<String>, ServiceError> {
        Err(ServiceError::KeyAlgorithmError(format!(
            "unsupported operation for {}",
            std::any::type_name::<Self>()
        )))
    }
}

pub fn key_algorithms_from_config(
    config: &KeyAlgorithmConfig,
) -> Result<HashMap<String, Arc<dyn KeyAlgorithm>>, ConfigValidationError> {
    let mut key_algorithms: HashMap<String, Arc<dyn KeyAlgorithm>> = HashMap::new();

    for (name, field) in config.iter() {
        let key_algorithm: Arc<dyn KeyAlgorithm> = match &field.r#type {
            KeyAlgorithmType::Eddsa => {
                let params = config.get(name)?;
                Arc::new(Eddsa::new(params))
            }
            KeyAlgorithmType::Es256 => {
                let params = config.get(name)?;
                Arc::new(Es256::new(params))
            }
            KeyAlgorithmType::Ecdsa => continue,
            KeyAlgorithmType::BbsPlus => Arc::new(BBS),
            KeyAlgorithmType::MlDsa => {
                let params = config.get(name)?;
                Arc::new(MlDsa::new(params))
            }
        };
        key_algorithms.insert(name.to_owned(), key_algorithm);
    }

    Ok(key_algorithms)
}
