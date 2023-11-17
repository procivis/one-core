use std::collections::HashMap;
use std::sync::Arc;

use crate::config::{
    data_structure::{KeyAlgorithmEntity, ParamsEnum},
    ConfigParseError,
};

pub mod eddsa;
pub mod es256;
pub mod provider;

use eddsa::Eddsa;
use es256::Es256;

pub struct GeneratedKey {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

#[cfg_attr(test, mockall::automock)]
pub trait KeyAlgorithm {
    fn fingerprint(&self, public_key: &[u8]) -> String;
    fn generate_key_pair(&self) -> GeneratedKey;
}

pub fn key_algorithms_from_config(
    algorithm_config: &HashMap<String, KeyAlgorithmEntity>,
) -> Result<HashMap<String, Arc<dyn KeyAlgorithm + Send + Sync>>, ConfigParseError> {
    algorithm_config
        .iter()
        .filter_map(|(name, entity)| algorithm_from_entity(name, entity).transpose())
        .collect::<Result<HashMap<String, _>, _>>()
}

// clippy::type-complexity
type KeyAlgorithmOption = Option<(String, Arc<dyn KeyAlgorithm + Send + Sync>)>;

fn algorithm_from_entity(
    name: &String,
    entity: &KeyAlgorithmEntity,
) -> Result<KeyAlgorithmOption, ConfigParseError> {
    if entity.disabled.is_some_and(|is_disabled| is_disabled) {
        return Ok(None);
    }

    let params = match &entity.params {
        None => Err(ConfigParseError::MissingParameter(
            "algorithm".to_string(),
            name.to_owned(),
        )),
        Some(value) => match value {
            ParamsEnum::Parsed(value) => Ok(value.to_owned()),
            _ => Err(ConfigParseError::InvalidType(
                name.to_owned(),
                String::new(),
            )),
        },
    }?;

    match entity.r#type.as_str() {
        "EDDSA" => Ok(Some((
            name.to_owned(),
            Arc::new(Eddsa::new(&params.algorithm.value)?),
        ))),
        "ES256" => Ok(Some((
            name.to_owned(),
            Arc::new(Es256::new(&params.algorithm.value)?),
        ))),
        _ => Err(ConfigParseError::InvalidType(
            entity.r#type.to_owned(),
            String::new(),
        )),
    }
}
