use one_core::config;
use strum::{Display, EnumString};

#[derive(Debug, Copy, Clone, Display, EnumString, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyAlgorithmType {
    #[strum(serialize = "EDDSA")]
    Eddsa,
    #[strum(serialize = "BBS_PLUS")]
    BbsPlus,
    #[strum(serialize = "ECDSA")]
    Ecdsa,
}

impl From<KeyAlgorithmType> for config::core_config::KeyAlgorithmType {
    fn from(key_algorithm_type: KeyAlgorithmType) -> Self {
        match key_algorithm_type {
            KeyAlgorithmType::Eddsa => config::core_config::KeyAlgorithmType::Eddsa,
            KeyAlgorithmType::BbsPlus => config::core_config::KeyAlgorithmType::BbsPlus,
            KeyAlgorithmType::Ecdsa => config::core_config::KeyAlgorithmType::Ecdsa,
        }
    }
}

#[derive(Debug, Copy, Clone, Display, EnumString, PartialEq, Eq, PartialOrd, Ord)]
pub enum CredentialFormat {
    #[strum(serialize = "JWT")]
    Jwt,
    #[strum(serialize = "SD_JWT")]
    SdJwt,
    #[strum(serialize = "JSON_LD_BBSPLUS")]
    JsonLdBbsPlus,
}

#[derive(Debug, Copy, Clone, Display, EnumString, PartialEq, Eq, PartialOrd, Ord)]
pub enum StorageType {
    #[strum(serialize = "INTERNAL")]
    Internal,
}

#[derive(Debug, Copy, Clone, Display, EnumString, PartialEq, Eq, PartialOrd, Ord)]
pub enum DidMethodType {
    #[strum(serialize = "JWK")]
    Jwk,
    #[strum(serialize = "KEY")]
    Key,
    #[strum(serialize = "WEB")]
    Web,
}
