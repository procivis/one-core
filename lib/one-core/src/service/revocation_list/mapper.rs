use super::dto::RevocationListResponseDTO;
use crate::config::core_config::RevocationType;
use crate::model::revocation_list::StatusListCredentialFormat;

impl RevocationListResponseDTO {
    pub fn get_content_type(&self) -> Option<String> {
        match self.r#type {
            RevocationType::BitstringStatusList => match self.format {
                StatusListCredentialFormat::Jwt => Some("application/jwt".to_owned()),
                StatusListCredentialFormat::JsonLdClassic => Some("application/ld+json".to_owned()),
                _ => None,
            },
            RevocationType::TokenStatusList => match self.format {
                StatusListCredentialFormat::Jwt => Some("application/statuslist+jwt".to_owned()),
                StatusListCredentialFormat::Cwt => Some("application/statuslist+cwt".to_owned()),
                _ => None,
            },
            RevocationType::CRL => Some("application/pkix-crl".to_owned()),
            _ => None,
        }
    }
}
