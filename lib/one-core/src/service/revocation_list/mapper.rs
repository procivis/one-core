use super::dto::RevocationListResponseDTO;
use super::error::RevocationServiceError;
use crate::config::core_config::RevocationType;
use crate::model::revocation_list::{RevocationList, StatusListCredentialFormat};

impl RevocationList {
    pub fn get_status_credential(&self) -> Result<String, RevocationServiceError> {
        String::from_utf8(self.formatted_list.clone())
            .map_err(|e| RevocationServiceError::MappingError(e.to_string()))
    }
}

impl RevocationListResponseDTO {
    pub fn get_content_type(&self) -> Option<String> {
        match self.r#type {
            RevocationType::BitstringStatusList => match self.format {
                StatusListCredentialFormat::Jwt => Some("application/jwt".to_owned()),
                StatusListCredentialFormat::JsonLdClassic => Some("application/ld+json".to_owned()),
                _ => None,
            },
            RevocationType::TokenStatusList => Some("application/statuslist+jwt".to_owned()),
            RevocationType::CRL => Some("application/pkix-crl".to_owned()),
            _ => None,
        }
    }
}
