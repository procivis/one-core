use crate::config::core_config::RevocationType;
use crate::model::revocation_list::StatusListCredentialFormat;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationListResponseDTO {
    pub revocation_list: String,
    pub format: StatusListCredentialFormat,
    pub r#type: RevocationType,
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
