use crate::model::revocation_list::{StatusListCredentialFormat, StatusListType};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationListResponseDTO {
    pub revocation_list: String,
    pub format: StatusListCredentialFormat,
    pub r#type: StatusListType,
}

impl RevocationListResponseDTO {
    pub fn get_content_type(&self) -> String {
        match self.r#type {
            StatusListType::BitstringStatusList => match self.format {
                StatusListCredentialFormat::Jwt => "application/jwt".to_owned(),
                StatusListCredentialFormat::JsonLdClassic => "application/ld+json".to_owned(),
                StatusListCredentialFormat::X509Crl => "application/pkix-crl".to_owned(),
            },
            StatusListType::TokenStatusList => "application/statuslist+jwt".to_owned(),
            StatusListType::Crl => "application/pkix-crl".to_owned(),
        }
    }
}
