use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::service::error::ServiceError;

pub type RevocationListId = Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationListResponse {
    pub revocation_list: String,
    pub format: SupportedBitstringCredentialFormat,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SupportedBitstringCredentialFormat {
    Jwt,
    JsonLdClassic,
}

impl Default for SupportedBitstringCredentialFormat {
    fn default() -> Self {
        Self::Jwt
    }
}

impl From<SupportedBitstringCredentialFormat> for String {
    fn from(val: SupportedBitstringCredentialFormat) -> Self {
        match val {
            SupportedBitstringCredentialFormat::Jwt => "JWT".to_string(),
            SupportedBitstringCredentialFormat::JsonLdClassic => "JSON_LD_CLASSIC".to_string(),
        }
    }
}

impl TryFrom<String> for SupportedBitstringCredentialFormat {
    type Error = ServiceError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "JWT" => Ok(Self::Jwt),
            "JSON_LD_CLASSIC" => Ok(Self::JsonLdClassic),
            _ => Err(ServiceError::MappingError("Unsupported format".to_string())),
        }
    }
}
