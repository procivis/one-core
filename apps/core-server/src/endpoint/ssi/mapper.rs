use one_core::provider::issuance_protocol::error::OpenID4VCIError;

use crate::endpoint::ssi::dto::OpenID4VCIErrorResponseRestDTO;

impl From<OpenID4VCIError> for OpenID4VCIErrorResponseRestDTO {
    fn from(value: OpenID4VCIError) -> Self {
        Self {
            error: value.into(),
        }
    }
}
