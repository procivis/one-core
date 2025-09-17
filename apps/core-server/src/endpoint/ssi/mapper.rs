use one_core::model::key::PublicKeyJwk;
use one_core::provider::issuance_protocol::error::OpenID4VCIError;
use one_core::service::key::dto::PublicKeyJwkDTO;

use super::dto::PublicKeyJwkRestDTO;
use crate::endpoint::ssi::dto::OpenID4VCIErrorResponseRestDTO;

impl From<OpenID4VCIError> for OpenID4VCIErrorResponseRestDTO {
    fn from(value: OpenID4VCIError) -> Self {
        Self {
            error: value.into(),
        }
    }
}

impl From<PublicKeyJwk> for PublicKeyJwkRestDTO {
    fn from(value: PublicKeyJwk) -> Self {
        PublicKeyJwkDTO::from(value).into()
    }
}
