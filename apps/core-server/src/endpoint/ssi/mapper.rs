use one_core::model::key::PublicKeyJwk;
use one_core::provider::issuance_protocol::openid4vci_draft13::error::OpenID4VCIError;
use one_core::provider::issuance_protocol::openid4vci_draft13::model::{
    OpenID4VCITokenRequestDTO, Timestamp,
};
use one_core::service::error::ServiceError;
use one_core::service::key::dto::PublicKeyJwkDTO;

use super::dto::{OpenID4VCITokenRequestRestDTO, PublicKeyJwkRestDTO, TimestampRest};
use crate::endpoint::ssi::dto::OpenID4VCIErrorResponseRestDTO;

impl From<OpenID4VCIError> for OpenID4VCIErrorResponseRestDTO {
    fn from(value: OpenID4VCIError) -> Self {
        Self {
            error: value.into(),
        }
    }
}

impl From<Timestamp> for TimestampRest {
    fn from(value: Timestamp) -> Self {
        Self(value.0)
    }
}

impl TryFrom<OpenID4VCITokenRequestRestDTO> for OpenID4VCITokenRequestDTO {
    type Error = ServiceError;

    fn try_from(value: OpenID4VCITokenRequestRestDTO) -> Result<Self, Self::Error> {
        match (
            value.grant_type.as_str(),
            value.pre_authorized_code,
            value.refresh_token,
        ) {
            (
                "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                Some(pre_authorized_code),
                None,
            ) => Ok(Self::PreAuthorizedCode {
                pre_authorized_code,
                tx_code: None,
            }),
            ("refresh_token", None, Some(refresh_token)) => {
                Ok(Self::RefreshToken { refresh_token })
            }
            ("urn:ietf:params:oauth:grant-type:pre-authorized_code" | "refresh_token", _, _) => {
                Err(ServiceError::OpenID4VCIError(
                    OpenID4VCIError::InvalidRequest,
                ))
            }
            (grant, _, _) if !grant.is_empty() => Err(ServiceError::OpenID4VCIError(
                OpenID4VCIError::UnsupportedGrantType,
            )),
            _ => Err(ServiceError::OpenID4VCIError(
                OpenID4VCIError::InvalidRequest,
            )),
        }
    }
}

impl From<PublicKeyJwk> for PublicKeyJwkRestDTO {
    fn from(value: PublicKeyJwk) -> Self {
        PublicKeyJwkDTO::from(value).into()
    }
}
