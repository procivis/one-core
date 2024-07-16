use std::collections::HashMap;

use dto_mapper::{convert_inner, convert_inner_of_inner};
use one_core::provider::dto::PublicKeyJwkDTO;
use one_core::provider::exchange_protocol::openid4vc::dto::OpenID4VCICredentialOfferClaimValue;
use one_core::service::error::ServiceError;
use one_core::service::oidc::dto::{
    OpenID4VCIError, OpenID4VCIIssuerMetadataMdocClaimsValuesDTO, OpenID4VCITokenRequestDTO,
    Timestamp,
};
use one_providers::common_models::PublicKeyJwk;

use super::dto::{
    OpenID4VCIIssuerMetadataMdocClaimsValuesRestDTO, OpenID4VCITokenRequestRestDTO,
    PublicKeyJwkRestDTO, TimestampRest,
};
use crate::endpoint::ssi::dto::{
    OpenID4VCICredentialOfferClaimValueDTO, OpenID4VCIErrorResponseRestDTO,
};

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

impl From<OpenID4VCICredentialOfferClaimValue> for OpenID4VCICredentialOfferClaimValueDTO {
    fn from(value: OpenID4VCICredentialOfferClaimValue) -> Self {
        match value {
            OpenID4VCICredentialOfferClaimValue::Nested(nested) => {
                OpenID4VCICredentialOfferClaimValueDTO::Nested(convert_inner(nested))
            }
            OpenID4VCICredentialOfferClaimValue::String(value) => {
                OpenID4VCICredentialOfferClaimValueDTO::String(value)
            }
        }
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
            }),
            ("refresh_token", None, Some(refresh_token)) => {
                Ok(Self::RefreshToken { refresh_token })
            }
            ("urn:ietf:params:oauth:grant-type:pre-authorized_code" | "refresh_token", _, _) => {
                Err(ServiceError::OpenID4VCError(
                    OpenID4VCIError::InvalidRequest,
                ))
            }
            (grant, _, _) if !grant.is_empty() => Err(ServiceError::OpenID4VCError(
                OpenID4VCIError::UnsupportedGrantType,
            )),
            _ => Err(ServiceError::OpenID4VCError(
                OpenID4VCIError::InvalidRequest,
            )),
        }
    }
}

pub(super) fn convert_mdoc_claims(
    input: Option<HashMap<String, HashMap<String, OpenID4VCIIssuerMetadataMdocClaimsValuesDTO>>>,
) -> Option<HashMap<String, HashMap<String, OpenID4VCIIssuerMetadataMdocClaimsValuesRestDTO>>> {
    input.map(convert_inner_of_inner)
}

impl From<PublicKeyJwk> for PublicKeyJwkRestDTO {
    fn from(value: PublicKeyJwk) -> Self {
        PublicKeyJwkDTO::from(value).into()
    }
}
