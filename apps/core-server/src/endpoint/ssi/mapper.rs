use crate::endpoint::ssi::dto::{
    DurationSecondsRest, OpenID4VCICredentialOfferClaimValueDTO, OpenID4VCIErrorResponseRestDTO,
};
use dto_mapper::convert_inner;
use one_core::provider::transport_protocol::openid4vc::dto::OpenID4VCICredentialOfferClaimValue;
use one_core::service::oidc::dto::{DurationSeconds, OpenID4VCIError};

impl From<OpenID4VCIError> for OpenID4VCIErrorResponseRestDTO {
    fn from(value: OpenID4VCIError) -> Self {
        Self {
            error: value.into(),
        }
    }
}

impl From<DurationSeconds> for DurationSecondsRest {
    fn from(value: DurationSeconds) -> Self {
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
