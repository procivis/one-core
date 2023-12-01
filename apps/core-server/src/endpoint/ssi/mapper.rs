use crate::endpoint::ssi::dto::{DurationSecondsRest, OpenID4VCIErrorResponseRestDTO};
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
