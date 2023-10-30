use crate::endpoint::ssi::dto::{DurationSecondsRest, OpenID4VCIErrorResponseRestDTO};
use one_core::service::oidc::dto::{DurationSeconds, OpenID4VCIError};

impl From<OpenID4VCIError> for OpenID4VCIErrorResponseRestDTO {
    fn from(value: OpenID4VCIError) -> Self {
        OpenID4VCIErrorResponseRestDTO {
            error: value.into(),
        }
    }
}

impl From<DurationSeconds> for DurationSecondsRest {
    fn from(value: DurationSeconds) -> Self {
        DurationSecondsRest(value.0)
    }
}
