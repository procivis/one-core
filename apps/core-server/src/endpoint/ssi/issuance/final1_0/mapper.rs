use one_core::provider::issuance_protocol::error::OpenID4VCIError;
use one_core::provider::issuance_protocol::openid4vci_final1_0::model::{
    ExtendedSubjectClaimsDTO, OpenID4VCIIssuerMetadataResponseDTO, OpenID4VCITokenRequestDTO,
    Timestamp,
};
use one_core::service::error::ServiceError;
use one_dto_mapper::convert_inner_of_inner;

use super::dto::{
    ExtendedSubjectClaimsRestDTO, OpenID4VCIErrorResponseRestDTO,
    OpenID4VCIIssuerMetadataResponseRestDTO, OpenID4VCITokenRequestRestDTO, TimestampRest,
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

impl From<OpenID4VCIIssuerMetadataResponseDTO> for OpenID4VCIIssuerMetadataResponseRestDTO {
    fn from(value: OpenID4VCIIssuerMetadataResponseDTO) -> Self {
        Self {
            credential_issuer: value.credential_issuer,
            credential_endpoint: value.credential_endpoint,
            notification_endpoint: value.notification_endpoint,
            credential_configurations_supported: value
                .credential_configurations_supported
                .into_iter()
                .map(|(key, value)| (key, value.into()))
                .collect(),
            display: convert_inner_of_inner(value.display),
        }
    }
}

impl From<ExtendedSubjectClaimsDTO> for ExtendedSubjectClaimsRestDTO {
    fn from(value: ExtendedSubjectClaimsDTO) -> Self {
        Self {
            claims: value
                .claims
                .into_iter()
                .map(|(key, value)| (key, value.into()))
                .collect(),
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
