use one_core::provider::issuance_protocol::error::OpenID4VCIError;
use one_core::provider::issuance_protocol::openid4vci_final1_0::model::{
    OpenID4VCIIssuerMetadataCredentialMetadataProcivisDesign, OpenID4VCIIssuerMetadataResponseDTO,
    OpenID4VCITokenRequestDTO, Timestamp,
};
use one_core::service::credential_schema::dto::CredentialSchemaCodeTypeEnum;
use one_core::service::error::ServiceError;
use one_dto_mapper::{convert_inner, convert_inner_of_inner};

use super::dto::{
    OpenID4VCIErrorResponseRestDTO, OpenID4VCIIssuerMetadataResponseRestDTO,
    OpenID4VCITokenRequestRestDTO, TimestampRest,
};
use crate::endpoint::ssi::issuance::final1_0::dto::OpenID4VCIIssuerMetadataCredentialMetadataProcivisDesignRestDTO;

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
            authorization_servers: value.authorization_servers,
            credential_endpoint: value.credential_endpoint,
            notification_endpoint: value.notification_endpoint,
            credential_configurations_supported: value
                .credential_configurations_supported
                .into_iter()
                .map(|(key, value)| (key, value.into()))
                .collect(),
            display: convert_inner_of_inner(value.display),
            nonce_endpoint: value.nonce_endpoint,
        }
    }
}

impl From<OpenID4VCIIssuerMetadataCredentialMetadataProcivisDesign>
    for OpenID4VCIIssuerMetadataCredentialMetadataProcivisDesignRestDTO
{
    fn from(value: OpenID4VCIIssuerMetadataCredentialMetadataProcivisDesign) -> Self {
        Self {
            primary_attribute: value.primary_attribute,
            secondary_attribute: value.secondary_attribute,
            picture_attribute: value.picture_attribute,
            code_attribute: value.code_attribute,
            code_type: convert_inner(value.code_type.map(CredentialSchemaCodeTypeEnum::from)),
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
