use one_core::provider::issuance_protocol::error::OpenID4VCIError;
use one_core::provider::issuance_protocol::openid4vci_draft13::model::{
    ExtendedSubjectClaimsDTO, OpenID4VCICredentialDefinitionRequestDTO,
    OpenID4VCICredentialRequestDTO, OpenID4VCIIssuerMetadataResponseDTO, OpenID4VCIProofRequestDTO,
    OpenID4VCITokenRequestDTO, Timestamp,
};
use one_core::service::error::ServiceError;
use one_core::service::oid4vci_draft13_swiyu::dto::OpenID4VCISwiyuCredentialResponseDTO;
use one_dto_mapper::convert_inner_of_inner;
use serde_json::json;

use super::dto::{
    ExtendedSubjectClaimsRestDTO, OpenID4VCICredentialDefinitionRequestRestDTO,
    OpenID4VCICredentialRequestNewRestDTO, OpenID4VCICredentialRequestRestDTO,
    OpenID4VCIErrorResponseRestDTO, OpenID4VCIIssuerMetadataResponseRestDTO,
    OpenID4VCIProofRequestNewRestDTO, OpenID4VCISwiyuCredentialResponseRestDTO,
    OpenID4VCITokenRequestRestDTO, TimestampRest,
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

impl TryFrom<OpenID4VCICredentialDefinitionRequestRestDTO>
    for OpenID4VCICredentialDefinitionRequestDTO
{
    type Error = ServiceError;

    fn try_from(value: OpenID4VCICredentialDefinitionRequestRestDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            r#type: value
                .r#type
                .or(value.types)
                .ok_or(ServiceError::MappingError(
                    "Missing type / types".to_string(),
                ))?,
            credential_subject: value.credential_subject,
        })
    }
}

impl From<OpenID4VCICredentialDefinitionRequestDTO>
    for OpenID4VCICredentialDefinitionRequestRestDTO
{
    fn from(value: OpenID4VCICredentialDefinitionRequestDTO) -> Self {
        Self {
            r#type: Some(value.r#type.clone()),
            types: Some(value.r#type.clone()),
            credential_subject: value.credential_subject,
        }
    }
}

impl TryFrom<OpenID4VCIProofRequestNewRestDTO> for OpenID4VCIProofRequestDTO {
    type Error = ServiceError;
    fn try_from(value: OpenID4VCIProofRequestNewRestDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            proof_type: "jwt".to_string(),
            jwt: value
                .jwt
                .first()
                .cloned()
                .ok_or(ServiceError::MappingError("missing jwt".to_string()))?,
        })
    }
}

impl TryFrom<OpenID4VCICredentialRequestNewRestDTO> for OpenID4VCICredentialRequestDTO {
    type Error = ServiceError;
    fn try_from(value: OpenID4VCICredentialRequestNewRestDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            format: "vc+sd-jwt".to_string(),
            credential_definition: None,
            doctype: None,
            vct: value.credential_configuration_id,
            proof: value.proofs.try_into()?,
        })
    }
}

impl TryFrom<OpenID4VCICredentialRequestRestDTO> for OpenID4VCICredentialRequestDTO {
    type Error = ServiceError;
    fn try_from(value: OpenID4VCICredentialRequestRestDTO) -> Result<Self, Self::Error> {
        Ok(match value {
            OpenID4VCICredentialRequestRestDTO::New(dto) => dto.try_into()?,
            OpenID4VCICredentialRequestRestDTO::Old(dto) => dto.as_ref().to_owned().try_into()?,
        })
    }
}

impl From<OpenID4VCISwiyuCredentialResponseDTO> for OpenID4VCISwiyuCredentialResponseRestDTO {
    fn from(value: OpenID4VCISwiyuCredentialResponseDTO) -> Self {
        Self {
            credentials: vec![json!({
                "credential": value.credential,
            })],
            credential: value.credential,
            format: value.format,
            redirect_uri: value.redirect_uri,
        }
    }
}
