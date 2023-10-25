use super::dto::{
    ConnectIssuerResponseRestDTO, ConnectVerifierResponseRestDTO,
    OpenID4VCIDiscoveryResponseRestDTO, ProofRequestClaimRestDTO,
};
use crate::endpoint::ssi::dto::{
    OpenID4VCIIssuerMetadataCredentialDefinitionResponseRestDTO,
    OpenID4VCIIssuerMetadataCredentialSupportedResponseRestDTO,
    OpenID4VCIIssuerMetadataResponseRestDTO,
};
use one_core::service::oidc::dto::{
    OpenID4VCIDiscoveryResponseDTO, OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO,
    OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO, OpenID4VCIIssuerMetadataResponseDTO,
};
use one_core::{
    common_mapper::vector_into,
    service::{
        ssi_issuer::dto::IssuerResponseDTO,
        ssi_verifier::dto::{ConnectVerifierResponseDTO, ProofRequestClaimDTO},
    },
};

impl From<ConnectVerifierResponseDTO> for ConnectVerifierResponseRestDTO {
    fn from(value: ConnectVerifierResponseDTO) -> Self {
        Self {
            claims: vector_into(value.claims),
            verifier_did: value.verifier_did,
        }
    }
}

impl From<OpenID4VCIIssuerMetadataResponseDTO> for OpenID4VCIIssuerMetadataResponseRestDTO {
    fn from(value: OpenID4VCIIssuerMetadataResponseDTO) -> Self {
        Self {
            credential_issuer: value.credential_issuer,
            credential_endpoint: value.credential_endpoint,
            credentials_supported: vector_into(value.credentials_supported),
        }
    }
}

impl From<OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO>
    for OpenID4VCIIssuerMetadataCredentialSupportedResponseRestDTO
{
    fn from(value: OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO) -> Self {
        Self {
            format: value.format,
            credential_definition: value.credential_definition.into(),
        }
    }
}

impl From<OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO>
    for OpenID4VCIIssuerMetadataCredentialDefinitionResponseRestDTO
{
    fn from(value: OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO) -> Self {
        Self {
            r#type: value.r#type,
        }
    }
}

impl From<OpenID4VCIDiscoveryResponseDTO> for OpenID4VCIDiscoveryResponseRestDTO {
    fn from(value: OpenID4VCIDiscoveryResponseDTO) -> Self {
        Self {
            issuer: value.issuer,
            authorization_endpoint: value.authorization_endpoint,
            token_endpoint: value.token_endpoint,
            jwks_uri: value.jwks_uri,
            response_types_supported: value.response_types_supported,
            grant_types_supported: value.grant_types_supported,
            subject_types_supported: value.subject_types_supported,
            id_token_signing_alg_values_supported: value.id_token_signing_alg_values_supported,
        }
    }
}

impl From<ProofRequestClaimDTO> for ProofRequestClaimRestDTO {
    fn from(value: ProofRequestClaimDTO) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            key: value.key,
            datatype: value.datatype,
            required: value.required,
            credential_schema: value.credential_schema.into(),
        }
    }
}

impl From<IssuerResponseDTO> for ConnectIssuerResponseRestDTO {
    fn from(value: IssuerResponseDTO) -> Self {
        Self {
            credential: value.credential,
            format: value.format,
        }
    }
}
