use super::dto::ConnectVerifierResponseRestDTO;
use crate::endpoint::ssi::dto::OpenID4VCIIssuerMetadataResponseRestDTO;
use one_core::{
    common_mapper::vector_into,
    service::{
        oidc::dto::OpenID4VCIIssuerMetadataResponseDTO,
        ssi_verifier::dto::ConnectVerifierResponseDTO,
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
