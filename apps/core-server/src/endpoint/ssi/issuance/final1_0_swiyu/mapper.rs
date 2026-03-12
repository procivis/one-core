use indexmap::IndexMap;
use one_core::provider::issuance_protocol::openid4vci_final1_0::model::{
    OpenID4VCICredentialConfigurationData, OpenID4VCIIssuerMetadataResponseDTO,
};
use one_dto_mapper::{convert_inner, convert_inner_of_inner};

use crate::endpoint::ssi::issuance::final1_0_swiyu::dto::{
    OpenID4VCISwiyuIssuerMetadataCredentialSupportedResponseRestDTO,
    OpenID4VCISwiyuIssuerMetadataResponseRestDTO,
};

impl From<OpenID4VCIIssuerMetadataResponseDTO> for OpenID4VCISwiyuIssuerMetadataResponseRestDTO {
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

impl From<OpenID4VCICredentialConfigurationData>
    for OpenID4VCISwiyuIssuerMetadataCredentialSupportedResponseRestDTO
{
    fn from(value: OpenID4VCICredentialConfigurationData) -> Self {
        let mut credential_display = vec![];
        let mut swiyu_claims = IndexMap::new();
        if let Some(meta) = &value.credential_metadata {
            if let Some(claims) = &meta.claims {
                for claim in claims {
                    swiyu_claims.insert(claim.path.join("."), claim.clone().into());
                }
            }
            if let Some(displays) = &meta.display {
                credential_display = displays.clone();
            }
        }
        Self {
            format: value.format,
            doctype: value.doctype,
            vct: value.vct,
            credential_metadata: convert_inner(value.credential_metadata),
            claims: swiyu_claims,
            display: convert_inner(credential_display),
            scope: value.scope,
            cryptographic_binding_methods_supported: value.cryptographic_binding_methods_supported,
            credential_signing_alg_values_supported: convert_inner_of_inner(
                value.credential_signing_alg_values_supported,
            ),
            proof_types_supported: value.proof_types_supported,
            credential_definition: convert_inner(value.credential_definition),
        }
    }
}
