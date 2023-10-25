use crate::model::credential_schema::CredentialSchema;
use crate::service::error::ServiceError;
use crate::service::oidc::dto::{
    OpenID4VCIDiscoveryResponseDTO, OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO,
    OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO, OpenID4VCIIssuerMetadataResponseDTO,
};

pub(super) fn create_issuer_metadata_response(
    base_url: String,
    schema: CredentialSchema,
) -> Result<OpenID4VCIIssuerMetadataResponseDTO, ServiceError> {
    Ok(OpenID4VCIIssuerMetadataResponseDTO {
        credential_issuer: base_url.to_owned(),
        credential_endpoint: format!("{base_url}/credential"),
        credentials_supported: vec![OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO {
            format: map_format_to_oidc_format(&schema.format)?,
            credential_definition: OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO {
                r#type: vec!["VerifiableCredential".to_string()],
            },
        }],
    })
}

fn map_format_to_oidc_format(format: &str) -> Result<String, ServiceError> {
    match format {
        "JWT" => Ok("jwt_vc_json".to_string()),
        "SDJWT" => Ok("vc+sd-jwt".to_string()),
        _ => Err(ServiceError::MappingError(
            "Credential format invalid!".to_string(),
        )),
    }
}

pub(super) fn create_service_discovery_response(
    base_url: String,
) -> Result<OpenID4VCIDiscoveryResponseDTO, ServiceError> {
    Ok(OpenID4VCIDiscoveryResponseDTO {
        issuer: base_url.to_owned(),
        authorization_endpoint: format!("{base_url}/authorize"),
        token_endpoint: format!("{base_url}/token"),
        jwks_uri: format!("{base_url}/jwks"),
        response_types_supported: vec!["token".to_string()],
        grant_types_supported: vec![
            "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string()
        ],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec![],
    })
}
