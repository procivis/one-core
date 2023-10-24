use crate::model::credential_schema::CredentialSchema;
use crate::service::error::ServiceError;
use crate::service::oidc::dto::{
    OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO,
    OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO, OpenID4VCIIssuerMetadataResponseDTO,
};

pub(super) fn create_issuer_metadata_response(
    base_url: &str,
    schema: &CredentialSchema,
) -> Result<OpenID4VCIIssuerMetadataResponseDTO, ServiceError> {
    let credential_url = format!("{}/ssi/oidc-issuer/v1/{}", base_url, schema.id);
    Ok(OpenID4VCIIssuerMetadataResponseDTO {
        credential_issuer: credential_url.to_string(),
        credential_endpoint: format!("{}/credential", credential_url),
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
