#[derive(Clone, Debug)]
pub struct OpenID4VCIIssuerMetadataResponseDTO {
    pub credential_issuer: String,
    pub credential_endpoint: String,
    pub credentials_supported: Vec<OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO>,
}
#[derive(Clone, Debug)]
pub struct OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO {
    pub format: String,
    pub credential_definition: OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO,
}

#[derive(Clone, Debug)]
pub struct OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO {
    pub r#type: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct OpenID4VCIDiscoveryResponseDTO {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
}
