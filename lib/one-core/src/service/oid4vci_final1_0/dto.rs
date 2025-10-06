use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct OpenID4VCICredentialResponseDTO {
    #[serde(rename = "redirectUri")]
    pub redirect_uri: Option<String>,

    pub credentials: Option<Vec<OpenID4VCICredentialResponseEntryDTO>>,
    pub transaction_id: Option<String>,
    pub interval: Option<u64>,
    pub notification_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OpenID4VCICredentialResponseEntryDTO {
    pub credential: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OAuthAuthorizationServerMetadataResponseDTO {
    pub issuer: String,
    pub token_endpoint: String,
    pub response_types_supported: Option<Vec<String>>,
    pub grant_types_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
}
