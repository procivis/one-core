#[derive(Clone, Debug)]
pub struct OpenID4VCISwiyuCredentialResponseDTO {
    pub credential: String,
    pub format: String,
    pub redirect_uri: Option<String>,
}
