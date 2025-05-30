use serde::Deserialize;
use url::Url;

use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::http_client::HttpClient;
use crate::service::key::dto::PublicKeyJwkDTO;

pub async fn resolve_jwks_url(
    issuer_url: Url,
    http_client: &dyn HttpClient,
) -> Result<Vec<PublicKeyJwkDTO>, FormatterError> {
    let issuer_url_path = issuer_url.path().trim_end_matches('/').to_string();

    const PATH_PREFIX: &str = "/.well-known/jwt-vc-issuer";

    let jwks_endpoint = {
        let mut cloned = issuer_url.clone();
        cloned.set_path(&format!("{PATH_PREFIX}{issuer_url_path}"));
        cloned
    };

    let response: SdJwtVcIssuerMetadataDTO = http_client
        .get(jwks_endpoint.as_str())
        .send()
        .await
        .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?
        .error_for_status()
        .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?
        .json()
        .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;

    let response_issuer = Url::parse(&response.issuer)
        .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;

    if response_issuer != issuer_url {
        return Err(FormatterError::CouldNotExtractCredentials(
            "Response issuer and url issuer mismatch".to_string(),
        ));
    }

    let keys = get_jwks_list(&response, http_client)
        .await?
        .into_iter()
        .map(|key| key.jwk)
        .collect();

    Ok(keys)
}

async fn get_jwks_list(
    dto: &SdJwtVcIssuerMetadataDTO,
    http_client: &dyn HttpClient,
) -> Result<Vec<SdJwtVcIssuerMetadataJwkKeyDTO>, FormatterError> {
    if let Some(jwks) = &dto.jwks {
        Ok(jwks.keys.clone())
    } else if let Some(jwks_uri) = &dto.jwks_uri {
        Ok(http_client
            .get(jwks_uri.as_str())
            .send()
            .await
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?
            .error_for_status()
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?
            .json::<SdJwtVcIssuerMetadataJwkDTO>()
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?
            .keys)
    } else {
        Err(FormatterError::CouldNotExtractCredentials(
            "Missing `jwks` or `jwks_uri`".to_string(),
        ))
    }
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct SdJwtVcIssuerMetadataDTO {
    pub issuer: String,
    #[serde(default)]
    pub jwks: Option<SdJwtVcIssuerMetadataJwkDTO>,
    #[serde(default)]
    pub jwks_uri: Option<Url>,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct SdJwtVcIssuerMetadataJwkDTO {
    pub keys: Vec<SdJwtVcIssuerMetadataJwkKeyDTO>,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct SdJwtVcIssuerMetadataJwkKeyDTO {
    // TODO: this could be used for matching SD-JWT header with key
    // #[serde(rename = "kid")]
    // pub key_id: String,
    #[serde(flatten)]
    pub jwk: PublicKeyJwkDTO,
}
