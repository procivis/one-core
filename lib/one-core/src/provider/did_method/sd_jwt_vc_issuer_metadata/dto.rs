use serde::Deserialize;
use url::Url;

use crate::service::key::dto::PublicKeyJwkDTO;

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
