//! Implementation of SD-JWT VC issuer metadata.

use std::sync::Arc;

use async_trait::async_trait;
use shared_types::{DidId, DidValue};
use url::Url;

use crate::model::key::Key;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::jwk::jwk_helpers::{encode_to_did, generate_document};
use crate::provider::did_method::keys::Keys;
use crate::provider::did_method::model::{AmountOfKeys, DidCapabilities, DidDocument, Operation};
use crate::provider::did_method::sd_jwt_vc_issuer_metadata::dto::{
    SdJwtVcIssuerMetadataDTO, SdJwtVcIssuerMetadataJwkDTO, SdJwtVcIssuerMetadataJwkKeyDTO,
};
use crate::provider::did_method::DidMethod;
use crate::provider::http_client::HttpClient;

mod dto;

#[derive(Debug, Clone, Default)]
pub struct Params {
    pub resolve_to_insecure_http: Option<bool>,
}

pub struct SdJwtVcIssuerMetadataDidMethod {
    http_client: Arc<dyn HttpClient>,
    pub params: Params,
}

impl SdJwtVcIssuerMetadataDidMethod {
    pub fn new(http_client: Arc<dyn HttpClient>, params: Params) -> Self {
        Self {
            http_client,
            params,
        }
    }
}

#[async_trait]
impl DidMethod for SdJwtVcIssuerMetadataDidMethod {
    async fn create(
        &self,
        _id: Option<DidId>,
        _params: &Option<serde_json::Value>,
        _keys: Option<Vec<Key>>,
    ) -> Result<DidValue, DidMethodError> {
        Err(DidMethodError::NotSupported)
    }

    async fn resolve(&self, did_value: &DidValue) -> Result<DidDocument, DidMethodError> {
        let url_decoded = if let Some(url_encoded) = did_value
            .as_str()
            .strip_prefix("did:sd_jwt_vc_issuer_metadata:")
        {
            urlencoding::decode(url_encoded)
                .map_err(|e| DidMethodError::ResolutionError(e.to_string()))?
        } else {
            return Err(DidMethodError::ResolutionError(format!(
                "invalid did method: {did_value}"
            )));
        };

        let mut url =
            Url::parse(&url_decoded).map_err(|e| DidMethodError::ResolutionError(e.to_string()))?;

        if !self.params.resolve_to_insecure_http.unwrap_or_default() && url.scheme() != "https" {
            return Err(DidMethodError::ResolutionError(
                "URL must use HTTPS scheme".to_string(),
            ));
        }

        const PATH_PREFIX: &str = "/.well-known/jwt-vc-issuer";

        let old_path = if url.path() == "/" { "" } else { url.path() };

        let new_path = format!("{PATH_PREFIX}{old_path}");
        url.set_path(&new_path);

        let response: SdJwtVcIssuerMetadataDTO = self
            .http_client
            .get(url.as_str())
            .send()
            .await
            .map_err(|e| DidMethodError::ResolutionError(e.to_string()))?
            .error_for_status()
            .map_err(|e| DidMethodError::ResolutionError(e.to_string()))?
            .json()
            .map_err(|e| DidMethodError::ResolutionError(e.to_string()))?;

        if response.issuer != url_decoded {
            return Err(DidMethodError::ResolutionError(
                "Issuer and did issuer mismatch".to_string(),
            ));
        }

        let key = self.get_first_jwk_from_dto(&response).await?;
        let did_jwk = encode_to_did(&key.jwk)?;
        Ok(generate_document(&did_jwk, key.jwk))
    }

    fn update(&self) -> Result<(), DidMethodError> {
        Err(DidMethodError::NotSupported)
    }

    fn can_be_deactivated(&self) -> bool {
        false
    }

    fn get_capabilities(&self) -> DidCapabilities {
        DidCapabilities {
            operations: vec![Operation::RESOLVE],
            key_algorithms: vec!["ES256".to_string(), "EDDSA".to_string()],
        }
    }

    fn validate_keys(&self, keys: AmountOfKeys) -> bool {
        Keys::default().validate_keys(keys)
    }

    fn get_keys(&self) -> Option<Keys> {
        Some(Keys::default())
    }
}

impl SdJwtVcIssuerMetadataDidMethod {
    async fn get_first_jwk_from_dto(
        &self,
        dto: &SdJwtVcIssuerMetadataDTO,
    ) -> Result<SdJwtVcIssuerMetadataJwkKeyDTO, DidMethodError> {
        if let Some(jwks) = &dto.jwks {
            jwks.keys
                .first()
                .ok_or(DidMethodError::ResolutionError(
                    "`jwks` are empty".to_string(),
                ))
                .cloned()
        } else if let Some(jwks_uri) = &dto.jwks_uri {
            self.http_client
                .get(jwks_uri.as_str())
                .send()
                .await
                .map_err(|e| DidMethodError::ResolutionError(e.to_string()))?
                .error_for_status()
                .map_err(|e| DidMethodError::ResolutionError(e.to_string()))?
                .json::<SdJwtVcIssuerMetadataJwkDTO>()
                .map_err(|e| DidMethodError::ResolutionError(e.to_string()))?
                .keys
                .first()
                .ok_or(DidMethodError::ResolutionError(
                    "`jwks` are empty".to_string(),
                ))
                .cloned()
        } else {
            Err(DidMethodError::ResolutionError(
                "Missing `jwks` or `jwks_uri`".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod test;
