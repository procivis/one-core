//! Implementation of SD-JWT VC issuer metadata.

use std::sync::Arc;

use async_trait::async_trait;
use dto::generate_document;
use futures::TryFutureExt;
use shared_types::{DidId, DidValue};
use url::Url;

use crate::model::key::Key;
use crate::provider::did_method::error::DidMethodError;
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

        let issuer_url =
            Url::parse(&url_decoded).map_err(|e| DidMethodError::ResolutionError(e.to_string()))?;

        if !self.params.resolve_to_insecure_http.unwrap_or_default()
            && issuer_url.scheme() != "https"
        {
            return Err(DidMethodError::ResolutionError(
                "URL must use HTTPS scheme".to_string(),
            ));
        }

        let issuer_url_path = if issuer_url.path() == "/" {
            "".to_string()
        } else {
            issuer_url.path().to_owned()
        };

        const JWKS_URI_SUFFIX: &str = "/.well-known/jwt-vc-issuer";
        const FALLBACK_URI_SUFFIX: &str = "/.well-known/openid-configuration";

        let (jwks_endpoint, fallback_jwks_endpoint) = {
            let mut jwks_endpoint = issuer_url.clone();
            jwks_endpoint.set_path(&format!("{JWKS_URI_SUFFIX}{issuer_url_path}"));

            // See ONE-4412
            // See https://github.com/eu-digital-identity-wallet/eudi-srv-web-issuing-eudiw-py/issues/78 (point 2)
            // Workaround for interoperability with the https://eudiw-issuer.eudi.dev deployment which does not support the jwks_uri
            let mut fallback_jwks_endpoint = issuer_url.clone();
            fallback_jwks_endpoint.set_path(&format!("{FALLBACK_URI_SUFFIX}{issuer_url_path}"));

            (jwks_endpoint, fallback_jwks_endpoint)
        };

        let response: SdJwtVcIssuerMetadataDTO = self
            .http_client
            .get(jwks_endpoint.as_str())
            .send()
            .and_then(|response| async { response.error_for_status() })
            .or_else(|_| self.http_client.get(fallback_jwks_endpoint.as_str()).send())
            .await
            .map_err(|e| DidMethodError::ResolutionError(e.to_string()))?
            .error_for_status()
            .map_err(|e| DidMethodError::ResolutionError(e.to_string()))?
            .json()
            .map_err(|e| DidMethodError::ResolutionError(e.to_string()))?;

        let response_issuer = Url::parse(&response.issuer)
            .map_err(|e| DidMethodError::ResolutionError(e.to_string()))?;

        if response_issuer != issuer_url {
            return Err(DidMethodError::ResolutionError(
                "Issuer and did issuer mismatch".to_string(),
            ));
        }

        let keys = self
            .get_jwks_list(&response)
            .await?
            .into_iter()
            .map(|key| key.jwk)
            .collect();

        Ok(generate_document(did_value, keys))
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
    async fn get_jwks_list(
        &self,
        dto: &SdJwtVcIssuerMetadataDTO,
    ) -> Result<Vec<SdJwtVcIssuerMetadataJwkKeyDTO>, DidMethodError> {
        if let Some(jwks) = &dto.jwks {
            Ok(jwks.keys.clone())
        } else if let Some(jwks_uri) = &dto.jwks_uri {
            Ok(self
                .http_client
                .get(jwks_uri.as_str())
                .send()
                .await
                .map_err(|e| DidMethodError::ResolutionError(e.to_string()))?
                .error_for_status()
                .map_err(|e| DidMethodError::ResolutionError(e.to_string()))?
                .json::<SdJwtVcIssuerMetadataJwkDTO>()
                .map_err(|e| DidMethodError::ResolutionError(e.to_string()))?
                .keys)
        } else {
            Err(DidMethodError::ResolutionError(
                "Missing `jwks` or `jwks_uri`".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod test;
