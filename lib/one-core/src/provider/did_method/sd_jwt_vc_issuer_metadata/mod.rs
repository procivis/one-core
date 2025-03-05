//! Implementation of SD-JWT VC issuer metadata.
//! https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-05.html#section-3.5

use std::sync::Arc;

use async_trait::async_trait;
use dto::generate_document;
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
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::service::key::dto::PublicKeyJwkDTO;
use crate::util::x509::{
    extract_jwk_from_der, extract_leaf_certificate_from_verified_chain, Certificate,
};

mod dto;

#[derive(Debug, Clone, Default)]
pub struct Params {
    pub resolve_to_insecure_http: Option<bool>,
    pub iaca_certificate: Option<String>,
}
pub struct SdJwtVcIssuerMetadataDidMethod {
    http_client: Arc<dyn HttpClient>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    params: Params,
}

impl SdJwtVcIssuerMetadataDidMethod {
    pub fn new(
        http_client: Arc<dyn HttpClient>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        params: Params,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            http_client,
            key_algorithm_provider,
            params,
        })
    }
}

impl SdJwtVcIssuerMetadataDidMethod {
    pub async fn resolve_jwks_url(
        &self,
        issuer_url: Url,
    ) -> Result<Vec<PublicKeyJwkDTO>, DidMethodError> {
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

        const PATH_PREFIX: &str = "/.well-known/jwt-vc-issuer";

        let jwks_endpoint = {
            let mut cloned = issuer_url.clone();
            cloned.set_path(&format!("{PATH_PREFIX}{issuer_url_path}"));
            cloned
        };

        let response: SdJwtVcIssuerMetadataDTO = self
            .http_client
            .get(jwks_endpoint.as_str())
            .send()
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

        Ok(keys)
    }

    pub async fn resolve_keys_from_x5c(
        &self,
        issuer_url: Url,
        x5c: &[String],
    ) -> Result<Vec<PublicKeyJwkDTO>, DidMethodError> {
        if x5c.is_empty() {
            return Err(DidMethodError::ResolutionError("x5c empty".to_string()));
        }

        let issuer_id = issuer_url.domain().ok_or(DidMethodError::ResolutionError(
            "invalid issuer url".to_string(),
        ))?;

        let root_certificate = self
            .params
            .iaca_certificate
            .as_ref()
            .map(|c| Certificate::from_base64_url_safe_no_padding(c))
            .transpose()
            .map_err(|_| {
                DidMethodError::ResolutionError("Failed to decode root certificate".to_string())
            })?;

        let leaf_certificate =
            extract_leaf_certificate_from_verified_chain(x5c, issuer_id, root_certificate.as_ref())
                .map_err(|e| DidMethodError::ResolutionError(e.to_string()))?;

        let encoded = leaf_certificate
            .as_base64_url_safe_no_padding()
            .map_err(|e| {
                DidMethodError::ResolutionError(format!("Failed to encode leaf certificate: {}", e))
            })?;

        let key =
            extract_jwk_from_der(&encoded, self.key_algorithm_provider.clone()).map_err(|e| {
                DidMethodError::ResolutionError(format!(
                    "Failed to extract jwk from leaf certificate: {}",
                    e
                ))
            })?;

        Ok(vec![key.into()])
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
        let issuer_url = {
            let without_did_prefix = did_value
                .as_str()
                .strip_prefix("did:sd_jwt_vc_issuer_metadata:")
                .ok_or(DidMethodError::ResolutionError(format!(
                    "missing did prefix for did: {}",
                    did_value
                )))?;

            let url_decoded = urlencoding::decode(without_did_prefix)
                .map_err(|e| DidMethodError::ResolutionError(e.to_string()))?;

            Url::parse(url_decoded.as_ref())
                .map_err(|e| DidMethodError::ResolutionError(e.to_string()))?
        };

        let x5c_params: Vec<String> = issuer_url
            .query_pairs()
            .filter_map(|(k, v)| {
                if k == "x5c" {
                    Some(v.to_string())
                } else {
                    None
                }
            })
            .collect();

        let keys = if x5c_params.is_empty() {
            self.resolve_jwks_url(issuer_url).await?
        } else {
            if issuer_url.query_pairs().count() != x5c_params.len() {
                return Err(DidMethodError::ResolutionError(
                    "x5c query parameter mismatch".to_string(),
                ));
            }

            self.resolve_keys_from_x5c(issuer_url, &x5c_params).await?
        };

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
            method_names: vec!["sd_jwt_vc_issuer_metadata".to_string()],
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
