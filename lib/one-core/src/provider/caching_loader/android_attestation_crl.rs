use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use time::{Duration, OffsetDateTime};

use super::{CacheError, CachingLoader, ResolveResult, Resolver, ResolverError};
use crate::error::ContextWithErrorCode;
use crate::proto::http_client::HttpClient;
use crate::provider::remote_entity_storage::{RemoteEntityStorage, RemoteEntityType};

/// <https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status>
pub struct AndroidAttestationCrlCache {
    inner: CachingLoader,
    resolver: Arc<dyn Resolver<Error = ResolverError>>,
}

impl AndroidAttestationCrlCache {
    pub fn new(
        resolver: Arc<dyn Resolver<Error = ResolverError>>,
        storage: Arc<dyn RemoteEntityStorage>,
        cache_size: usize,
        cache_refresh_timeout: time::Duration,
        refresh_after: time::Duration,
    ) -> Self {
        Self {
            inner: CachingLoader::new(
                RemoteEntityType::AndroidAttestationCrl,
                storage,
                cache_size,
                cache_refresh_timeout,
                refresh_after,
            ),
            resolver,
        }
    }

    pub(crate) async fn get(&self) -> Result<AndroidKeyAttestationsCrl, CacheError> {
        let (crl, _) = self
            .inner
            .get(
                "https://android.googleapis.com/attestation/status",
                self.resolver.clone(),
                false,
            )
            .await
            .error_while("getting google android attestation certificate status")?;
        Ok(serde_json::from_slice(&crl)?)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CertificateStatus {
    Revoked,
    Suspended,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StatusReason {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    Superseded,
    SoftwareFlaw,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
pub struct AndroidCertificateInfo {
    pub status: CertificateStatus,
    pub reason: Option<StatusReason>,
    pub expires: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AndroidKeyAttestationsCrl {
    pub entries: HashMap<String, AndroidCertificateInfo>,
}

pub struct AndroidAttestationCrlResolver {
    client: Arc<dyn HttpClient>,
}

impl AndroidAttestationCrlResolver {
    pub fn new(client: Arc<dyn HttpClient>) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl Resolver for AndroidAttestationCrlResolver {
    type Error = ResolverError;

    async fn do_resolve(
        &self,
        key: &str,
        _last_modified: Option<&OffsetDateTime>,
    ) -> Result<ResolveResult, Self::Error> {
        let response = self
            .client
            .get(key)
            .send()
            .await
            .error_while("downloading Android attestation CRL")?
            .error_for_status()
            .error_while("downloading Android attestation CRL")?;

        let cache_control =
            response
                .header_get("Cache-Control")
                .ok_or(ResolverError::InvalidResponse(
                    "Missing Cache-Control response header".to_string(),
                ))?;

        let max_age = cache_control
            .split(", ")
            .find_map(|directive| directive.strip_prefix("max-age="))
            .and_then(|age| age.parse::<usize>().ok());

        let expiry_date =
            max_age.map(|age| OffsetDateTime::now_utc() + Duration::seconds(age as _));

        Ok(ResolveResult::NewValue {
            content: response.body,
            media_type: Some("application/json".to_string()),
            expiry_date,
        })
    }
}

#[cfg(any(test, feature = "mock"))]
#[derive(Debug, Default)]
pub struct MockAndroidAttestationCrlResolver {
    pub crl: AndroidKeyAttestationsCrl,
}

#[cfg(any(test, feature = "mock"))]
#[async_trait::async_trait]
impl Resolver for MockAndroidAttestationCrlResolver {
    type Error = ResolverError;

    async fn do_resolve(
        &self,
        _key: &str,
        _last_modified: Option<&OffsetDateTime>,
    ) -> Result<ResolveResult, Self::Error> {
        Ok(ResolveResult::NewValue {
            content: serde_json::to_vec(&self.crl).map_err(Self::Error::InvalidResponseBody)?,
            media_type: Some("application/json".to_string()),
            expiry_date: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use similar_asserts::assert_eq;

    use super::AndroidAttestationCrlResolver;
    use crate::proto::http_client::reqwest_client::ReqwestClient;
    use crate::provider::caching_loader::android_attestation_crl::AndroidKeyAttestationsCrl;
    use crate::provider::caching_loader::{ResolveResult, Resolver};

    #[tokio::test]
    async fn test_android_crl_resolver_real_google_api() {
        let resolver = AndroidAttestationCrlResolver::new(Arc::new(ReqwestClient::default()));

        let result = resolver
            .do_resolve("https://android.googleapis.com/attestation/status", None)
            .await
            .unwrap();

        let ResolveResult::NewValue {
            content,
            media_type,
            ..
        } = result
        else {
            panic!("Invalid result type");
        };

        assert_eq!(media_type.unwrap(), "application/json");
        let _crl: AndroidKeyAttestationsCrl = serde_json::from_slice(&content).unwrap();
    }
}
