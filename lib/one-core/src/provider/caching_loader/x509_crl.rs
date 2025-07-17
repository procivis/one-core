use std::sync::Arc;

use time::OffsetDateTime;

use super::{
    CacheError, CachingLoader, CachingLoaderError, ResolveResult, Resolver, ResolverError,
};
use crate::provider::http_client::HttpClient;
use crate::provider::remote_entity_storage::{RemoteEntityStorage, RemoteEntityType};

pub struct X509CrlCache {
    inner: CachingLoader,
    resolver: Arc<dyn Resolver<Error = ResolverError>>,
}

impl X509CrlCache {
    pub fn new(
        resolver: Arc<dyn Resolver<Error = ResolverError>>,
        storage: Arc<dyn RemoteEntityStorage>,
        cache_size: usize,
        cache_refresh_timeout: time::Duration,
        refresh_after: time::Duration,
    ) -> Self {
        Self {
            inner: CachingLoader::new(
                RemoteEntityType::X509Crl,
                storage,
                cache_size,
                cache_refresh_timeout,
                refresh_after,
            ),
            resolver,
        }
    }

    pub async fn get(&self, key: &str) -> Result<Vec<u8>, CacheError> {
        let (crl, _) = self.inner.get(key, self.resolver.clone(), false).await?;

        Ok(crl)
    }
}

pub struct X509CrlResolver {
    client: Arc<dyn HttpClient>,
}

impl X509CrlResolver {
    pub fn new(client: Arc<dyn HttpClient>) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl Resolver for X509CrlResolver {
    type Error = ResolverError;

    async fn do_resolve(
        &self,
        key: &str,
        _last_modified: Option<&OffsetDateTime>,
    ) -> Result<ResolveResult, Self::Error> {
        let content = self.client.get(key).send().await?.error_for_status()?.body;
        let (_, crl) = x509_parser::parse_x509_crl(&content)
            .map_err(|_| CachingLoaderError::UnexpectedResolveResult)?;
        let expiry_date = crl.next_update().map(|time| time.to_datetime());

        Ok(ResolveResult::NewValue {
            content,
            media_type: None,
            expiry_date,
        })
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use rcgen::{
        BasicConstraints, CertificateParams, CertificateRevocationList,
        CertificateRevocationListParams, IsCa, KeyPair,
    };
    use time::{Duration, OffsetDateTime};
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::provider::caching_loader::x509_crl::X509CrlResolver;
    use crate::provider::caching_loader::{ResolveResult, Resolver};
    use crate::provider::http_client::reqwest_client::ReqwestClient;

    #[tokio::test]
    async fn test_cached_crl_expiry() {
        let (next_update, signed_crl) = prepare_crl();
        let mock_server = MockServer::start().await;
        mock_server
            .register(
                Mock::given(method("GET")).respond_with(
                    ResponseTemplate::new(200)
                        .set_body_bytes(signed_crl.der().to_vec())
                        .clone(),
                ),
            )
            .await;

        let resolver = X509CrlResolver::new(Arc::new(ReqwestClient::default()));
        let result = resolver
            .do_resolve(&format!("http://{}", mock_server.address()), None)
            .await
            .unwrap();

        assert!(
            matches!(result, ResolveResult::NewValue { expiry_date: Some(expiry) ,.. } if expiry == next_update)
        );
    }

    fn prepare_crl() -> (OffsetDateTime, CertificateRevocationList) {
        let issuer_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let next_update = OffsetDateTime::now_utc()
            .checked_add(Duration::hours(24))
            .unwrap()
            .replace_millisecond(0)
            .unwrap();
        let crl_params = CertificateRevocationListParams {
            this_update: OffsetDateTime::now_utc()
                .checked_sub(Duration::hours(1))
                .unwrap(),
            next_update,
            crl_number: vec![0].into(),
            issuing_distribution_point: None,
            revoked_certs: vec![],
            key_identifier_method: ca_params.key_identifier_method.to_owned(),
        };
        let issuer = ca_params.self_signed(&issuer_key).unwrap();
        let signed_crl = crl_params.signed_by(&issuer, &issuer_key).unwrap();
        (next_update, signed_crl)
    }
}
