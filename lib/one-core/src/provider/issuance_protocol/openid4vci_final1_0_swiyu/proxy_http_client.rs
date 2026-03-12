use std::sync::Arc;

use time::Duration;

use crate::proto::http_client::{Error, Headers, HttpClient, Method, RequestBuilder, Response};

const API_VERSION_OID4VCI_1_0: &str = "2";
const SWIYU_API_VERSION_HTTP_HEADER: &str = "SWIYU-API-Version";

#[derive(Clone)]
pub(super) struct ProxySwiyuHttpClient {
    pub client: Arc<dyn HttpClient>,
}

#[async_trait::async_trait]
impl HttpClient for ProxySwiyuHttpClient {
    fn get(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Arc::new(self.clone()), Method::Get, url)
    }

    fn post(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Arc::new(self.clone()), Method::Post, url)
    }

    fn put(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Arc::new(self.clone()), Method::Put, url)
    }

    fn patch(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Arc::new(self.clone()), Method::Patch, url)
    }

    async fn send(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
        headers: Option<Headers>,
        method: Method,
        timeout: Option<Duration>,
    ) -> Result<Response, Error> {
        let mut headers = headers.unwrap_or_default();
        // Enable HTTP version 2 (OpenID4VCI 1.0)
        headers.insert(
            SWIYU_API_VERSION_HTTP_HEADER.to_owned(),
            API_VERSION_OID4VCI_1_0.to_owned(),
        );
        self.client
            .send(url, body, Some(headers), method, timeout)
            .await
    }
}
