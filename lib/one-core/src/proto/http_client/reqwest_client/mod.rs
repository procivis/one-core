use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use super::{Error, Headers, HttpClient, Method, Request, RequestBuilder, Response, StatusCode};
#[derive(Clone)]
pub struct ReqwestClient {
    pub client: reqwest::Client,
}

impl ReqwestClient {
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

impl Default for ReqwestClient {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

#[async_trait::async_trait]
impl HttpClient for ReqwestClient {
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

    #[track_caller]
    async fn send(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
        headers: Option<Headers>,
        method: Method,
    ) -> Result<Response, Error> {
        let request = Request {
            body: body.clone(),
            headers: headers.clone().unwrap_or_default(),
            method,
            url: url.to_string(),
        };

        let mut builder = match method {
            Method::Get => self.client.get(url),
            Method::Post => self.client.post(url),
            Method::Put => self.client.put(url),
            Method::Patch => self.client.patch(url),
        };

        if let Some(headers) = headers {
            builder = builder.headers(to_header_map(headers)?);
        }
        if let Some(body) = body {
            builder = builder.body(body);
        }

        let response = builder
            .send()
            .await
            .map_err(|e| Error::HttpError(e.to_string()))?;

        let headers = response
            .headers()
            .iter()
            .map(|(k, v)| {
                let value = v.to_str().map_err(|e| Error::Other(e.to_string()))?;

                Ok((k.to_string(), value.to_string()))
            })
            .collect::<Result<Headers, Error>>()?;
        let status_code = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .map_err(|e| Error::HttpError(e.to_string()))?;

        Ok(Response {
            body: body.to_vec(),
            headers,
            status: StatusCode(status_code),
            request,
        })
    }
}

fn to_header_map(headers: HashMap<String, String>) -> Result<HeaderMap, Error> {
    headers
        .into_iter()
        .map(|(k, v)| {
            let name = HeaderName::from_str(k.as_str()).map_err(|e| Error::Other(e.to_string()))?;
            let value =
                HeaderValue::from_str(v.as_str()).map_err(|e| Error::Other(e.to_string()))?;

            Ok((name, value))
        })
        .collect::<Result<HeaderMap, Error>>()
}
