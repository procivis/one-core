use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use futures_util::StreamExt;
use reqwest::header::{CONTENT_LENGTH, HeaderMap, HeaderName, HeaderValue};
use reqwest::{ClientBuilder, Identity, redirect};
use time::{Duration, OffsetDateTime};
use url::{Host, Url};

use super::{
    Error, Headers, HttpClient, HttpClientSecurityConfig, Method, Request, RequestBuilder,
    Response, StatusCode,
};
use crate::validator::x509::is_dns_name_matching;

#[cfg(test)]
mod test;

#[derive(Clone)]
#[cfg_attr(any(test, feature = "mock"), derive(Default))]
pub struct ReqwestClient {
    client: reqwest::Client,
    denied_hosts: Option<Vec<String>>,
    max_response_size: Option<u64>,
    timeout: Option<Duration>,
    params: HttpClientSecurityConfig,
}

fn builder_from_params(params: &HttpClientSecurityConfig) -> Result<ClientBuilder, Error> {
    let mut client_builder = reqwest::Client::builder()
        .https_only(!params.insecure_http_transport_allowed)
        .redirect(redirect::Policy::limited(params.max_redirects));

    if let Some(timeout) = params.timeout_seconds {
        client_builder = client_builder.timeout(timeout.try_into()?);
    }
    Ok(client_builder)
}

impl ReqwestClient {
    pub fn new(params: HttpClientSecurityConfig) -> Result<Self, Error> {
        let client_builder = builder_from_params(&params)?;

        Ok(Self {
            client: client_builder.build()?,
            denied_hosts: params.denied_hosts.clone(),
            max_response_size: params.max_response_size,
            timeout: params.timeout_seconds,
            params,
        })
    }
}

#[async_trait::async_trait]
impl HttpClient for ReqwestClient {
    fn with_identity(&self, identity: Identity) -> Result<Arc<dyn HttpClient>, Error> {
        let mut client_builder = builder_from_params(&self.params)?;
        client_builder = client_builder.identity(identity);
        Ok(Arc::new(Self {
            client: client_builder.build()?,
            denied_hosts: self.denied_hosts.clone(),
            max_response_size: self.max_response_size,
            timeout: self.timeout,
            params: self.params.clone(),
        }))
    }

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
        timeout: Option<Duration>,
    ) -> Result<Response, Error> {
        if let Some(denied_hosts) = &self.denied_hosts {
            let url = url.parse::<Url>()?;
            let Some(host) = url.host() else {
                return Err(Error::InvalidHost("URL host not detected".to_string()));
            };

            if denied_hosts.iter().any(|definition| match host {
                Host::Domain(domain) => is_dns_name_matching(definition, domain),
                Host::Ipv4(ipv4_addr) => definition == &ipv4_addr.to_string(),
                Host::Ipv6(ipv6_addr) => definition == &ipv6_addr.to_string(),
            }) {
                return Err(Error::InvalidHost(format!("URL host `{host}` not allowed")));
            }
        }

        let request = Request {
            body: body.clone(),
            headers: headers.clone().unwrap_or_default(),
            method,
            url: url.to_string(),
            timeout,
        };

        let mut builder = match method {
            Method::Get => self.client.get(url),
            Method::Post => self.client.post(url),
            Method::Put => self.client.put(url),
            Method::Patch => self.client.patch(url),
        };

        let mut header_map = to_header_map(headers.unwrap_or_default())?;
        // hyper sends no `Content-Length` for a request without body, some servers then wait
        // for content until they time out. Set it for methods that define request content.
        // Spec: <https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6-5>
        if body.is_none() && !matches!(method, Method::Get) {
            header_map
                .entry(CONTENT_LENGTH)
                .or_insert(HeaderValue::from_static("0"));
        }
        builder = builder.headers(header_map);
        if let Some(body) = body {
            builder = builder.body(body);
        }
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout.try_into()?);
        }

        let finish_before = self
            .timeout
            .map(|timeout| crate::clock::now_utc() + timeout);

        let response = builder.send().await?;

        let headers = response
            .headers()
            .iter()
            .map(|(k, v)| {
                let value = v.to_str()?;
                Ok((k.to_string(), value.to_string()))
            })
            .collect::<Result<Headers, Error>>()?;
        let status_code = response.status().as_u16();

        let body = if let Some(max_response_size) = self.max_response_size {
            read_body_with_size_limit(response, max_response_size, finish_before).await?
        } else {
            response.bytes().await?.to_vec()
        };

        Ok(Response {
            body,
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
            let name = HeaderName::from_str(k.as_str())?;
            let value = HeaderValue::from_str(v.as_str())?;

            Ok((name, value))
        })
        .collect::<Result<HeaderMap, Error>>()
}

async fn read_body_with_size_limit(
    response: reqwest::Response,
    max_response_size: u64,
    finish_before: Option<OffsetDateTime>,
) -> Result<Vec<u8>, Error> {
    let content_length = response.content_length().or_else(|| {
        response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
    });

    if let Some(content_length) = content_length
        && content_length > max_response_size
    {
        return Err(Error::ResponseTooLong(content_length));
    }

    let mut stream = response.bytes_stream();
    let mut read_chunk = async move || {
        if let Some(finish_before) = finish_before {
            let duration = (finish_before - crate::clock::now_utc())
                .try_into()
                .map_err(|_| Error::Timeout)?;

            tokio::time::timeout(duration, stream.next())
                .await
                .map_err(|_| Error::Timeout)
        } else {
            Ok(stream.next().await)
        }
    };

    let mut body_buffer = Vec::with_capacity(content_length.unwrap_or(0) as _);
    while let Some(bytes) = read_chunk().await? {
        body_buffer.extend(bytes?);

        let downloaded_size = body_buffer.len() as _;
        if downloaded_size > max_response_size {
            return Err(Error::ResponseTooLong(downloaded_size));
        }
    }

    Ok(body_buffer)
}
