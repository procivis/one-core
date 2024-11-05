pub mod reqwest_client;

use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait HttpClient: Send + Sync {
    fn get(&self, url: &str) -> RequestBuilder;
    fn post(&self, url: &str) -> RequestBuilder;

    async fn send(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
        headers: Option<Headers>,
        method: Method,
    ) -> Result<Response, Error>;
}

pub type Headers = HashMap<String, String>;

#[derive(Debug)]
pub struct StatusCode(pub u16);

#[derive(Debug)]
pub struct Response {
    pub body: Vec<u8>,
    pub headers: Headers,
    pub status: StatusCode,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("HTTP error: {0}")]
    HttpError(String),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Other HTTP client error: {0}")]
    Other(String),
    #[error("HTTP status code is error: {0}")]
    StatusCodeIsError(StatusCode),
    #[error("Url encoding error: {0}")]
    UrlEncode(#[from] serde_urlencoded::ser::Error),
}

impl Response {
    pub fn error_for_status(self) -> Result<Self, Error> {
        if self.status.is_client_error() || self.status.is_server_error() {
            Err(Error::StatusCodeIsError(self.status))
        } else {
            Ok(self)
        }
    }

    pub fn header_get(&self, key: &str) -> Option<&String> {
        self.headers
            .iter()
            .find(|(header_key, _)| header_key.eq_ignore_ascii_case(key))
            .map(|(_, value)| value)
    }

    pub fn json<T: DeserializeOwned>(self) -> Result<T, Error> {
        serde_json::from_slice(&self.body).map_err(Error::JsonError)
    }
}

impl StatusCode {
    pub fn is_success(&self) -> bool {
        self.0 >= 200 && self.0 < 300
    }

    pub fn is_redirection(&self) -> bool {
        self.0 >= 300 && self.0 < 400
    }

    pub fn is_client_error(&self) -> bool {
        self.0 >= 400 && self.0 < 500
    }

    pub fn is_server_error(&self) -> bool {
        self.0 >= 500 && self.0 < 600
    }
}

impl Display for StatusCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Method {
    Get,
    Post,
}

pub struct RequestBuilder {
    client: Arc<dyn HttpClient>,
    body: Option<Vec<u8>>,
    headers: Headers,
    method: Method,
    url: String,
}

impl RequestBuilder {
    pub fn new(client: Arc<dyn HttpClient>, method: Method, url: &str) -> Self {
        Self {
            client,
            body: None,
            headers: Headers::default(),
            method,
            url: url.to_string(),
        }
    }

    pub fn header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }

    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    pub fn bearer_auth(mut self, token: &str) -> Self {
        self.headers
            .insert("Authorization".to_string(), format!("Bearer {token}"));
        self
    }

    pub fn form<T: Serialize>(mut self, value: T) -> Result<Self, Error> {
        self.headers.insert(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_owned(),
        );
        self.body = Some(
            serde_urlencoded::to_string(value)
                .map_err(|e| Error::Other(e.to_string()))?
                .into_bytes(),
        );
        Ok(self)
    }

    pub fn json<T: Serialize>(mut self, value: T) -> Result<Self, Error> {
        self.headers
            .insert("Content-Type".to_string(), "application/json".to_owned());
        self.body = Some(serde_json::to_vec(&value).map_err(Error::JsonError)?);
        Ok(self)
    }

    pub async fn send(self) -> Result<Response, Error> {
        let headers = if self.headers.is_empty() {
            None
        } else {
            Some(self.headers)
        };

        self.client
            .send(&self.url, self.body, headers, self.method)
            .await
    }
}
