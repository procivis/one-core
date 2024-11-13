pub mod reqwest_client;

use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Arc;

use itertools::Itertools;
use serde::de::DeserializeOwned;
use serde::Serialize;
use strum_macros::Display;
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

#[derive(Copy, Clone, Debug)]
pub struct StatusCode(pub u16);

#[derive(Debug)]
pub struct Request {
    pub body: Option<Vec<u8>>,
    pub headers: Headers,
    pub method: Method,
    pub url: String,
}

#[derive(Debug)]
pub struct Response {
    pub body: Vec<u8>,
    pub headers: Headers,
    pub status: StatusCode,

    pub request: Request,
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

impl Error {
    pub fn log_error(self, location: &std::panic::Location, request: &Request) -> Self {
        let debug_message = format!("\n{} {} - {self}", request.method, request.url);
        tracing::error!(%debug_message, %location);

        self
    }
}

impl Response {
    #[track_caller]
    pub fn error_for_status(self) -> Result<Self, Error> {
        if self.status.is_client_error() || self.status.is_server_error() {
            let location = std::panic::Location::caller();
            Err(Error::StatusCodeIsError(self.status).log_error(location, &self.request))
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

    #[track_caller]
    pub fn json<T: DeserializeOwned>(self) -> Result<T, Error> {
        match serde_json::from_slice(&self.body) {
            Ok(value) => Ok(value),
            Err(error) => {
                let location = std::panic::Location::caller();
                Err(Error::JsonError(error).log_error(location, &self.request))
            }
        }
    }

    #[track_caller]
    fn log_success(self) -> Self {
        let debug_message = format!(
            "\n{} {} - HTTP",
            &self.request.method.to_string(),
            &self.request.url
        );

        let location = std::panic::Location::caller();
        tracing::debug!(%debug_message, %location);
        log_request_details(location, &self.request);

        let trace_response = format!(
            "\nResponse\nStatus: {}\nHeaders:\n{}\nBody:\n{}\n",
            self.status,
            format_headers(&self.headers),
            format_body(&Some(&self.body))
        );
        tracing::trace!(%trace_response, %location);

        self
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

#[derive(Copy, Clone, Debug, Eq, PartialEq, Display)]
pub enum Method {
    #[strum(serialize = "GET")]
    Get,
    #[strum(serialize = "POST")]
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

    #[track_caller]
    pub fn form<T: Serialize>(mut self, value: T) -> Result<Self, Error> {
        let location = std::panic::Location::caller();

        self.headers.insert(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_owned(),
        );

        self.body = Some(
            serde_urlencoded::to_string(value)
                .map_err(|e| Error::Other(e.to_string()).log_error(location, &self.as_request()))?
                .into_bytes(),
        );
        Ok(self)
    }

    #[track_caller]
    pub fn json<T: Serialize>(mut self, value: T) -> Result<Self, Error> {
        let location = std::panic::Location::caller();

        self.headers
            .insert("Content-Type".to_string(), "application/json".to_owned());
        self.body = Some(
            serde_json::to_vec(&value)
                .map_err(|e| Error::JsonError(e).log_error(location, &self.as_request()))?,
        );
        Ok(self)
    }

    // TODO: #[track_caller] (currently not supported in stable Rust
    pub async fn send(self) -> Result<Response, Error> {
        let location = std::panic::Location::caller();
        let as_request = self.as_request();

        let headers = if self.headers.is_empty() {
            None
        } else {
            Some(self.headers)
        };

        self.client
            .send(&self.url, self.body, headers, self.method)
            .await
            .map(|response| response.log_success())
            .map_err(|e| {
                let error = e.log_error(location, &as_request);
                log_request_details(location, &as_request);
                error
            })
    }

    fn as_request(&self) -> Request {
        Request {
            body: self.body.clone(),
            headers: self.headers.clone(),
            method: self.method,
            url: self.url.clone(),
        }
    }
}

fn format_headers(headers: &Headers) -> String {
    match headers.is_empty() {
        true => "<None>".to_string(),
        false => headers.iter().map(|(k, v)| format!("{k}: {v}")).join("\n"),
    }
}

fn format_body(body: &Option<&Vec<u8>>) -> String {
    match body {
        None => "<None>".to_string(),
        Some(value) => match String::from_utf8((*value).clone()) {
            Ok(string) => string,
            Err(_) => format!("{:?}", value),
        },
    }
}

fn log_request_details(location: &std::panic::Location, request: &Request) {
    let trace_request = format!(
        "\nRequest\nHeaders:\n{}\nBody:\n{}\n",
        format_headers(&request.headers),
        format_body(&request.body.as_ref())
    );

    tracing::trace!(%trace_request, %location);
}
