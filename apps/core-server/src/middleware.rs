use std::sync::Arc;
use std::time::Instant;

use axum::Extension;
use axum::body::{Body, Bytes};
use axum::extract::MatchedPath;
use axum::http::{HeaderMap, Request, Response, StatusCode};
use axum::middleware::Next;
use axum::response::IntoResponse;
use headers::HeaderValue;
use http_body_util::BodyExt;
use sentry::{Hub, SentryFutureExt};
use serde::Deserialize;
use shared_types::OrganisationId;
use tracing::trace;

use crate::ServerConfig;
use crate::authentication::Authentication;
use crate::permissions::Permission;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StsToken {
    #[allow(unused)]
    pub organisation_id: Option<OrganisationId>,
    #[serde(default)]
    pub permissions: Vec<Permission>,
}

#[derive(Debug, Clone)]
pub struct Authorized {
    pub permissions: Vec<Permission>,
}

pub struct HttpRequestContext<'a> {
    pub path: &'a str,
    pub method: &'a str,
    pub request_id: Option<&'a str>,
    pub session_id: Option<&'a str>,
}

// create new sentry hub per request
pub async fn sentry_layer(
    path: MatchedPath,
    request: Request<Body>,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    use sentry::protocol::*;

    async {
        let HttpRequestContext {
            method,
            request_id,
            session_id,
            ..
        } = get_http_request_context(&request);

        let method_path = format!("{} {}", method, path.as_str());

        sentry::configure_scope(|scope| {
            scope.set_tag("http-request", method_path.to_owned());

            if let Some(request_id) = request_id {
                scope.set_tag("ONE-request-id", request_id);
            }

            if let Some(session_id) = session_id {
                scope.set_tag("ONE-session-id", session_id);
            }
        });

        let response = next.run(request).await;

        let status = response.status();
        if status.is_server_error() {
            sentry::capture_event(Event {
                level: Level::Error,
                message: Some(format!("[{}] {method_path}", status.as_u16())),
                ..Default::default()
            });
        }

        Ok(response)
    }
    // make sure that the future is run in the new hub
    .bind_hub(Hub::new_from_top(Hub::main()))
    .await
}

pub async fn authorization_check(
    Extension(authentication): Extension<Authentication>,
    mut request: Request<Body>,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    match authentication {
        Authentication::None => {
            request.extensions_mut().insert(Authorized {
                permissions: vec![],
            });
        }
        Authentication::Static(static_token) => {
            let token = extract_auth_token(&request)?;
            if !token.is_empty() && token == static_token {
                request.extensions_mut().insert(Authorized {
                    permissions: vec![],
                });
            } else {
                tracing::warn!(
                    "Could not authorize request. Incorrect authorization method or token."
                );
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
        Authentication::SecurityTokenService(security_token_service) => {
            let token = extract_auth_token(&request)?;
            let decomposed_token = security_token_service
                .validate_sts_token::<StsToken>(token)
                .await
                .inspect_err(|e| {
                    tracing::warn!("Could not authorize request. Invalid token. Cause: {e}")
                })
                .map_err(|_| StatusCode::UNAUTHORIZED)?;
            request.extensions_mut().insert(Authorized {
                permissions: decomposed_token.payload.custom.permissions,
            });
        }
    }
    Ok(next.run(request).await)
}

fn extract_auth_token(request: &Request<Body>) -> Result<&str, StatusCode> {
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|header| header.to_str().ok());

    let auth_header = if let Some(auth_header) = auth_header {
        auth_header
    } else {
        tracing::warn!("Authorization header not found.");
        return Err(StatusCode::UNAUTHORIZED);
    };

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;
    Ok(token)
}

pub fn get_http_request_context<T>(request: &Request<T>) -> HttpRequestContext {
    let headers = request.headers();
    let request_id = headers
        .get("x-request-id")
        .and_then(|header| header.to_str().ok())
        .filter(|value| !value.is_empty());

    let session_id = headers
        .get("x-session-id")
        .and_then(|header| header.to_str().ok())
        .filter(|value| !value.is_empty());

    HttpRequestContext {
        path: request.uri().path(),
        method: request.method().as_str(),
        request_id,
        session_id,
    }
}

pub async fn metrics_counter(
    Extension(config): Extension<Arc<ServerConfig>>,
    path: MatchedPath,
    request: Request<Body>,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    let method = request.method().to_owned();
    let start_time = Instant::now();

    let resp = next.run(request).await;

    if config.enable_metrics {
        let duration = start_time.elapsed();
        let duration = duration.as_micros() as f64 / 1_000_000f64;

        crate::metrics::track_response_status_code(
            method.as_str(),
            path.as_str(),
            resp.status().as_str(),
            duration,
        );
    }

    Ok(resp)
}

pub async fn add_disable_cache_headers(
    request: Request<Body>,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert("Cache-Control", HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert("Pragma", HeaderValue::from_static("no-cache"));
    Ok(response)
}

pub async fn add_x_content_type_options_no_sniff_header(
    request: Request<Body>,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    Ok(response)
}

pub async fn log_request_and_response(
    request: Request<Body>,
    next: Next,
) -> Result<axum::response::Response, axum::response::Response> {
    const TRACING_LAYER_ERROR: &str = "!HTTP Tracing Layer Error!";

    let (parts, body) = request.into_parts();
    let bytes = body
        .collect()
        .await
        .map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("{TRACING_LAYER_ERROR}: {err}"),
            )
                .into_response()
        })?
        .to_bytes();
    let method = parts.method.clone();
    let request_uri = parts.uri.to_string();
    log_details(
        "request",
        method.as_str(),
        &request_uri,
        &bytes,
        &parts.headers,
    );

    let request = Request::from_parts(parts, Body::from(bytes));
    let response = next.run(request).await;

    let (parts, body) = response.into_parts();
    let bytes = body
        .collect()
        .await
        .map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("{TRACING_LAYER_ERROR}: {err}"),
            )
                .into_response()
        })?
        .to_bytes();
    log_details(
        "response",
        method.as_str(),
        &request_uri,
        &bytes,
        &parts.headers,
    );

    Ok(Response::from_parts(parts, Body::from(bytes)))
}

fn log_details(kind: &str, method: &str, url: &str, bytes: &Bytes, headers: &HeaderMap) {
    const NONE: &str = " None";

    let resp_body = if bytes.is_empty() {
        NONE.to_string()
    } else {
        format!(
            "\n{}",
            String::from_utf8(bytes.to_vec()).unwrap_or("Unable to parse UTF-8".to_string())
        )
    };

    let resp_headers = if headers.is_empty() {
        NONE.to_string()
    } else {
        format!(
            "\n{}\n",
            headers
                .iter()
                .map(|(k, v)| format!("{}: {}", k.as_str(), v.to_str().unwrap_or_default()))
                .collect::<Vec<_>>()
                .join("\n")
        )
    };

    trace!(
        "{}",
        format!("{kind} {method} {url}\nHeaders:{resp_headers}\nBody:{resp_body}",)
    );
}
