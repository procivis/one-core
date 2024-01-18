use std::sync::Arc;

use axum::{
    body::Body,
    extract::MatchedPath,
    http::{Request, StatusCode},
    middleware::Next,
    Extension,
};
use sentry::{Hub, SentryFutureExt};

use crate::ServerConfig;

#[derive(Debug, Clone)]
pub struct Authorized {}

pub struct HttpRequestContext<'a> {
    pub path: &'a str,
    pub method: &'a str,
    pub request_id: Option<&'a str>,
    pub session_id: Option<&'a str>,
}

// create new sentry hub per request
pub async fn new_sentry_hub(
    path: MatchedPath,
    request: Request<Body>,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    async {
        let HttpRequestContext {
            method,
            request_id,
            session_id,
            ..
        } = get_http_request_context(&request);

        let method_path = format!("{} {}", method, path.as_str());

        sentry::configure_scope(|scope| {
            scope.set_tag("http-request", method_path);

            if let Some(request_id) = request_id {
                scope.set_tag("ONE-request-id", request_id);
            }

            if let Some(session_id) = session_id {
                scope.set_tag("ONE-session-id", session_id);
            }
        });

        Ok(next.run(request).await)
    }
    // make sure that the future is run in the new hub
    .bind_hub(Hub::new_from_top(Hub::main()))
    .await
}

pub async fn bearer_check(
    Extension(config): Extension<Arc<ServerConfig>>,
    mut request: Request<Body>,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|header| header.to_str().ok());

    let auth_header = if let Some(auth_header) = auth_header {
        auth_header.to_owned()
    } else {
        tracing::warn!("Authorization header not found.");
        return Err(StatusCode::UNAUTHORIZED);
    };

    let mut split = auth_header.split(' ');
    let auth_type = split.next().unwrap_or_default();
    let token = split.next().unwrap_or_default();

    if auth_type == "Bearer" && !token.is_empty() && token == config.auth_token {
        request.extensions_mut().insert(Authorized {});
    } else {
        tracing::warn!("Could not authorize request. Incorrect authorization method or token.");
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(request).await)
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
