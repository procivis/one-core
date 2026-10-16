use std::str::FromStr;
use std::sync::LazyLock;

use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use mime::Mime;
use shared_types::DpopNonce;
use standardized_types::oauth2::dpop::{DPOP_HEADER, DPOP_NONCE_HEADER};

#[allow(clippy::expect_used)]
pub(crate) static APPLICATION_XML: LazyLock<Mime> = LazyLock::new(|| {
    Mime::from_str("application/xml").expect("application/xml is valid mime type")
});

#[expect(clippy::expect_used)]
pub(crate) static APPLICATION_PEM_CHAIN: LazyLock<Mime> = LazyLock::new(|| {
    Mime::from_str("application/pem-certificate-chain")
        .expect("application/pem-certificate-chain is valid mime type")
});

#[expect(clippy::expect_used)]
pub(crate) static APPLICATION_COSE_X509: LazyLock<Mime> = LazyLock::new(|| {
    Mime::from_str("application/cose-x509").expect("application/cose-x509 is valid mime type")
});

#[allow(clippy::expect_used)]
pub(crate) static APPLICATION_JWT: LazyLock<Mime> = LazyLock::new(|| {
    Mime::from_str("application/jwt").expect("application/jwt is valid mime type")
});

/// Media type the did:webvh specification mandates for DID logs.
/// https://identity.foundation/didwebvh/v1.0/#the-did-log-file
#[expect(clippy::expect_used)]
pub(crate) static TEXT_JSONL: LazyLock<Mime> =
    LazyLock::new(|| Mime::from_str("text/jsonl").expect("text/jsonl is valid mime type"));

/// Media type some deployments (e.g. swiyu) expect for DID logs instead of [`TEXT_JSONL`].
#[expect(clippy::expect_used)]
pub(crate) static APPLICATION_JSONL_JSON: LazyLock<Mime> = LazyLock::new(|| {
    Mime::from_str("application/jsonl+json").expect("application/jsonl+json is valid mime type")
});

pub(crate) fn with_dpop_nonce(mut response: Response, dpop_nonce: Option<DpopNonce>) -> Response {
    if let Some(dpop_nonce) = dpop_nonce {
        let value = match HeaderValue::try_from(dpop_nonce.to_string()) {
            Ok(v) => v,
            Err(error) => {
                tracing::error!(%error, "Failed to serialize DPoP-Nonce response header");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        response.headers_mut().insert(DPOP_NONCE_HEADER, value);
    }
    response
}

pub(crate) fn get_dpop_proof(headers: &HeaderMap) -> Option<&str> {
    headers.get(DPOP_HEADER).and_then(|v| v.to_str().ok())
}
