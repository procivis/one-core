use std::sync::Arc;

use mockall::predicate::{always, eq};
use serde_json::json;

use crate::model::key::{PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::model::{DidDocument, DidVerificationMethod};
use crate::provider::did_method::sd_jwt_vc_issuer_metadata::{
    Params, SdJwtVcIssuerMetadataDidMethod,
};
use crate::provider::did_method::DidMethod;
use crate::provider::http_client::{
    Method, MockHttpClient, Request, RequestBuilder, Response, StatusCode,
};

fn mock_http_get_request(http_client: &mut MockHttpClient, url: &'static str, response: Response) {
    let mut new_client = MockHttpClient::new();
    new_client
        .expect_send()
        .with(eq(url), always(), always(), eq(Method::Get))
        .return_once(move |_, _, _, _| Ok(response));

    http_client
        .expect_get()
        .with(eq(url))
        .return_once(move |url| RequestBuilder::new(Arc::new(new_client), Method::Get, url));
}

fn expected_did_document(did: &str) -> DidDocument {
    DidDocument {
        context: json!([
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ]),
        id: did.parse().unwrap(),
        verification_method: vec![
            DidVerificationMethod {
                id: format!("{did}#2ZLVwwjX7E3BOs2EKTvNqeLq1ieBMwFIJU_KTI933fk"),
                r#type: "JsonWebKey2020".to_string(),
                controller: did.to_string(),
                public_key_jwk: PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
                    r#use: None,
                    kid: Some("2ZLVwwjX7E3BOs2EKTvNqeLq1ieBMwFIJU_KTI933fk".to_string()),
                    crv: "Ed25519".to_string(),
                    x: "ZUQNBknv-ayaCBe3zuPOxkRoBBQam4E-tWbQtQKP9_0".to_string(),
                    y: None,
                }),
            },
            DidVerificationMethod {
                id: format!("{did}#2ZLVwwjX7E3BOs2EKTvNqeLq1ieBMwFIJU_KTI933fk-second"),
                r#type: "JsonWebKey2020".to_string(),
                controller: did.to_string(),
                public_key_jwk: PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
                    r#use: None,
                    kid: Some("2ZLVwwjX7E3BOs2EKTvNqeLq1ieBMwFIJU_KTI933fk-second".to_string()),
                    crv: "Ed25519".to_string(),
                    x: "ZUQNBknv-ayaCBe3zuPOxkRoBBQam4E-tWbQtQKP9_0-second".to_string(),
                    y: None,
                }),
            },
        ],
        authentication: Some(vec![
            format!("{did}#2ZLVwwjX7E3BOs2EKTvNqeLq1ieBMwFIJU_KTI933fk"),
            format!("{did}#2ZLVwwjX7E3BOs2EKTvNqeLq1ieBMwFIJU_KTI933fk-second"),
        ]),
        assertion_method: Some(vec![
            format!("{did}#2ZLVwwjX7E3BOs2EKTvNqeLq1ieBMwFIJU_KTI933fk"),
            format!("{did}#2ZLVwwjX7E3BOs2EKTvNqeLq1ieBMwFIJU_KTI933fk-second"),
        ]),
        key_agreement: Some(vec![
            format!("{did}#2ZLVwwjX7E3BOs2EKTvNqeLq1ieBMwFIJU_KTI933fk"),
            format!("{did}#2ZLVwwjX7E3BOs2EKTvNqeLq1ieBMwFIJU_KTI933fk-second"),
        ]),
        capability_invocation: Some(vec![
            format!("{did}#2ZLVwwjX7E3BOs2EKTvNqeLq1ieBMwFIJU_KTI933fk"),
            format!("{did}#2ZLVwwjX7E3BOs2EKTvNqeLq1ieBMwFIJU_KTI933fk-second"),
        ]),
        capability_delegation: Some(vec![
            format!("{did}#2ZLVwwjX7E3BOs2EKTvNqeLq1ieBMwFIJU_KTI933fk"),
            format!("{did}#2ZLVwwjX7E3BOs2EKTvNqeLq1ieBMwFIJU_KTI933fk-second"),
        ]),
        rest: json!(null),
    }
}

#[tokio::test]
async fn test_resolve_through_jwks_with_path() {
    const DID_URL: &str = "http://example-did-provider.did/some/path";
    const DID_URL_AFTER_PREPENDING_WELL_KNOWN_ISSUER: &str =
        "http://example-did-provider.did/.well-known/jwt-vc-issuer/some/path";

    let response_with_jwk_url = json!({
        "issuer": DID_URL,
        "jwks": {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "kid": "2ZLVwwjX7E3BOs2EKTvNqeLq1ieBMwFIJU_KTI933fk",
                    "x": "ZUQNBknv-ayaCBe3zuPOxkRoBBQam4E-tWbQtQKP9_0"
                }, {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "kid": "2ZLVwwjX7E3BOs2EKTvNqeLq1ieBMwFIJU_KTI933fk-second",
                    "x": "ZUQNBknv-ayaCBe3zuPOxkRoBBQam4E-tWbQtQKP9_0-second"
                }
            ]
        }
    });

    let mut http_client = MockHttpClient::new();
    mock_http_get_request(
        &mut http_client,
        DID_URL_AFTER_PREPENDING_WELL_KNOWN_ISSUER,
        Response {
            body: serde_json::to_string(&response_with_jwk_url)
                .unwrap()
                .into_bytes(),
            headers: Default::default(),
            status: StatusCode(200),
            request: Request {
                body: None,
                headers: Default::default(),
                method: Method::Get,
                url: DID_URL_AFTER_PREPENDING_WELL_KNOWN_ISSUER.to_string(),
            },
        },
    );

    let provider = SdJwtVcIssuerMetadataDidMethod::new(
        Arc::new(http_client),
        Params {
            resolve_to_insecure_http: Some(true),
        },
    );

    let did = format!(
        "did:sd_jwt_vc_issuer_metadata:{}",
        urlencoding::encode(DID_URL)
    );

    assert_eq!(
        expected_did_document(&did),
        provider.resolve(&did.parse().unwrap()).await.unwrap()
    );
}

#[tokio::test]
async fn test_resolve_through_jwk_url_without_path() {
    const DID_URL: &str = "http://example-did-provider.did";
    const DID_URL_AFTER_PREPENDING_WELL_KNOWN_ISSUER: &str =
        "http://example-did-provider.did/.well-known/jwt-vc-issuer";
    const JWKS_URL: &str = "http://example-did-provider.did/jwks";

    let response_with_jwk_url = json!({
        "issuer": DID_URL,
        "jwks_uri": JWKS_URL
    });

    let jwks_uri_response = json!({
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "2ZLVwwjX7E3BOs2EKTvNqeLq1ieBMwFIJU_KTI933fk",
                "x": "ZUQNBknv-ayaCBe3zuPOxkRoBBQam4E-tWbQtQKP9_0"
            }, {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "2ZLVwwjX7E3BOs2EKTvNqeLq1ieBMwFIJU_KTI933fk-second",
                "x": "ZUQNBknv-ayaCBe3zuPOxkRoBBQam4E-tWbQtQKP9_0-second"
            }
        ]
    });

    let mut http_client = MockHttpClient::new();
    mock_http_get_request(
        &mut http_client,
        DID_URL_AFTER_PREPENDING_WELL_KNOWN_ISSUER,
        Response {
            body: serde_json::to_string(&response_with_jwk_url)
                .unwrap()
                .into_bytes(),
            headers: Default::default(),
            status: StatusCode(200),
            request: Request {
                body: None,
                headers: Default::default(),
                method: Method::Get,
                url: DID_URL_AFTER_PREPENDING_WELL_KNOWN_ISSUER.to_string(),
            },
        },
    );
    mock_http_get_request(
        &mut http_client,
        JWKS_URL,
        Response {
            body: serde_json::to_string(&jwks_uri_response)
                .unwrap()
                .into_bytes(),
            headers: Default::default(),
            status: StatusCode(200),
            request: Request {
                body: None,
                headers: Default::default(),
                method: Method::Get,
                url: JWKS_URL.to_string(),
            },
        },
    );

    let provider = SdJwtVcIssuerMetadataDidMethod::new(
        Arc::new(http_client),
        Params {
            resolve_to_insecure_http: Some(true),
        },
    );

    let did = format!(
        "did:sd_jwt_vc_issuer_metadata:{}",
        urlencoding::encode(DID_URL)
    );

    assert_eq!(
        expected_did_document(&did),
        provider.resolve(&did.parse().unwrap()).await.unwrap()
    );
}

#[tokio::test]
async fn test_resolve_failure_disallowed_scheme() {
    const DID_URL: &str = "http://example-did-provider.did";

    let http_client = MockHttpClient::new();
    let provider = SdJwtVcIssuerMetadataDidMethod::new(Arc::new(http_client), Default::default());

    let did = format!(
        "did:sd_jwt_vc_issuer_metadata:{}",
        urlencoding::encode(DID_URL)
    );

    let result = provider.resolve(&did.parse().unwrap()).await;

    assert!(matches!(result, Err(DidMethodError::ResolutionError(_))));
}
