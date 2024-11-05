use std::sync::Arc;

use mockall::predicate::{always, eq};
use serde_json::json;
use shared_types::DidValue;

use crate::model::key::{PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::provider::did_method::model::{DidDocument, DidVerificationMethod};
use crate::provider::did_method::sd_jwt_vc_issuer_metadata::SdJwtVcIssuerMetadataDidMethod;
use crate::provider::did_method::DidMethod;
use crate::provider::http_client::{Method, MockHttpClient, RequestBuilder, Response, StatusCode};

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

fn expected_did_document() -> DidDocument {
    DidDocument {
        context: json!([
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ]),
        id: DidValue::from(
            "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IlpVUU5Ca252LWF5YUNCZTN6dVBPeGtSb0JCUWFtNEUtdFdiUXRRS1A5XzAifQ".to_string()
        ),
        verification_method: vec![
            DidVerificationMethod {
                id: "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IlpVUU5Ca252LWF5YUNCZTN6dVBPeGtSb0JCUWFtNEUtdFdiUXRRS1A5XzAifQ#0".to_string(),
                r#type: "JsonWebKey2020".to_string(),
                controller: "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IlpVUU5Ca252LWF5YUNCZTN6dVBPeGtSb0JCUWFtNEUtdFdiUXRRS1A5XzAifQ".to_string(),
                public_key_jwk: PublicKeyJwk::Okp(
                    PublicKeyJwkEllipticData {
                        r#use: None,
                        crv: "Ed25519".to_string(),
                        x: "ZUQNBknv-ayaCBe3zuPOxkRoBBQam4E-tWbQtQKP9_0".to_string(),
                        y: None,
                    },
                ),
            },
        ],
        authentication: Some(
            vec![
                "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IlpVUU5Ca252LWF5YUNCZTN6dVBPeGtSb0JCUWFtNEUtdFdiUXRRS1A5XzAifQ#0".to_string(),
            ],
        ),
        assertion_method: Some(
            vec![
                "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IlpVUU5Ca252LWF5YUNCZTN6dVBPeGtSb0JCUWFtNEUtdFdiUXRRS1A5XzAifQ#0".to_string(),
            ],
        ),
        key_agreement: Some(
            vec![
                "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IlpVUU5Ca252LWF5YUNCZTN6dVBPeGtSb0JCUWFtNEUtdFdiUXRRS1A5XzAifQ#0".to_string(),
            ],
        ),
        capability_invocation: Some(
            vec![
                "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IlpVUU5Ca252LWF5YUNCZTN6dVBPeGtSb0JCUWFtNEUtdFdiUXRRS1A5XzAifQ#0".to_string(),
            ],
        ),
        capability_delegation: Some(
            vec![
                "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IlpVUU5Ca252LWF5YUNCZTN6dVBPeGtSb0JCUWFtNEUtdFdiUXRRS1A5XzAifQ#0".to_string(),
            ],
        ),
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
        },
    );

    let provider = SdJwtVcIssuerMetadataDidMethod::new(Arc::new(http_client));

    assert_eq!(
        expected_did_document(),
        provider
            .resolve(&DidValue::from(DID_URL.to_string()))
            .await
            .unwrap()
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
        },
    );

    let provider = SdJwtVcIssuerMetadataDidMethod::new(Arc::new(http_client));

    assert_eq!(
        expected_did_document(),
        provider
            .resolve(&DidValue::from(DID_URL.to_string()))
            .await
            .unwrap()
    );
}
