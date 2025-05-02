use std::sync::Arc;

use mockall::predicate::eq;
use serde_json::json;

use crate::model::key::{PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::model::{DidDocument, DidVerificationMethod};
use crate::provider::did_method::sd_jwt_vc_issuer_metadata::{
    Params, SdJwtVcIssuerMetadataDidMethod,
};
use crate::provider::did_method::DidMethod;
use crate::provider::http_client::{Method, MockHttpClient, Request, Response, StatusCode};
use crate::provider::key_algorithm::key::{
    KeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
};
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::util::test_utilities::mock_http_get_request;

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
        also_known_as: None,
        service: None,
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
        DID_URL_AFTER_PREPENDING_WELL_KNOWN_ISSUER.to_string(),
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

    let key_algorithm_provider = MockKeyAlgorithmProvider::new();
    let provider = SdJwtVcIssuerMetadataDidMethod::new(
        Arc::new(http_client),
        Arc::new(key_algorithm_provider),
        Params {
            resolve_to_insecure_http: Some(true),
            iaca_certificate: None,
        },
    )
    .unwrap();

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
    const DID_URL_AFTER_APPENDING_WELL_KNOWN_ISSUER: &str =
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
        DID_URL_AFTER_APPENDING_WELL_KNOWN_ISSUER.to_string(),
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
                url: DID_URL_AFTER_APPENDING_WELL_KNOWN_ISSUER.to_string(),
            },
        },
    );
    mock_http_get_request(
        &mut http_client,
        JWKS_URL.to_string(),
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

    let key_algorithm_provider = MockKeyAlgorithmProvider::new();
    let provider = SdJwtVcIssuerMetadataDidMethod::new(
        Arc::new(http_client),
        Arc::new(key_algorithm_provider),
        Params {
            resolve_to_insecure_http: Some(true),
            iaca_certificate: None,
        },
    )
    .unwrap();

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
    let mock_key_algorithm_provider = MockKeyAlgorithmProvider::new();
    let provider = SdJwtVcIssuerMetadataDidMethod::new(
        Arc::new(http_client),
        Arc::new(mock_key_algorithm_provider),
        Default::default(),
    )
    .unwrap();

    let did = format!(
        "did:sd_jwt_vc_issuer_metadata:{}",
        urlencoding::encode(DID_URL)
    );

    let result = provider.resolve(&did.parse().unwrap()).await;

    assert!(matches!(result, Err(DidMethodError::ResolutionError(_))));
}

#[tokio::test]
async fn test_resolve_with_certificate() {
    const ROOT_CA: &str = "MIIDHTCCAqOgAwIBAgIUVqjgtJqf4hUYJkqdYzi-0xwhwFYwCgYIKoZIzj0EAwMwXDEeMBwGA1UEAwwVUElEIElzc3VlciBDQSAtIFVUIDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMB4XDTIzMDkwMTE4MzQxN1oXDTMyMTEyNzE4MzQxNlowXDEeMBwGA1UEAwwVUElEIElzc3VlciBDQSAtIFVUIDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEFg5Shfsxp5R_UFIEKS3L27dwnFhnjSgUh2btKOQEnfb3doyeqMAvBtUMlClhsF3uefKinCw08NB31rwC-dtj6X_LE3n2C9jROIUN8PrnlLS5Qs4Rs4ZU5OIgztoaO8G9o4IBJDCCASAwEgYDVR0TAQH_BAgwBgEB_wIBADAfBgNVHSMEGDAWgBSzbLiRFxzXpBpmMYdC4YvAQMyVGzAWBgNVHSUBAf8EDDAKBggrgQICAAABBzBDBgNVHR8EPDA6MDigNqA0hjJodHRwczovL3ByZXByb2QucGtpLmV1ZGl3LmRldi9jcmwvcGlkX0NBX1VUXzAxLmNybDAdBgNVHQ4EFgQUs2y4kRcc16QaZjGHQuGLwEDMlRswDgYDVR0PAQH_BAQDAgEGMF0GA1UdEgRWMFSGUmh0dHBzOi8vZ2l0aHViLmNvbS9ldS1kaWdpdGFsLWlkZW50aXR5LXdhbGxldC9hcmNoaXRlY3R1cmUtYW5kLXJlZmVyZW5jZS1mcmFtZXdvcmswCgYIKoZIzj0EAwMDaAAwZQIwaXUA3j--xl_tdD76tXEWCikfM1CaRz4vzBC7NS0wCdItKiz6HZeV8EPtNCnsfKpNAjEAqrdeKDnr5Kwf8BA7tATehxNlOV4Hnc10XO1XULtigCwb49RpkqlS2Hul-DpqObUs";
    const LEAF_CERT: &str = "MIIDADCCAoagAwIBAgIUGazK3gunp2AkVzo824kBG4hV+1gwCgYIKoZIzj0EAwIwXDEeMBwGA1UEAwwVUElEIElzc3VlciBDQSAtIFVUIDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMB4XDTI1MDExNDEyNTcyM1oXDTI2MDQwOTEyNTcyMlowUzEVMBMGA1UEAwwMUElEIERTIC0gMDAzMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAy52Z4doQ6MCdAuG1U9fFFfKvlhmGbmtSVXdF7BNyvktmQbch58hZOfItH8j29wcU3OGf3nNEo1FG8o1vOora6OCAS0wggEpMB8GA1UdIwQYMBaAFLNsuJEXHNekGmYxh0Lhi8BAzJUbMBsGA1UdEQQUMBKCEGlzc3Vlci5ldWRpdy5kZXYwFgYDVR0lAQH/BAwwCgYIK4ECAgAAAQIwQwYDVR0fBDwwOjA4oDagNIYyaHR0cHM6Ly9wcmVwcm9kLnBraS5ldWRpdy5kZXYvY3JsL3BpZF9DQV9VVF8wMS5jcmwwHQYDVR0OBBYEFH7QIGQSbLgqDS8Pdq5Uu/IyX3+IMA4GA1UdDwEB/wQEAwIHgDBdBgNVHRIEVjBUhlJodHRwczovL2dpdGh1Yi5jb20vZXUtZGlnaXRhbC1pZGVudGl0eS13YWxsZXQvYXJjaGl0ZWN0dXJlLWFuZC1yZWZlcmVuY2UtZnJhbWV3b3JrMAoGCCqGSM49BAMCA2gAMGUCMFh4E+SbogxFDzalQt3tVWWkcqx6hcImUQ6UVwLeBWPRoKgpyCnyGp+yLHDWrGvoOQIxAO155AH+T3Mg14Oc6Qnc6Ht6o+YuIN86voO6GkwconHsrcBSj5TwJcqNB5qtf7I19w==";
    const CERT_KEY: [u8; 91] = [
        48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3,
        66, 0, 4, 3, 46, 118, 103, 135, 104, 67, 163, 2, 116, 11, 134, 213, 79, 95, 20, 87, 202,
        190, 88, 102, 25, 185, 173, 73, 85, 221, 23, 176, 77, 202, 249, 45, 153, 6, 220, 135, 159,
        33, 100, 231, 200, 180, 127, 35, 219, 220, 28, 83, 115, 134, 127, 121, 205, 18, 141, 69,
        27, 202, 53, 188, 234, 43, 107,
    ];

    let http_client = MockHttpClient::new();
    let mut mock_key_algorithm_provider = MockKeyAlgorithmProvider::new();
    let mut mock_key_algorithm = MockKeyAlgorithm::new();
    let mut public_key_handle = MockSignaturePublicKeyHandle::default();
    public_key_handle.expect_as_jwk().return_once(|| {
        Ok(PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
            r#use: None,
            kid: None,
            crv: "crv".to_string(),
            x: "x".to_string(),
            y: None,
        }))
    });

    mock_key_algorithm
        .expect_parse_raw()
        .with(eq(CERT_KEY))
        .return_once(move |_| {
            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(public_key_handle),
            )))
        });

    mock_key_algorithm_provider
        .expect_key_algorithm_from_name()
        .with(eq("ECDSA"))
        .return_once(move |_| Some(Arc::new(mock_key_algorithm)));

    let provider = SdJwtVcIssuerMetadataDidMethod::new(
        Arc::new(http_client),
        Arc::new(mock_key_algorithm_provider),
        Params {
            iaca_certificate: Some(ROOT_CA.to_string()),
            ..Default::default()
        },
    )
    .unwrap();

    let mut url = url::Url::parse("https://issuer.eudiw.dev").unwrap();
    url.query_pairs_mut().append_pair("x5c", LEAF_CERT);

    let did = format!(
        "did:sd_jwt_vc_issuer_metadata:{}",
        urlencoding::encode(url.as_ref())
    );

    let did_document: DidDocument = provider.resolve(&did.parse().unwrap()).await.unwrap();
    assert_eq!(did_document.id.as_str(), &did);
}
