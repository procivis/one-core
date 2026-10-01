use std::str::FromStr;
use std::sync::Arc;

use serde_json::json;
use shared_types::DidId;
use similar_asserts::assert_eq;
use standardized_types::jwk::{PublicJwk, PublicJwkEc, PublicJwkRsa};
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::{WebDidMethod, did_value_to_url, fetch_did_web_document};
use crate::proto::http_client::reqwest_client::ReqwestClient;
use crate::proto::http_client::{HttpClient, MockHttpClient};
use crate::provider::did_method::decorators::CapabilityChecked;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::model::Operation;
use crate::provider::did_method::{DidKeys, DidMethod};
use crate::provider::provider_directory::WithDisabledDecorator;
use crate::service::test_utilities::dummy_key;

fn single_key_set() -> DidKeys {
    let key = dummy_key();
    DidKeys {
        authentication: vec![key.clone()],
        assertion_method: vec![key.clone()],
        key_agreement: vec![key.clone()],
        capability_invocation: vec![key.clone()],
        capability_delegation: vec![key],
        update_keys: None,
    }
}

fn web_method_for_update() -> Arc<dyn DidMethod> {
    Arc::new(CapabilityChecked(Arc::new(
        WebDidMethod::new(
            "WEB".into(),
            &Some("https://example.com".to_string()),
            Arc::new(MockHttpClient::new()),
            json!({}),
        )
        .unwrap(),
    )))
}

#[rstest::rstest]
#[case(false)]
#[case(true)]
#[tokio::test]
async fn test_did_web_update(#[case] disabled: bool) {
    let mut method = web_method_for_update();
    if disabled {
        method = method.decorate();
    }
    assert!(
        method
            .get_capabilities()
            .operations
            .contains(&Operation::UPDATE)
    );
    let update = method
        .update(
            Uuid::new_v4().into(),
            single_key_set(),
            single_key_set(),
            None,
        )
        .await
        .unwrap();

    // did:web needs only the caller's new keys persisted, without a log or state change.
    assert!(update.deactivated.is_none());
    assert!(update.log.is_none());
}

#[tokio::test]
async fn test_did_web_update_rejects_invalid_key_count() {
    let method = web_method_for_update();
    let result = method
        .update(
            Uuid::new_v4().into(),
            single_key_set(),
            DidKeys::default(),
            None,
        )
        .await;
    assert!(matches!(result, Err(DidMethodError::InvalidNumberOfKeys)));
}

#[tokio::test]
async fn test_did_web_update_rejects_unsupported_update_keys() {
    let method = web_method_for_update();
    let mut keys = single_key_set();
    // did:web does not support the log-signing keys used by did:tdw/webvh.
    keys.update_keys = Some(vec![dummy_key()]);

    let result = method
        .update(Uuid::new_v4().into(), single_key_set(), keys, None)
        .await;
    assert!(matches!(result, Err(DidMethodError::UnsupportedKeyType(_))));
}

#[tokio::test]
async fn test_did_web_update_rejects_invalid_authentication_key_type() {
    let method = web_method_for_update();
    let mut keys = single_key_set();
    keys.authentication[0].key_type = "RSA".to_string();

    let result = method
        .update(Uuid::new_v4().into(), single_key_set(), keys, None)
        .await;
    assert!(matches!(result, Err(DidMethodError::Nested(_))));
}

static JSON_DATA: &str = r#"
    {
        "@context": [
          "https://www.w3.org/ns/did/v1",
          "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "id": "did:web:test-domain.com%3A54812:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7",
        "verificationMethod": [
          {
            "id": "did:web:test-domain.com%3A54812:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7#key-0",
            "type": "JsonWebKey2020",
            "controller": "did:web:test-domain.com%3A54812:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7",
            "publicKeyJwk": {
              "kty": "OKP",
              "crv": "Ed25519",
              "x": "0-e2i2_Ua1S5HbTYnVB0lj2Z2ytXu2-tYmDFf8f5NjU"
            }
          },
          {
            "id": "did:web:test-domain.com%3A54812:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7#key-1",
            "type": "JsonWebKey2020",
            "controller": "did:web:test-domain.com%3A54812:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7",
            "publicKeyJwk": {
              "kty": "OKP",
              "crv": "X25519",
              "x": "9GXjPGGvmRq9F6Ng5dQQ_s31mfhxrcNZxRGONrmH30k"
            }
          },
          {
            "id": "did:web:test-domain.com%3A54812:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7#key-2",
            "type": "JsonWebKey2020",
            "controller": "did:web:test-domain.com%3A54812:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7",
            "publicKeyJwk": {
              "kty": "EC",
              "crv": "P-256",
              "x": "38M1FDts7Oea7urmseiugGW7tWc3mLpJh6rKe7xINZ8",
              "y": "nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4"
            }
          },
          {
            "id": "did:example:123#n4cQ-I_WkHMcwXBJa7IHkYu8CMfdNcZKnKsOrnHLpFs",
            "type": "JsonWebKey2020",
            "controller": "did:example:123",
            "publicKeyJwk": {
              "kty": "RSA",
              "e": "AQAB",
              "n": "omwsC1AqEk6whvxyOltCFWheSQvv1MExu5RLCMT4jVk9khJKv8JeMXWe3bWHatjPskdf2dlaGkW5QjtOnUKL742mvr4tCldKS3ULIaT1hJInMHHxj2gcubO6eEegACQ4QSu9LO0H-LM_L3DsRABB7Qja8HecpyuspW1Tu_DbqxcSnwendamwL52V17eKhlO4uXwv2HFlxufFHM0KmCJujIKyAxjD_m3q__IiHUVHD1tDIEvLPhG9Azsn3j95d-saIgZzPLhQFiKluGvsjrSkYU5pXVWIsV-B2jtLeeLC14XcYxWDUJ0qVopxkBvdlERcNtgF4dvW4X00EHj4vCljFw"
            }
          }
        ],
        "authentication": [
          "did:web:test-domain.com%3A54812:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7#key-0",
          "did:web:test-domain.com%3A54812:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7#key-2"
        ],
        "assertionMethod": [
          "did:web:test-domain.com%3A54812:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7#key-0",
          "did:web:test-domain.com%3A54812:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7#key-2"
        ],
        "keyAgreement": [
          "did:web:test-domain.com%3A54812:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7#key-1",
          "did:web:test-domain.com%3A54812:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7#key-2"
        ]
      }
"#;

#[tokio::test]
async fn test_did_web_create() {
    let base_url = "https://test-domain.com".to_string();

    let did_web_method = WebDidMethod::new(
        "web".into(),
        &Some(base_url),
        Arc::new(MockHttpClient::new()),
        json!({}),
    )
    .unwrap();

    let id = DidId::from(Uuid::from_str("2389ba3f-81d5-4931-9222-c23ec721deb7").unwrap());

    let result = did_web_method
        .create(id, &None, DidKeys::default())
        .await
        .unwrap()
        .did;

    assert_eq!(
        result.as_str(),
        "did:web:test-domain.com:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7"
    )
}

#[tokio::test]
async fn test_did_web_create_with_port() {
    let base_url = "https://test-domain.com:54812".to_string();

    let did_web_method = WebDidMethod::new(
        "web".into(),
        &Some(base_url),
        Arc::new(MockHttpClient::new()),
        json!({}),
    )
    .unwrap();

    let id = DidId::from(Uuid::from_str("2389ba3f-81d5-4931-9222-c23ec721deb7").unwrap());

    let result = did_web_method
        .create(id, &None, DidKeys::default())
        .await
        .unwrap()
        .did;

    assert_eq!(
        result.as_str(),
        "did:web:test-domain.com%3A54812:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7"
    )
}

#[tokio::test]
async fn test_did_web_create_fail_no_base_url() {
    let did_web_method = WebDidMethod::new(
        "web".into(),
        &None,
        Arc::new(MockHttpClient::new()),
        json!({}),
    )
    .unwrap();

    let id = DidId::from(Uuid::from_str("2389ba3f-81d5-4931-9222-c23ec721deb7").unwrap());

    let result = did_web_method.create(id, &None, DidKeys::default()).await;

    assert!(matches!(
        result,
        Err(DidMethodError::InitializationError(_))
    ))
}

#[tokio::test]
async fn test_did_web_value_extract() {
    let test_cases = vec![
        (
            "did:web:w3c-ccg.github.io",
            "https://w3c-ccg.github.io/.well-known/did.json",
        ),
        (
            "did:web:w3c-ccg.github.io:user:alice",
            "https://w3c-ccg.github.io/user/alice/did.json",
        ),
        (
            "did:web:example.com%3A3000:user:alice",
            "https://example.com:3000/user/alice/did.json",
        ),
        (
            "did:web:test-domain.com:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7",
            "https://test-domain.com/ssi/did-web/v1/2389ba3f-81d5-4931-9222-c23ec721deb7/did.json",
        ),
        (
            "did:web:test-domain.com%3A54812:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7",
            "https://test-domain.com:54812/ssi/did-web/v1/2389ba3f-81d5-4931-9222-c23ec721deb7/did.json",
        ),
    ];

    for case in test_cases {
        println!("Checking: {} -> {}", case.0, case.1);
        assert_eq!(
            case.1,
            did_value_to_url(&case.0.parse().unwrap(), Some(false))
                .unwrap()
                .to_string()
        )
    }
}

#[tokio::test]
async fn test_did_web_value_extract_debug_http() {
    let test_cases = vec![
        (
            "did:web:w3c-ccg.github.io",
            "http://w3c-ccg.github.io/.well-known/did.json",
        ),
        (
            "did:web:w3c-ccg.github.io:user:alice",
            "http://w3c-ccg.github.io/user/alice/did.json",
        ),
        (
            "did:web:example.com%3A3000:user:alice",
            "http://example.com:3000/user/alice/did.json",
        ),
        (
            "did:web:test-domain.com:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7",
            "http://test-domain.com/ssi/did-web/v1/2389ba3f-81d5-4931-9222-c23ec721deb7/did.json",
        ),
        (
            "did:web:test-domain.com%3A54812:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7",
            "http://test-domain.com:54812/ssi/did-web/v1/2389ba3f-81d5-4931-9222-c23ec721deb7/did.json",
        ),
    ];

    for case in test_cases {
        println!("Checking: {} -> {}", case.0, case.1);
        assert_eq!(
            case.1,
            did_value_to_url(&case.0.parse().unwrap(), Some(true))
                .unwrap()
                .to_string()
        )
    }
}

#[tokio::test]
async fn test_did_web_fetch() {
    let mock_server = MockServer::start().await;

    Mock::given(method(Method::GET))
        .and(path(
            "/ssi/did-web/v1/2389ba3f-81d5-4931-9222-c23ec721deb7/did.json",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_raw(JSON_DATA, "text/html"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client: Arc<dyn HttpClient> = Arc::new(ReqwestClient::default());

    let url = format!(
        "{}/ssi/did-web/v1/2389ba3f-81d5-4931-9222-c23ec721deb7/did.json",
        mock_server.uri()
    )
    .parse()
    .unwrap();
    let result = fetch_did_web_document(url, &client).await;

    assert!(result.is_ok());
    let data = result.unwrap();

    assert_eq!(
        data.id,
        "did:web:test-domain.com%3A54812:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7"
            .parse()
            .unwrap()
    );

    assert!(data.assertion_method.is_some());
    assert!(data.key_agreement.is_some());
    assert!(data.authentication.is_some());

    let methods = data.verification_method;

    assert_eq!(
        methods[0].public_key_jwk,
        PublicJwk::Okp(PublicJwkEc {
            alg: None,
            r#use: None,
            kid: None,
            crv: "Ed25519".to_string(),
            x: "0-e2i2_Ua1S5HbTYnVB0lj2Z2ytXu2-tYmDFf8f5NjU".to_string(),
            y: None,
        })
    );
    assert_eq!(
        methods[1].public_key_jwk,
        PublicJwk::Okp(PublicJwkEc {
            alg: None,
            r#use: None,
            kid: None,
            crv: "X25519".to_string(),
            x: "9GXjPGGvmRq9F6Ng5dQQ_s31mfhxrcNZxRGONrmH30k".to_string(),
            y: None,
        }),
    );
    assert_eq!(
        methods[2].public_key_jwk,
        PublicJwk::Ec(PublicJwkEc {
            alg: None,
            r#use: None,
            kid: None,
            crv: "P-256".to_string(),
            x: "38M1FDts7Oea7urmseiugGW7tWc3mLpJh6rKe7xINZ8".to_string(),
            y: Some("nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4".to_string()),
        }),
    );
    assert_eq!(
        methods[3].public_key_jwk,
        PublicJwk::Rsa(PublicJwkRsa {
            alg: None,
            r#use: None,
            kid: None,
            e: "AQAB".to_string(),
            n: "omwsC1AqEk6whvxyOltCFWheSQvv1MExu5RLCMT4jVk9khJKv8JeMXWe3bWHatjPskdf2dlaGkW5Qj\
            tOnUKL742mvr4tCldKS3ULIaT1hJInMHHxj2gcubO6eEegACQ4QSu9LO0H-LM_L3DsRABB7Qja8Hecpyus\
            pW1Tu_DbqxcSnwendamwL52V17eKhlO4uXwv2HFlxufFHM0KmCJujIKyAxjD_m3q__IiHUVHD1tDIEvLPh\
            G9Azsn3j95d-saIgZzPLhQFiKluGvsjrSkYU5pXVWIsV-B2jtLeeLC14XcYxWDUJ0qVopxkBvdlERcNtgF\
            4dvW4X00EHj4vCljFw"
                .to_string(),
        }),
    );
}
