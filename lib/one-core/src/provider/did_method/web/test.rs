use std::str::FromStr;
use std::sync::Arc;

use shared_types::DidId;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::keys::{Keys, MinMax};
use crate::provider::did_method::model::AmountOfKeys;
use crate::provider::did_method::web::{
    did_value_to_url, fetch_did_web_document, Params, WebDidMethod,
};
use crate::provider::did_method::DidMethod;
use crate::provider::http_client::reqwest_client::ReqwestClient;
use crate::provider::http_client::{HttpClient, MockHttpClient};
use crate::service::key::dto::{
    PublicKeyJwkDTO, PublicKeyJwkEllipticDataDTO, PublicKeyJwkRsaDataDTO,
};

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
        &Some(base_url),
        Arc::new(MockHttpClient::new()),
        Default::default(),
    )
    .unwrap();

    let id = DidId::from(Uuid::from_str("2389ba3f-81d5-4931-9222-c23ec721deb7").unwrap());

    let result = did_web_method.create(Some(id), &None, None).await;

    assert_eq!(
        result.unwrap().as_str(),
        "did:web:test-domain.com:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7"
    )
}

#[tokio::test]
async fn test_did_web_create_with_port() {
    let base_url = "https://test-domain.com:54812".to_string();

    let did_web_method = WebDidMethod::new(
        &Some(base_url),
        Arc::new(MockHttpClient::new()),
        Default::default(),
    )
    .unwrap();

    let id = DidId::from(Uuid::from_str("2389ba3f-81d5-4931-9222-c23ec721deb7").unwrap());

    let result = did_web_method.create(Some(id), &None, None).await;

    assert_eq!(
        result.unwrap().as_str(),
        "did:web:test-domain.com%3A54812:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7"
    )
}

#[tokio::test]
async fn test_did_web_create_fail_no_base_url() {
    let did_web_method =
        WebDidMethod::new(&None, Arc::new(MockHttpClient::new()), Default::default()).unwrap();

    let id = DidId::from(Uuid::from_str("2389ba3f-81d5-4931-9222-c23ec721deb7").unwrap());

    let result = did_web_method.create(Some(id), &None, None).await;

    assert!(matches!(result, Err(DidMethodError::CouldNotCreate(_))))
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
        )
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
        )
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
        PublicKeyJwkDTO::Okp(PublicKeyJwkEllipticDataDTO {
            r#use: None,
            crv: "Ed25519".to_string(),
            x: "0-e2i2_Ua1S5HbTYnVB0lj2Z2ytXu2-tYmDFf8f5NjU".to_string(),
            y: None,
        })
    );
    assert_eq!(
        methods[1].public_key_jwk,
        PublicKeyJwkDTO::Okp(PublicKeyJwkEllipticDataDTO {
            r#use: None,
            crv: "X25519".to_string(),
            x: "9GXjPGGvmRq9F6Ng5dQQ_s31mfhxrcNZxRGONrmH30k".to_string(),
            y: None,
        }),
    );
    assert_eq!(
        methods[2].public_key_jwk,
        PublicKeyJwkDTO::Ec(PublicKeyJwkEllipticDataDTO {
            r#use: None,
            crv: "P-256".to_string(),
            x: "38M1FDts7Oea7urmseiugGW7tWc3mLpJh6rKe7xINZ8".to_string(),
            y: Some("nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4".to_string()),
        }),
    );
    assert_eq!(
        methods[3].public_key_jwk,
        PublicKeyJwkDTO::Rsa(PublicKeyJwkRsaDataDTO {
            r#use: None,
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

#[test]
fn test_validate_default_keys() {
    let did_method =
        WebDidMethod::new(&None, Arc::new(MockHttpClient::new()), Default::default()).unwrap();
    let keys = AmountOfKeys {
        global: 1,
        authentication: 1,
        assertion_method: 1,
        key_agreement: 1,
        capability_invocation: 1,
        capability_delegation: 1,
    };
    assert!(did_method.validate_keys(keys));
}

#[test]
fn test_validate_default_keys_no_keys() {
    let did_method =
        WebDidMethod::new(&None, Arc::new(MockHttpClient::new()), Default::default()).unwrap();
    let keys = AmountOfKeys {
        global: 0,
        authentication: 0,
        assertion_method: 0,
        key_agreement: 0,
        capability_invocation: 0,
        capability_delegation: 0,
    };
    assert!(!did_method.validate_keys(keys));
}

#[test]
fn test_validate_default_keys_too_much_keys() {
    let did_method =
        WebDidMethod::new(&None, Arc::new(MockHttpClient::new()), Default::default()).unwrap();
    let keys = AmountOfKeys {
        global: 2,
        authentication: 1,
        assertion_method: 1,
        key_agreement: 1,
        capability_invocation: 1,
        capability_delegation: 1,
    };
    assert!(!did_method.validate_keys(keys));
}

#[test]
fn test_validate_default_keys_missing_key() {
    let did_method =
        WebDidMethod::new(&None, Arc::new(MockHttpClient::new()), Default::default()).unwrap();
    let keys = AmountOfKeys {
        global: 1,
        authentication: 1,
        assertion_method: 0,
        key_agreement: 1,
        capability_invocation: 1,
        capability_delegation: 1,
    };
    assert!(!did_method.validate_keys(keys));
}

#[test]
fn test_validate_keys() {
    let did_method = WebDidMethod::new(
        &None,
        Arc::new(MockHttpClient::new()),
        Params {
            keys: Keys {
                global: MinMax { min: 2, max: 3 },
                authentication: MinMax { min: 2, max: 3 },
                assertion_method: MinMax { min: 2, max: 3 },
                key_agreement: MinMax { min: 2, max: 3 },
                capability_invocation: MinMax { min: 2, max: 3 },
                capability_delegation: MinMax { min: 2, max: 3 },
            },
            ..Default::default()
        },
    )
    .unwrap();
    let keys = AmountOfKeys {
        global: 2,
        authentication: 3,
        assertion_method: 3,
        key_agreement: 2,
        capability_invocation: 2,
        capability_delegation: 2,
    };
    assert!(did_method.validate_keys(keys));
}

#[test]
fn test_validate_keys_no_keys() {
    let did_method = WebDidMethod::new(
        &None,
        Arc::new(MockHttpClient::new()),
        Params {
            keys: Keys {
                global: MinMax { min: 2, max: 3 },
                authentication: MinMax { min: 2, max: 3 },
                assertion_method: MinMax { min: 2, max: 3 },
                key_agreement: MinMax { min: 2, max: 3 },
                capability_invocation: MinMax { min: 2, max: 3 },
                capability_delegation: MinMax { min: 2, max: 3 },
            },
            ..Default::default()
        },
    )
    .unwrap();
    let keys = AmountOfKeys {
        global: 0,
        authentication: 0,
        assertion_method: 0,
        key_agreement: 0,
        capability_invocation: 0,
        capability_delegation: 0,
    };
    assert!(!did_method.validate_keys(keys));
}

#[test]
fn test_validate_keys_too_much_keys() {
    let did_method = WebDidMethod::new(
        &None,
        Arc::new(MockHttpClient::new()),
        Params {
            keys: Keys {
                global: MinMax { min: 2, max: 3 },
                authentication: MinMax { min: 2, max: 3 },
                assertion_method: MinMax { min: 2, max: 3 },
                key_agreement: MinMax { min: 2, max: 3 },
                capability_invocation: MinMax { min: 2, max: 3 },
                capability_delegation: MinMax { min: 2, max: 3 },
            },
            ..Default::default()
        },
    )
    .unwrap();
    let keys = AmountOfKeys {
        global: 5,
        authentication: 2,
        assertion_method: 2,
        key_agreement: 2,
        capability_invocation: 2,
        capability_delegation: 2,
    };
    assert!(!did_method.validate_keys(keys));
}

#[test]
fn test_validate_keys_missing_key() {
    let did_method = WebDidMethod::new(
        &None,
        Arc::new(MockHttpClient::new()),
        Params {
            keys: Keys {
                global: MinMax { min: 2, max: 3 },
                authentication: MinMax { min: 2, max: 3 },
                assertion_method: MinMax { min: 2, max: 3 },
                key_agreement: MinMax { min: 2, max: 3 },
                capability_invocation: MinMax { min: 2, max: 3 },
                capability_delegation: MinMax { min: 2, max: 3 },
            },
            ..Default::default()
        },
    )
    .unwrap();
    let keys = AmountOfKeys {
        global: 2,
        authentication: 2,
        assertion_method: 0,
        key_agreement: 2,
        capability_invocation: 2,
        capability_delegation: 2,
    };
    assert!(!did_method.validate_keys(keys));
}
