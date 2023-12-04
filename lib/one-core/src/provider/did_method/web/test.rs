use std::str::FromStr;

use shared_types::{DidId, DidValue};
use uuid::Uuid;
use wiremock::{
    http::Method,
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

use crate::provider::did_method::{
    dto::{PublicKeyJwkDTO, PublicKeyJwkEllipticDataDTO, PublicKeyJwkRsaDataDTO},
    web::{did_value_to_url, fetch_did_web_document, WebDidMethod},
    DidMethod, DidMethodError,
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

    let did_web_method = WebDidMethod::new(&Some(base_url)).unwrap();

    let id = DidId::from(Uuid::from_str("2389ba3f-81d5-4931-9222-c23ec721deb7").unwrap());

    let result = did_web_method.create(&id, &None, &None).await;

    assert_eq!(
        result.unwrap().as_str(),
        "did:web:test-domain.com:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7"
    )
}

#[tokio::test]
async fn test_did_web_create_with_port() {
    let base_url = "https://test-domain.com:54812".to_string();

    let did_web_method = WebDidMethod::new(&Some(base_url)).unwrap();

    let id = DidId::from(Uuid::from_str("2389ba3f-81d5-4931-9222-c23ec721deb7").unwrap());

    let result = did_web_method.create(&id, &None, &None).await;

    assert_eq!(
        result.unwrap().as_str(),
        "did:web:test-domain.com%3A54812:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7"
    )
}

#[tokio::test]
async fn test_did_web_create_fail_no_base_url() {
    let did_web_method = WebDidMethod::new(&None).unwrap();

    let id = DidId::from(Uuid::from_str("2389ba3f-81d5-4931-9222-c23ec721deb7").unwrap());

    let result = did_web_method.create(&id, &None, &None).await;

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
            did_value_to_url(&DidValue::from_str(case.0).unwrap())
                .unwrap()
                .to_string()
        )
    }
}

#[tokio::test]
async fn test_did_web_fetch() {
    let mock_server = MockServer::start().await;

    Mock::given(method(Method::Get))
        .and(path(
            "/ssi/did-web/v1/2389ba3f-81d5-4931-9222-c23ec721deb7/did.json",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_raw(JSON_DATA, "text/html"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = reqwest::Client::new();

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
        DidValue::from_str(
            "did:web:test-domain.com%3A54812:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7"
        )
        .unwrap()
    );

    assert!(data.assertion_method.is_some());
    assert!(data.key_agreement.is_some());
    assert!(data.authentication.is_some());

    let methods = data.verification_method;

    assert_eq!(
        methods[0].public_key_jwk,
        PublicKeyJwkDTO::Okp(PublicKeyJwkEllipticDataDTO {
            crv: "Ed25519".to_string(),
            x: "0-e2i2_Ua1S5HbTYnVB0lj2Z2ytXu2-tYmDFf8f5NjU".to_string(),
            y: None,
        })
    );
    assert_eq!(
        methods[1].public_key_jwk,
        PublicKeyJwkDTO::Okp(PublicKeyJwkEllipticDataDTO {
            crv: "X25519".to_string(),
            x: "9GXjPGGvmRq9F6Ng5dQQ_s31mfhxrcNZxRGONrmH30k".to_string(),
            y: None,
        }),
    );
    assert_eq!(
        methods[2].public_key_jwk,
        PublicKeyJwkDTO::Ec(PublicKeyJwkEllipticDataDTO {
            crv: "P-256".to_string(),
            x: "38M1FDts7Oea7urmseiugGW7tWc3mLpJh6rKe7xINZ8".to_string(),
            y: Some("nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4".to_string(),),
        },),
    );
    assert_eq!(
        methods[3].public_key_jwk,
        PublicKeyJwkDTO::Rsa(PublicKeyJwkRsaDataDTO {
            e: "AQAB".to_string(),
            n: "omwsC1AqEk6whvxyOltCFWheSQvv1MExu5RLCMT4jVk9khJKv8JeMXWe3bWHatjPskdf2dlaGkW5Qj\
            tOnUKL742mvr4tCldKS3ULIaT1hJInMHHxj2gcubO6eEegACQ4QSu9LO0H-LM_L3DsRABB7Qja8Hecpyus\
            pW1Tu_DbqxcSnwendamwL52V17eKhlO4uXwv2HFlxufFHM0KmCJujIKyAxjD_m3q__IiHUVHD1tDIEvLPh\
            G9Azsn3j95d-saIgZzPLhQFiKluGvsjrSkYU5pXVWIsV-B2jtLeeLC14XcYxWDUJ0qVopxkBvdlERcNtgF\
            4dvW4X00EHj4vCljFw"
                .to_string(),
        },),
    );
}
