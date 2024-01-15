use mockall::predicate::eq;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::provider::did_method::DidCapabilities;
use crate::{
    model::key::Key,
    provider::{
        did_method::{
            dto::{PublicKeyJwkDTO, PublicKeyJwkEllipticDataDTO},
            jwk::JWKDidMethod,
            DidMethod, DidMethodError,
        },
        key_algorithm::{provider::MockKeyAlgorithmProvider, MockKeyAlgorithm},
    },
};

#[tokio::test]
async fn test_resolve_jwk_did_without_use_field() {
    let provider = JWKDidMethod::new(
        DidCapabilities {
            operations: vec!["RESOLVE".to_string(), "CREATE".to_string()],
            key_algorithms: vec!["ES256".to_string(), "EDDSA".to_string()],
        },
        Arc::new(MockKeyAlgorithmProvider::default()),
    );

    let result = provider
        .resolve(
            &"did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9"
                .parse()
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        serde_json::json!(result),
        serde_json::json!({
            "@context": [
              "https://www.w3.org/ns/did/v1",
              "https://w3id.org/security/suites/jws-2020/v1"
            ],
            "id": "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9",
            "verificationMethod": [
              {
                "id": "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0",
                "type": "JsonWebKey2020",
                "controller": "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9",
                "publicKeyJwk": {
                  "crv": "P-256",
                  "kty": "EC",
                  "x": "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
                  "y": "_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"
                }
              }
            ],
            "assertionMethod": ["did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0"],
            "authentication": ["did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0"],
            "capabilityInvocation": ["did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0"],
            "capabilityDelegation": ["did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0"],
            "keyAgreement": ["did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0"]
        })
    );
}

#[tokio::test]
async fn test_resolve_jwk_did_with_use_enc_field() {
    let provider = JWKDidMethod::new(
        get_default_capabilities(),
        Arc::new(MockKeyAlgorithmProvider::default()),
    );

    let result = provider
        .resolve(
            &"did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9"
                .parse()
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        serde_json::json!(result),
        serde_json::json!({
          "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
          ],
          "id": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9",
          "verificationMethod": [
            {
              "id": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9#0",
              "type": "JsonWebKey2020",
              "controller": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9",
              "publicKeyJwk": {
                "kty":"OKP",
                "crv":"X25519",
                "use":"enc",
                "x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"
              }
            }
          ],
          "keyAgreement": ["did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9#0"]
        })
    );
}

#[tokio::test]
async fn test_resolve_jwk_did_with_use_sig_field() {
    let provider = JWKDidMethod::new(
        get_default_capabilities(),
        Arc::new(MockKeyAlgorithmProvider::default()),
    );

    let result = provider
        .resolve(
            &"did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwieCI6IjNwN2JmWHQ5d2JUVFcySEM3T1ExTnotRFE4aGJlR2ROcmZ4LUZHLUlLMDgifQ"
                .parse()
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        serde_json::json!(result),
        serde_json::json!({
          "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
          ],
          "id": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwieCI6IjNwN2JmWHQ5d2JUVFcySEM3T1ExTnotRFE4aGJlR2ROcmZ4LUZHLUlLMDgifQ",
          "verificationMethod": [
            {
              "id": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwieCI6IjNwN2JmWHQ5d2JUVFcySEM3T1ExTnotRFE4aGJlR2ROcmZ4LUZHLUlLMDgifQ#0",
              "type": "JsonWebKey2020",
              "controller": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwieCI6IjNwN2JmWHQ5d2JUVFcySEM3T1ExTnotRFE4aGJlR2ROcmZ4LUZHLUlLMDgifQ",
              "publicKeyJwk": {
                "kty":"OKP",
                "crv":"Ed25519",
                "use":"sig",
                "x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"
              }
            }
          ],
          "assertionMethod": ["did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwieCI6IjNwN2JmWHQ5d2JUVFcySEM3T1ExTnotRFE4aGJlR2ROcmZ4LUZHLUlLMDgifQ#0"],
          "authentication": ["did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwieCI6IjNwN2JmWHQ5d2JUVFcySEM3T1ExTnotRFE4aGJlR2ROcmZ4LUZHLUlLMDgifQ#0"],
          "capabilityInvocation": ["did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwieCI6IjNwN2JmWHQ5d2JUVFcySEM3T1ExTnotRFE4aGJlR2ROcmZ4LUZHLUlLMDgifQ#0"],
          "capabilityDelegation": ["did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwieCI6IjNwN2JmWHQ5d2JUVFcySEM3T1ExTnotRFE4aGJlR2ROcmZ4LUZHLUlLMDgifQ#0"],
        })
    );
}

#[tokio::test]
async fn test_fail_to_resolve_jwk_did_invalid_did_prefix() {
    let provider = JWKDidMethod::new(
        get_default_capabilities(),
        Arc::new(MockKeyAlgorithmProvider::default()),
    );

    let result = provider
        .resolve(
            &"did:jkk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJzaWciLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9"
                .parse()
                .unwrap(),
        )
        .await;

    assert!(matches!(result, Err(DidMethodError::ResolutionError(_))));
}

#[tokio::test]
async fn test_fail_to_resolve_jwk_did_invalid_encoding() {
    let provider = JWKDidMethod::new(
        get_default_capabilities(),
        Arc::new(MockKeyAlgorithmProvider::default()),
    );

    let result = provider
        .resolve(
            &"did:jwk:eyJrdHk`iOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJzaWciLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9"
                .parse()
                .unwrap(),
        )
        .await;

    assert!(matches!(result, Err(DidMethodError::ResolutionError(_))));
}

#[tokio::test]
async fn test_fail_to_resolve_jwk_did_invalid_jwk_format() {
    let provider = JWKDidMethod::new(
        get_default_capabilities(),
        Arc::new(MockKeyAlgorithmProvider::default()),
    );

    let result = provider
        .resolve(
            &"did:jwk:eyJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJzaWciLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9"
                .parse()
                .unwrap(),
        )
        .await;

    assert!(matches!(result, Err(DidMethodError::ResolutionError(_))));
}

#[tokio::test]
async fn test_create_did_jwk_success() {
    let mut key_algorithm = MockKeyAlgorithm::default();
    key_algorithm.expect_bytes_to_jwk().once().returning(|_| {
        Ok(PublicKeyJwkDTO::Ec(PublicKeyJwkEllipticDataDTO {
            r#use: None,
            crv: "crv".to_string(),
            x: "x".to_string(),
            y: None,
        }))
    });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    key_algorithm_provider
        .expect_get_key_algorithm()
        .with(eq("key_type"))
        .once()
        .return_once(move |_| Some(Arc::new(key_algorithm)));

    let provider = JWKDidMethod::new(get_default_capabilities(), Arc::new(key_algorithm_provider));

    let result = provider
        .create(
            &Uuid::new_v4().into(),
            &None,
            &Some(Key {
                id: Uuid::new_v4(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                public_key: b"public".into(),
                name: "name".to_owned(),
                key_reference: vec![],
                storage_type: "test".to_owned(),
                key_type: "key_type".to_owned(),
                organisation: None,
            }),
        )
        .await
        .unwrap();

    assert_eq!(
        result.as_str(),
        "did:jwk:eyJrdHkiOiJFQyIsImNydiI6ImNydiIsIngiOiJ4In0"
    )
}

#[test]
fn test_get_capabilities() {
    let provider = JWKDidMethod::new(
        get_default_capabilities(),
        Arc::new(MockKeyAlgorithmProvider::default()),
    );

    assert_eq!(
        vec!["RESOLVE".to_string(), "CREATE".to_string()],
        provider.get_capabilities().operations
    );
}

fn get_default_capabilities() -> DidCapabilities {
    DidCapabilities {
        operations: vec!["RESOLVE".to_string(), "CREATE".to_string()],
        key_algorithms: vec!["ES256".to_string(), "EDDSA".to_string()],
    }
}
