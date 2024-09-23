use std::sync::Arc;

use mockall::predicate::eq;
use shared_types::DidValue;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::key::{Key, PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::jwk::JWKDidMethod;
use crate::provider::did_method::model::{
    AmountOfKeys, DidDocument, DidVerificationMethod, Operation,
};
use crate::provider::did_method::DidMethod;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_algorithm::MockKeyAlgorithm;

#[tokio::test]
async fn test_resolve_jwk_did_without_use_field() {
    let provider = JWKDidMethod::new(Arc::new(MockKeyAlgorithmProvider::default()));

    let result = provider
        .resolve(
            &DidValue::from("did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9".to_string()),
        )
        .await
        .unwrap();

    let expected = DidDocument {
        context: serde_json::json!([
              "https://www.w3.org/ns/did/v1",
              "https://w3id.org/security/suites/jws-2020/v1"
            ]),
        id: DidValue::from("did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9".to_string()),
        verification_method: vec![DidVerificationMethod {
            id: "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0".to_string(),
            r#type: "JsonWebKey2020".to_string(),
            controller: "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9".to_string(),
            public_key_jwk: PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
                r#use: None,
                crv: "P-256".to_string(),
                x: "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0".to_string(),
                y: Some("_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE".to_string()),
            }),
        }],
        authentication: Some(vec!["did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0".to_string()]),
        assertion_method: Some(vec!["did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0".to_string()]),
        key_agreement: Some(vec!["did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0".to_string()]),
        capability_invocation: Some(vec!["did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0".to_string()]),
        capability_delegation: Some(vec!["did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0".to_string()]),
        rest: Default::default()
    };

    assert_eq!(expected, result);
}

#[tokio::test]
async fn test_resolve_jwk_did_with_use_enc_field() {
    let provider = JWKDidMethod::new(Arc::new(MockKeyAlgorithmProvider::default()));

    let result = provider
        .resolve(
            &DidValue::from("did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9".to_string()))
        .await
        .unwrap();

    let expected = DidDocument {
        context: serde_json::json!([
              "https://www.w3.org/ns/did/v1",
              "https://w3id.org/security/suites/jws-2020/v1"
            ]),
        id: DidValue::from("did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9".to_string()),
        verification_method: vec![DidVerificationMethod {
            id: "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9#0".to_string(),
            r#type: "JsonWebKey2020".to_string(),
            controller: "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9".to_string(),
            public_key_jwk: PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
                r#use: Some("enc".to_string()),
                crv: "X25519".to_string(),
                x: "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08".to_string(),
                y: None,
            }),
        }],
        authentication: None,
        assertion_method: None,
        key_agreement: Some(vec!["did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9#0".to_string()]),
        capability_invocation: None,
        capability_delegation: None,
        rest: Default::default()
    };

    assert_eq!(expected, result);
}

#[tokio::test]
async fn test_resolve_jwk_did_with_use_sig_field() {
    let provider = JWKDidMethod::new(Arc::new(MockKeyAlgorithmProvider::default()));

    let result = provider
        .resolve(
            &DidValue::from("did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwieCI6IjNwN2JmWHQ5d2JUVFcySEM3T1ExTnotRFE4aGJlR2ROcmZ4LUZHLUlLMDgifQ".to_string()))
        .await
        .unwrap();

    let expected = DidDocument {
        context: serde_json::json!([
              "https://www.w3.org/ns/did/v1",
              "https://w3id.org/security/suites/jws-2020/v1"
            ]),
        id: DidValue::from("did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwieCI6IjNwN2JmWHQ5d2JUVFcySEM3T1ExTnotRFE4aGJlR2ROcmZ4LUZHLUlLMDgifQ".to_string()),
        verification_method: vec![DidVerificationMethod {
            id: "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwieCI6IjNwN2JmWHQ5d2JUVFcySEM3T1ExTnotRFE4aGJlR2ROcmZ4LUZHLUlLMDgifQ#0".to_string(),
            r#type: "JsonWebKey2020".to_string(),
            controller: "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwieCI6IjNwN2JmWHQ5d2JUVFcySEM3T1ExTnotRFE4aGJlR2ROcmZ4LUZHLUlLMDgifQ".to_string(),
            public_key_jwk: PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
                r#use: Some("sig".to_string()),
                crv: "Ed25519".to_string(),
                x: "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08".to_string(),
                y: None,
            }),
        }],
        authentication: Some(vec!["did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwieCI6IjNwN2JmWHQ5d2JUVFcySEM3T1ExTnotRFE4aGJlR2ROcmZ4LUZHLUlLMDgifQ#0".to_string()]),
        assertion_method: Some(vec!["did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwieCI6IjNwN2JmWHQ5d2JUVFcySEM3T1ExTnotRFE4aGJlR2ROcmZ4LUZHLUlLMDgifQ#0".to_string()]),
        key_agreement: None,
        capability_invocation: Some(vec!["did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwieCI6IjNwN2JmWHQ5d2JUVFcySEM3T1ExTnotRFE4aGJlR2ROcmZ4LUZHLUlLMDgifQ#0".to_string()]),
        capability_delegation: Some(vec!["did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwieCI6IjNwN2JmWHQ5d2JUVFcySEM3T1ExTnotRFE4aGJlR2ROcmZ4LUZHLUlLMDgifQ#0".to_string()]),
        rest: Default::default()
    };

    assert_eq!(expected, result);
}

#[tokio::test]
async fn test_fail_to_resolve_jwk_did_invalid_did_prefix() {
    let provider = JWKDidMethod::new(Arc::new(MockKeyAlgorithmProvider::default()));

    let result = provider
        .resolve(
            &DidValue::from("did:jkk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJzaWciLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9".to_string()))
        .await;

    assert!(matches!(result, Err(DidMethodError::ResolutionError(_))));
}

#[tokio::test]
async fn test_fail_to_resolve_jwk_did_invalid_encoding() {
    let provider = JWKDidMethod::new(Arc::new(MockKeyAlgorithmProvider::default()));

    let result = provider
        .resolve(
            &DidValue::from("did:jwk:eyJrdHk`iOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJzaWciLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9".to_string()))
        .await;

    assert!(matches!(result, Err(DidMethodError::ResolutionError(_))));
}

#[tokio::test]
async fn test_fail_to_resolve_jwk_did_invalid_jwk_format() {
    let provider = JWKDidMethod::new(Arc::new(MockKeyAlgorithmProvider::default()));

    let result = provider
        .resolve(
            &DidValue::from("did:jwk:eyJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJzaWciLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9".to_string()))
        .await;

    assert!(matches!(result, Err(DidMethodError::ResolutionError(_))));
}

#[tokio::test]
async fn test_create_did_jwk_success() {
    let mut key_algorithm = MockKeyAlgorithm::default();
    key_algorithm
        .expect_bytes_to_jwk()
        .once()
        .returning(|_, _| {
            Ok(PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
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

    let provider = JWKDidMethod::new(Arc::new(key_algorithm_provider));

    let result = provider
        .create(
            Some(Uuid::new_v4().into()),
            &None,
            Some(vec![Key {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                public_key: b"public".into(),
                name: "name".to_owned(),
                key_reference: vec![],
                storage_type: "test".to_owned(),
                key_type: "key_type".to_owned(),
                organisation: None,
            }]),
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
    let provider = JWKDidMethod::new(Arc::new(MockKeyAlgorithmProvider::default()));

    assert_eq!(
        vec![Operation::RESOLVE, Operation::CREATE],
        provider.get_capabilities().operations
    );
}

#[test]
fn test_validate_keys() {
    let did_method = JWKDidMethod::new(Arc::new(MockKeyAlgorithmProvider::default()));
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
fn test_validate_keys_no_keys() {
    let did_method = JWKDidMethod::new(Arc::new(MockKeyAlgorithmProvider::default()));
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
    let did_method = JWKDidMethod::new(Arc::new(MockKeyAlgorithmProvider::default()));
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
fn test_validate_keys_missing_key() {
    let did_method = JWKDidMethod::new(Arc::new(MockKeyAlgorithmProvider::default()));
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
