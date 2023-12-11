use crate::provider::did_method::{jwk::JWKMethod, DidMethod, DidMethodError};

#[tokio::test]
async fn test_resolve_jwk_did_without_use_field() {
    let provider = JWKMethod {};

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
    let provider = JWKMethod {};

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
    let provider = JWKMethod {};

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
    let provider = JWKMethod {};

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
    let provider = JWKMethod {};

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
    let provider = JWKMethod {};

    let result = provider
        .resolve(
            &"did:jwk:eyJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJzaWciLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9"
                .parse()
                .unwrap(),
        )
        .await;

    assert!(matches!(result, Err(DidMethodError::ResolutionError(_))));
}
