use serde_json::json;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_resolve_did_jwk_document() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context
        .api
        .did_resolvers
        .resolve("did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9")
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let document = resp.json_value().await;
    assert_eq!(
        document,
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
                "use": null,
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
    )
}

#[tokio::test]
async fn test_fail_to_resolve_invalid_did_jwk() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context.api.did_resolvers.resolve("did:jwk:1").await;

    // THEN
    assert_eq!(resp.status(), 500);
    assert_eq!("BR_0064", resp.error_code().await);
}

#[tokio::test]
async fn test_resolve_did_key_document() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context
        .api
        .did_resolvers
        .resolve("did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv")
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let document = resp.json_value().await;
    assert_eq!(
        document,
        serde_json::json!({
          "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
          ],
          "id":"did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv",
          "verificationMethod": [
            {
              "id": "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv",
              "type": "JsonWebKey2020",
              "controller": "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv",
              "publicKeyJwk": {
                "crv": "P-256",
                "kty": "EC",
                "use": null,
                "x": "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns",
                "y": "efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM"
              }
            }
          ],
          "authentication": ["did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv"],
          "assertionMethod": ["did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv"],
          "keyAgreement": ["did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv"],
          "capabilityInvocation": ["did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv"],
          "capabilityDelegation": ["did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv"],
        })
    )
}

#[tokio::test]
async fn test_fail_to_resolve_invalid_did_key() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context.api.did_resolvers.resolve("did:key:1").await;

    // THEN
    assert_eq!(resp.status(), 500);
    assert_eq!("BR_0064", resp.error_code().await);
}

#[tokio::test]
async fn test_resolve_did_universal_document() {
    // GIVEN
    let context = TestContext::new().await;
    let did = "did:ion:EiAnKD8-jfdd0MDcZUjAbRgaThBrMxPTFOxcnfJhI7Ukaw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJzaWdfNzJiZDE2ZDYiLCJwdWJsaWNLZXlKd2siOnsiY3J2Ijoic2VjcDI1NmsxIiwia3R5IjoiRUMiLCJ4IjoiS2JfMnVOR3Nyd1VOdkh2YUNOckRGdW14VXlQTWZZd3kxNEpZZmphQUhmayIsInkiOiJhSFNDZDVEOFh0RUxvSXBpN1A5eDV1cXBpeEVxNmJDenQ0QldvUVk1UUFRIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIiwiYXNzZXJ0aW9uTWV0aG9kIl0sInR5cGUiOiJFY2RzYVNlY3AyNTZrMVZlcmlmaWNhdGlvbktleTIwMTkifV0sInNlcnZpY2VzIjpbeyJpZCI6ImxpbmtlZGRvbWFpbnMiLCJzZXJ2aWNlRW5kcG9pbnQiOnsib3JpZ2lucyI6WyJodHRwczovL3d3dy52Y3NhdG9zaGkuY29tLyJdfSwidHlwZSI6IkxpbmtlZERvbWFpbnMifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUR4SWxJak9xQk5NTGZjdzZndWpHNEdFVDM3UjBIRWM2Z20xclNZTjlMOF9RIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlBLXV3TWo3RVFheURmWTRJS3pfSE9LdmJZQ05td19Tb1lhUmhOcWhFSWhudyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQ0czQ1M5RFJpeU1JRVoxRl9sSjZnRVRMZWVHREwzZnpuQUViMVRGdFZXNEEifX0";
    let expected_document = serde_json::json!({
        "id": "did:ion:EiAnKD8-jfdd0MDcZUjAbRgaThBrMxPTFOxcnfJhI7Ukaw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJzaWdfNzJiZDE2ZDYiLCJwdWJsaWNLZXlKd2siOnsiY3J2Ijoic2VjcDI1NmsxIiwia3R5IjoiRUMiLCJ4IjoiS2JfMnVOR3Nyd1VOdkh2YUNOckRGdW14VXlQTWZZd3kxNEpZZmphQUhmayIsInkiOiJhSFNDZDVEOFh0RUxvSXBpN1A5eDV1cXBpeEVxNmJDenQ0QldvUVk1UUFRIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIiwiYXNzZXJ0aW9uTWV0aG9kIl0sInR5cGUiOiJFY2RzYVNlY3AyNTZrMVZlcmlmaWNhdGlvbktleTIwMTkifV0sInNlcnZpY2VzIjpbeyJpZCI6ImxpbmtlZGRvbWFpbnMiLCJzZXJ2aWNlRW5kcG9pbnQiOnsib3JpZ2lucyI6WyJodHRwczovL3d3dy52Y3NhdG9zaGkuY29tLyJdfSwidHlwZSI6IkxpbmtlZERvbWFpbnMifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUR4SWxJak9xQk5NTGZjdzZndWpHNEdFVDM3UjBIRWM2Z20xclNZTjlMOF9RIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlBLXV3TWo3RVFheURmWTRJS3pfSE9LdmJZQ05td19Tb1lhUmhOcWhFSWhudyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQ0czQ1M5RFJpeU1JRVoxRl9sSjZnRVRMZWVHREwzZnpuQUViMVRGdFZXNEEifX0",
        "@context": [
          "https://www.w3.org/ns/did/v1",
          {
            "@base": "did:ion:EiAnKD8-jfdd0MDcZUjAbRgaThBrMxPTFOxcnfJhI7Ukaw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJzaWdfNzJiZDE2ZDYiLCJwdWJsaWNLZXlKd2siOnsiY3J2Ijoic2VjcDI1NmsxIiwia3R5IjoiRUMiLCJ4IjoiS2JfMnVOR3Nyd1VOdkh2YUNOckRGdW14VXlQTWZZd3kxNEpZZmphQUhmayIsInkiOiJhSFNDZDVEOFh0RUxvSXBpN1A5eDV1cXBpeEVxNmJDenQ0QldvUVk1UUFRIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIiwiYXNzZXJ0aW9uTWV0aG9kIl0sInR5cGUiOiJFY2RzYVNlY3AyNTZrMVZlcmlmaWNhdGlvbktleTIwMTkifV0sInNlcnZpY2VzIjpbeyJpZCI6ImxpbmtlZGRvbWFpbnMiLCJzZXJ2aWNlRW5kcG9pbnQiOnsib3JpZ2lucyI6WyJodHRwczovL3d3dy52Y3NhdG9zaGkuY29tLyJdfSwidHlwZSI6IkxpbmtlZERvbWFpbnMifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUR4SWxJak9xQk5NTGZjdzZndWpHNEdFVDM3UjBIRWM2Z20xclNZTjlMOF9RIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlBLXV3TWo3RVFheURmWTRJS3pfSE9LdmJZQ05td19Tb1lhUmhOcWhFSWhudyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQ0czQ1M5RFJpeU1JRVoxRl9sSjZnRVRMZWVHREwzZnpuQUViMVRGdFZXNEEifX0"
          }
        ],
        "service": [
          {
            "id": "#linkeddomains",
            "type": "LinkedDomains",
            "serviceEndpoint": {
              "origins": [
                "https://www.vcsatoshi.com/"
              ]
            }
          }
        ],
        "verificationMethod": [
          {
            "id": "#sig_72bd16d6",
            "controller": "did:ion:EiAnKD8-jfdd0MDcZUjAbRgaThBrMxPTFOxcnfJhI7Ukaw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJzaWdfNzJiZDE2ZDYiLCJwdWJsaWNLZXlKd2siOnsiY3J2Ijoic2VjcDI1NmsxIiwia3R5IjoiRUMiLCJ4IjoiS2JfMnVOR3Nyd1VOdkh2YUNOckRGdW14VXlQTWZZd3kxNEpZZmphQUhmayIsInkiOiJhSFNDZDVEOFh0RUxvSXBpN1A5eDV1cXBpeEVxNmJDenQ0QldvUVk1UUFRIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIiwiYXNzZXJ0aW9uTWV0aG9kIl0sInR5cGUiOiJFY2RzYVNlY3AyNTZrMVZlcmlmaWNhdGlvbktleTIwMTkifV0sInNlcnZpY2VzIjpbeyJpZCI6ImxpbmtlZGRvbWFpbnMiLCJzZXJ2aWNlRW5kcG9pbnQiOnsib3JpZ2lucyI6WyJodHRwczovL3d3dy52Y3NhdG9zaGkuY29tLyJdfSwidHlwZSI6IkxpbmtlZERvbWFpbnMifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUR4SWxJak9xQk5NTGZjdzZndWpHNEdFVDM3UjBIRWM2Z20xclNZTjlMOF9RIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlBLXV3TWo3RVFheURmWTRJS3pfSE9LdmJZQ05td19Tb1lhUmhOcWhFSWhudyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQ0czQ1M5RFJpeU1JRVoxRl9sSjZnRVRMZWVHREwzZnpuQUViMVRGdFZXNEEifX0",
            "type": "EcdsaSecp256k1VerificationKey2019",
            "publicKeyJwk": {
              "crv": "secp256k1",
              "kty": "EC",
              "use": null,
              "x": "Kb_2uNGsrwUNvHvaCNrDFumxUyPMfYwy14JYfjaAHfk",
              "y": "aHSCd5D8XtELoIpi7P9x5uqpixEq6bCzt4BWoQY5QAQ"
            }
          }
        ],
        "authentication": [
          "#sig_72bd16d6"
        ],
        "assertionMethod": [
          "#sig_72bd16d6"
        ],
        "keyAgreement": null,
        "capabilityDelegation": null,
        "capabilityInvocation": null,
    });

    context
        .server_mock
        .universal_resolving(did, expected_document.clone())
        .await;

    // WHEN
    let resp = context.api.did_resolvers.resolve(did).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let document = resp.json_value().await;
    assert_eq!(document, expected_document);
}

#[tokio::test]
async fn test_fail_to_resolve_invalid_did_universal_document() {
    // GIVEN
    let context = TestContext::new().await;
    let did = "did:ion:1";

    context.server_mock.fail_universal_resolving(did).await;

    // WHEN
    let resp = context.api.did_resolvers.resolve(did).await;

    // THEN
    assert_eq!(resp.status(), 500);
    assert_eq!("BR_0064", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_to_resolve_unknown_did_type() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context.api.did_resolvers.resolve("did:foo:barbaz").await;

    // THEN
    assert_eq!(resp.status(), 404);
    assert_eq!("BR_0031", resp.error_code().await);
}

#[tokio::test]
async fn test_resolve_did_mdl_certificate() {
    // GIVEN
    let context = TestContext::new().await;

    let did = "did:mdl:certificate:MIIDYTCCAwegAwIBAgIUOfrQW7V3t1Df5wF54HMja4jXSiowCgYIKoZIzj0EAwIwYjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMuY29tMB4XDTI0MDUxNDA3MjcwMFoXDTI0MDgxMjAwMDAwMFowSjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxFDASBgNVBAMMC3Byb2NpdmlzLmNoMCowBQYDK2VwAyEA3LOKxB5ik9WikgQmqNFtmuvNC0FMFFVXr6ATVoL-kT6jggHgMIIB3DAOBgNVHQ8BAf8EBAMCB4AwFQYDVR0lAQH_BAswCQYHKIGMXQUBAjAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFO0asJ3iYEVQADvaWjQyGpi-LbfFMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbS9jcmwvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC8wgcgGCCsGAQUFBwEBBIG7MIG4MFoGCCsGAQUFBzAChk5odHRwOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbS9pc3N1ZXIvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC5kZXIwWgYIKwYBBQUHMAGGTmh0dHA6Ly9jYS5kZXYubWRsLXBsdXMuY29tL29jc3AvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC9jZXJ0LzAmBgNVHRIEHzAdhhtodHRwczovL2NhLmRldi5tZGwtcGx1cy5jb20wFgYDVR0RBA8wDYILcHJvY2l2aXMuY2gwHQYDVR0OBBYEFKz7jJBlcj4WlpOgMzjKwilDZ_ogMAoGCCqGSM49BAMCA0gAMEUCIDj2w5vOQacNAfIdHmfqlsn0nBpBlbBdC784VT0lqA1FAiEAtCGKf9Pd6dOyz6ke30fFb-YfKaOmbDngZ3dlZIh4dvg";

    // WHEN
    let resp = context.api.did_resolvers.resolve(did).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let document = resp.json_value().await;

    let expected = json!({
      "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
      "id": "did:mdl:certificate:MIIDYTCCAwegAwIBAgIUOfrQW7V3t1Df5wF54HMja4jXSiowCgYIKoZIzj0EAwIwYjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMuY29tMB4XDTI0MDUxNDA3MjcwMFoXDTI0MDgxMjAwMDAwMFowSjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxFDASBgNVBAMMC3Byb2NpdmlzLmNoMCowBQYDK2VwAyEA3LOKxB5ik9WikgQmqNFtmuvNC0FMFFVXr6ATVoL-kT6jggHgMIIB3DAOBgNVHQ8BAf8EBAMCB4AwFQYDVR0lAQH_BAswCQYHKIGMXQUBAjAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFO0asJ3iYEVQADvaWjQyGpi-LbfFMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbS9jcmwvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC8wgcgGCCsGAQUFBwEBBIG7MIG4MFoGCCsGAQUFBzAChk5odHRwOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbS9pc3N1ZXIvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC5kZXIwWgYIKwYBBQUHMAGGTmh0dHA6Ly9jYS5kZXYubWRsLXBsdXMuY29tL29jc3AvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC9jZXJ0LzAmBgNVHRIEHzAdhhtodHRwczovL2NhLmRldi5tZGwtcGx1cy5jb20wFgYDVR0RBA8wDYILcHJvY2l2aXMuY2gwHQYDVR0OBBYEFKz7jJBlcj4WlpOgMzjKwilDZ_ogMAoGCCqGSM49BAMCA0gAMEUCIDj2w5vOQacNAfIdHmfqlsn0nBpBlbBdC784VT0lqA1FAiEAtCGKf9Pd6dOyz6ke30fFb-YfKaOmbDngZ3dlZIh4dvg",
      "verificationMethod": [
        {
          "id": "did:mdl:certificate:MIIDYTCCAwegAwIBAgIUOfrQW7V3t1Df5wF54HMja4jXSiowCgYIKoZIzj0EAwIwYjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMuY29tMB4XDTI0MDUxNDA3MjcwMFoXDTI0MDgxMjAwMDAwMFowSjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxFDASBgNVBAMMC3Byb2NpdmlzLmNoMCowBQYDK2VwAyEA3LOKxB5ik9WikgQmqNFtmuvNC0FMFFVXr6ATVoL-kT6jggHgMIIB3DAOBgNVHQ8BAf8EBAMCB4AwFQYDVR0lAQH_BAswCQYHKIGMXQUBAjAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFO0asJ3iYEVQADvaWjQyGpi-LbfFMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbS9jcmwvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC8wgcgGCCsGAQUFBwEBBIG7MIG4MFoGCCsGAQUFBzAChk5odHRwOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbS9pc3N1ZXIvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC5kZXIwWgYIKwYBBQUHMAGGTmh0dHA6Ly9jYS5kZXYubWRsLXBsdXMuY29tL29jc3AvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC9jZXJ0LzAmBgNVHRIEHzAdhhtodHRwczovL2NhLmRldi5tZGwtcGx1cy5jb20wFgYDVR0RBA8wDYILcHJvY2l2aXMuY2gwHQYDVR0OBBYEFKz7jJBlcj4WlpOgMzjKwilDZ_ogMAoGCCqGSM49BAMCA0gAMEUCIDj2w5vOQacNAfIdHmfqlsn0nBpBlbBdC784VT0lqA1FAiEAtCGKf9Pd6dOyz6ke30fFb-YfKaOmbDngZ3dlZIh4dvg#key-0",
          "type": "JsonWebKey2020",
          "controller": "did:mdl:certificate:MIIDYTCCAwegAwIBAgIUOfrQW7V3t1Df5wF54HMja4jXSiowCgYIKoZIzj0EAwIwYjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMuY29tMB4XDTI0MDUxNDA3MjcwMFoXDTI0MDgxMjAwMDAwMFowSjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxFDASBgNVBAMMC3Byb2NpdmlzLmNoMCowBQYDK2VwAyEA3LOKxB5ik9WikgQmqNFtmuvNC0FMFFVXr6ATVoL-kT6jggHgMIIB3DAOBgNVHQ8BAf8EBAMCB4AwFQYDVR0lAQH_BAswCQYHKIGMXQUBAjAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFO0asJ3iYEVQADvaWjQyGpi-LbfFMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbS9jcmwvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC8wgcgGCCsGAQUFBwEBBIG7MIG4MFoGCCsGAQUFBzAChk5odHRwOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbS9pc3N1ZXIvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC5kZXIwWgYIKwYBBQUHMAGGTmh0dHA6Ly9jYS5kZXYubWRsLXBsdXMuY29tL29jc3AvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC9jZXJ0LzAmBgNVHRIEHzAdhhtodHRwczovL2NhLmRldi5tZGwtcGx1cy5jb20wFgYDVR0RBA8wDYILcHJvY2l2aXMuY2gwHQYDVR0OBBYEFKz7jJBlcj4WlpOgMzjKwilDZ_ogMAoGCCqGSM49BAMCA0gAMEUCIDj2w5vOQacNAfIdHmfqlsn0nBpBlbBdC784VT0lqA1FAiEAtCGKf9Pd6dOyz6ke30fFb-YfKaOmbDngZ3dlZIh4dvg",
          "publicKeyJwk": {
            "kty": "OKP",
            "use": null,
            "crv": "Ed25519",
            "x": "3LOKxB5ik9WikgQmqNFtmuvNC0FMFFVXr6ATVoL-kT4",
            "y": null
          }
        }
      ],
      "authentication": ["did:mdl:certificate:MIIDYTCCAwegAwIBAgIUOfrQW7V3t1Df5wF54HMja4jXSiowCgYIKoZIzj0EAwIwYjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMuY29tMB4XDTI0MDUxNDA3MjcwMFoXDTI0MDgxMjAwMDAwMFowSjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxFDASBgNVBAMMC3Byb2NpdmlzLmNoMCowBQYDK2VwAyEA3LOKxB5ik9WikgQmqNFtmuvNC0FMFFVXr6ATVoL-kT6jggHgMIIB3DAOBgNVHQ8BAf8EBAMCB4AwFQYDVR0lAQH_BAswCQYHKIGMXQUBAjAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFO0asJ3iYEVQADvaWjQyGpi-LbfFMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbS9jcmwvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC8wgcgGCCsGAQUFBwEBBIG7MIG4MFoGCCsGAQUFBzAChk5odHRwOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbS9pc3N1ZXIvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC5kZXIwWgYIKwYBBQUHMAGGTmh0dHA6Ly9jYS5kZXYubWRsLXBsdXMuY29tL29jc3AvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC9jZXJ0LzAmBgNVHRIEHzAdhhtodHRwczovL2NhLmRldi5tZGwtcGx1cy5jb20wFgYDVR0RBA8wDYILcHJvY2l2aXMuY2gwHQYDVR0OBBYEFKz7jJBlcj4WlpOgMzjKwilDZ_ogMAoGCCqGSM49BAMCA0gAMEUCIDj2w5vOQacNAfIdHmfqlsn0nBpBlbBdC784VT0lqA1FAiEAtCGKf9Pd6dOyz6ke30fFb-YfKaOmbDngZ3dlZIh4dvg#key-0"],
      "assertionMethod": ["did:mdl:certificate:MIIDYTCCAwegAwIBAgIUOfrQW7V3t1Df5wF54HMja4jXSiowCgYIKoZIzj0EAwIwYjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMuY29tMB4XDTI0MDUxNDA3MjcwMFoXDTI0MDgxMjAwMDAwMFowSjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxFDASBgNVBAMMC3Byb2NpdmlzLmNoMCowBQYDK2VwAyEA3LOKxB5ik9WikgQmqNFtmuvNC0FMFFVXr6ATVoL-kT6jggHgMIIB3DAOBgNVHQ8BAf8EBAMCB4AwFQYDVR0lAQH_BAswCQYHKIGMXQUBAjAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFO0asJ3iYEVQADvaWjQyGpi-LbfFMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbS9jcmwvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC8wgcgGCCsGAQUFBwEBBIG7MIG4MFoGCCsGAQUFBzAChk5odHRwOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbS9pc3N1ZXIvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC5kZXIwWgYIKwYBBQUHMAGGTmh0dHA6Ly9jYS5kZXYubWRsLXBsdXMuY29tL29jc3AvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC9jZXJ0LzAmBgNVHRIEHzAdhhtodHRwczovL2NhLmRldi5tZGwtcGx1cy5jb20wFgYDVR0RBA8wDYILcHJvY2l2aXMuY2gwHQYDVR0OBBYEFKz7jJBlcj4WlpOgMzjKwilDZ_ogMAoGCCqGSM49BAMCA0gAMEUCIDj2w5vOQacNAfIdHmfqlsn0nBpBlbBdC784VT0lqA1FAiEAtCGKf9Pd6dOyz6ke30fFb-YfKaOmbDngZ3dlZIh4dvg#key-0"],
      "keyAgreement": ["did:mdl:certificate:MIIDYTCCAwegAwIBAgIUOfrQW7V3t1Df5wF54HMja4jXSiowCgYIKoZIzj0EAwIwYjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMuY29tMB4XDTI0MDUxNDA3MjcwMFoXDTI0MDgxMjAwMDAwMFowSjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxFDASBgNVBAMMC3Byb2NpdmlzLmNoMCowBQYDK2VwAyEA3LOKxB5ik9WikgQmqNFtmuvNC0FMFFVXr6ATVoL-kT6jggHgMIIB3DAOBgNVHQ8BAf8EBAMCB4AwFQYDVR0lAQH_BAswCQYHKIGMXQUBAjAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFO0asJ3iYEVQADvaWjQyGpi-LbfFMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbS9jcmwvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC8wgcgGCCsGAQUFBwEBBIG7MIG4MFoGCCsGAQUFBzAChk5odHRwOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbS9pc3N1ZXIvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC5kZXIwWgYIKwYBBQUHMAGGTmh0dHA6Ly9jYS5kZXYubWRsLXBsdXMuY29tL29jc3AvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC9jZXJ0LzAmBgNVHRIEHzAdhhtodHRwczovL2NhLmRldi5tZGwtcGx1cy5jb20wFgYDVR0RBA8wDYILcHJvY2l2aXMuY2gwHQYDVR0OBBYEFKz7jJBlcj4WlpOgMzjKwilDZ_ogMAoGCCqGSM49BAMCA0gAMEUCIDj2w5vOQacNAfIdHmfqlsn0nBpBlbBdC784VT0lqA1FAiEAtCGKf9Pd6dOyz6ke30fFb-YfKaOmbDngZ3dlZIh4dvg#key-0"],
      "capabilityInvocation": ["did:mdl:certificate:MIIDYTCCAwegAwIBAgIUOfrQW7V3t1Df5wF54HMja4jXSiowCgYIKoZIzj0EAwIwYjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMuY29tMB4XDTI0MDUxNDA3MjcwMFoXDTI0MDgxMjAwMDAwMFowSjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxFDASBgNVBAMMC3Byb2NpdmlzLmNoMCowBQYDK2VwAyEA3LOKxB5ik9WikgQmqNFtmuvNC0FMFFVXr6ATVoL-kT6jggHgMIIB3DAOBgNVHQ8BAf8EBAMCB4AwFQYDVR0lAQH_BAswCQYHKIGMXQUBAjAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFO0asJ3iYEVQADvaWjQyGpi-LbfFMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbS9jcmwvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC8wgcgGCCsGAQUFBwEBBIG7MIG4MFoGCCsGAQUFBzAChk5odHRwOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbS9pc3N1ZXIvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC5kZXIwWgYIKwYBBQUHMAGGTmh0dHA6Ly9jYS5kZXYubWRsLXBsdXMuY29tL29jc3AvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC9jZXJ0LzAmBgNVHRIEHzAdhhtodHRwczovL2NhLmRldi5tZGwtcGx1cy5jb20wFgYDVR0RBA8wDYILcHJvY2l2aXMuY2gwHQYDVR0OBBYEFKz7jJBlcj4WlpOgMzjKwilDZ_ogMAoGCCqGSM49BAMCA0gAMEUCIDj2w5vOQacNAfIdHmfqlsn0nBpBlbBdC784VT0lqA1FAiEAtCGKf9Pd6dOyz6ke30fFb-YfKaOmbDngZ3dlZIh4dvg#key-0"],
      "capabilityDelegation": ["did:mdl:certificate:MIIDYTCCAwegAwIBAgIUOfrQW7V3t1Df5wF54HMja4jXSiowCgYIKoZIzj0EAwIwYjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMuY29tMB4XDTI0MDUxNDA3MjcwMFoXDTI0MDgxMjAwMDAwMFowSjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxFDASBgNVBAMMC3Byb2NpdmlzLmNoMCowBQYDK2VwAyEA3LOKxB5ik9WikgQmqNFtmuvNC0FMFFVXr6ATVoL-kT6jggHgMIIB3DAOBgNVHQ8BAf8EBAMCB4AwFQYDVR0lAQH_BAswCQYHKIGMXQUBAjAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFO0asJ3iYEVQADvaWjQyGpi-LbfFMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbS9jcmwvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC8wgcgGCCsGAQUFBwEBBIG7MIG4MFoGCCsGAQUFBzAChk5odHRwOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbS9pc3N1ZXIvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC5kZXIwWgYIKwYBBQUHMAGGTmh0dHA6Ly9jYS5kZXYubWRsLXBsdXMuY29tL29jc3AvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC9jZXJ0LzAmBgNVHRIEHzAdhhtodHRwczovL2NhLmRldi5tZGwtcGx1cy5jb20wFgYDVR0RBA8wDYILcHJvY2l2aXMuY2gwHQYDVR0OBBYEFKz7jJBlcj4WlpOgMzjKwilDZ_ogMAoGCCqGSM49BAMCA0gAMEUCIDj2w5vOQacNAfIdHmfqlsn0nBpBlbBdC784VT0lqA1FAiEAtCGKf9Pd6dOyz6ke30fFb-YfKaOmbDngZ3dlZIh4dvg#key-0"]
    });

    assert_eq!(expected, document);
}

#[tokio::test]
async fn test_resolve_did_mdl_public_key() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context
        .api
        .did_resolvers
        .resolve("did:mdl:public_key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv")
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let document = resp.json_value().await;
    assert_eq!(
        document,
        serde_json::json!({
          "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
          ],
          "id":"did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv",
          "verificationMethod": [
            {
              "id": "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv",
              "type": "JsonWebKey2020",
              "controller": "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv",
              "publicKeyJwk": {
                "crv": "P-256",
                "kty": "EC",
                "use": null,
                "x": "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns",
                "y": "efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM"
              }
            }
          ],
          "authentication": ["did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv"],
          "assertionMethod": ["did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv"],
          "keyAgreement": ["did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv"],
          "capabilityInvocation": ["did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv"],
          "capabilityDelegation": ["did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv"],
        })
    )
}
