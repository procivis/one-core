use std::collections::HashMap;
use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use mockall::predicate::eq;
use one_crypto::{MockCryptoProvider, MockHasher};
use shared_types::DidValue;
use time::Duration;

use crate::provider::credential_formatter::common::MockAuth;
use crate::provider::credential_formatter::json_ld::model::ContextType;
use crate::provider::credential_formatter::jwt::model::JWTPayload;
use crate::provider::credential_formatter::model::{
    CredentialStatus, ExtractPresentationCtx, MockTokenVerifier,
};
use crate::provider::credential_formatter::sdjwt::disclosures::DisclosureArray;
use crate::provider::credential_formatter::sdjwt::model::Sdvc;
use crate::provider::credential_formatter::sdjwt::test::get_credential_data;
use crate::provider::credential_formatter::sdjwtvc_formatter::{Params, SDJWTVCFormatter};
use crate::provider::credential_formatter::CredentialFormatter;

#[tokio::test]
async fn test_format_credential_a() {
    let mut hasher = MockHasher::default();
    hasher
        .expect_hash_base64()
        .returning(|_| Ok(String::from("YWJjMTIz")));
    let hasher = Arc::new(hasher);

    let mut crypto = MockCryptoProvider::default();

    crypto
        .expect_get_hasher()
        .with(eq("sha-256"))
        .returning(move |_| Ok(hasher.clone()));

    let leeway = 45u64;

    let sd_formatter = SDJWTVCFormatter::new(
        Params {
            leeway,
            embed_layout_properties: false,
        },
        Arc::new(crypto),
    );

    let credential_data = get_credential_data(
        vec![CredentialStatus {
            id: Some("did:status:id".parse().unwrap()),
            r#type: "TYPE".to_string(),
            status_purpose: Some("PURPOSE".to_string()),
            additional_fields: HashMap::from([("Field1".to_owned(), "Val1".into())]),
        }],
        "http://base_url",
    );

    let auth_fn = MockAuth(|_| vec![65u8, 66, 67]);

    let result = sd_formatter
        .format_credentials(
            credential_data,
            &Some(DidValue::from("holder_did".to_string())),
            "algorithm",
            vec![ContextType::Url("http://context.com".parse().unwrap())],
            vec!["Type1".to_string()],
            Box::new(auth_fn),
        )
        .await;

    assert!(result.is_ok());

    let token = result.unwrap();

    let parts: Vec<&str> = token.splitn(4, '~').collect();

    assert_eq!(parts.len(), 3);

    let part1 = DisclosureArray::from_b64(parts[1]);
    assert_eq!(part1.key, "name");
    assert_eq!(part1.value, "John");

    let part2 = DisclosureArray::from_b64(parts[2]);
    assert_eq!(part2.key, "age");
    assert_eq!(part2.value, "42");

    let jwt_parts: Vec<&str> = parts[0].splitn(3, '.').collect();

    assert_eq!(
        jwt_parts[0],
        &Base64UrlSafeNoPadding::encode_to_string(
            r##"{"alg":"algorithm","kid":"#key0","typ":"vc+sd-jwt"}"##
        )
        .unwrap()
    );
    assert_eq!(
        jwt_parts[2],
        &Base64UrlSafeNoPadding::encode_to_string(r#"ABC"#).unwrap()
    );

    let payload: JWTPayload<Sdvc> = serde_json::from_str(
        &String::from_utf8(Base64UrlSafeNoPadding::decode_to_vec(jwt_parts[1], None).unwrap())
            .unwrap(),
    )
    .unwrap();

    assert_eq!(
        payload.expires_at,
        Some(payload.issued_at.unwrap() + Duration::days(365 * 2)),
    );
    assert_eq!(
        payload.invalid_before,
        Some(payload.issued_at.unwrap() - Duration::seconds(leeway as i64)),
    );

    assert_eq!(payload.issuer, Some(String::from("did:issuer:test")));
    assert_eq!(payload.subject, Some(String::from("holder_did")));

    let vc = payload.custom.vc;

    assert!(vc
        .credential_subject
        .claims
        .iter()
        .all(|hashed_claim| hashed_claim == "YWJjMTIz"));

    assert!(vc
        .context
        .contains(&ContextType::Url("http://context.com".parse().unwrap())));
    assert!(vc.r#type.contains(&String::from("Type1")));

    assert_eq!(1, vc.credential_status.len());
    let first_credential_status = vc.credential_status.first().unwrap();
    assert!(first_credential_status
        .id
        .as_ref()
        .is_some_and(|id| id.as_str() == "did:status:id"));
    assert_eq!(first_credential_status.r#type, "TYPE");
    assert_eq!(
        first_credential_status.status_purpose.as_deref(),
        Some("PURPOSE")
    );
    assert_eq!(
        first_credential_status.additional_fields.get("Field1"),
        Some(&"Val1".into())
    );
}

#[tokio::test]
async fn test_extract_credentials() {
    let jwt_token = "ewogICJhbGciOiAiYWxnb3JpdGhtIiwKICAidHlwIjogInZjK3NkLWp3dCIKfQo.ewogICJpYXQiOiAxNjk5MjcwMjY2LAogICJleHAiOiAxNzYyMzQyMjY2LAogICJuYmYiOiAxNjk5MjcwMjIxLAogICJpc3MiOiAiZGlkOmlzc3Vlcjp0ZXN0IiwKICAic3ViIjogImRpZDpob2xkZXI6dGVzdCIsCiAgImp0aSI6ICI5YTQxNGE2MC05ZTZiLTQ3NTctODAxMS05YWE4NzBlZjQ3ODgiLAogICJ2Y3QiOiAiaHR0cDovLzEyNy4wLjAuMS9zc2kvc2NoZW1hL3YxLzlhNDE0YTYwLTllNmItNDc1Ny04MDExLTlhYTg3MGVmNDc4OCIsCiAgInZjIjogewogICAgIkBjb250ZXh0IjogWwogICAgICAiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLAogICAgICAiaHR0cHM6Ly93d3cudHlwZTEtY29udGV4dC5jb20vdjEiCiAgICBdLAogICAgInR5cGUiOiBbCiAgICAgICJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsCiAgICAgICJUeXBlMSIKICAgIF0sCiAgICAiY3JlZGVudGlhbFN1YmplY3QiOiB7CiAgICAgICJfc2QiOiBbCiAgICAgICAgInJaanl4RjR6RTdmZFJta2NVVDhIa3I4X0lIU0JlczF6MXBaV1AydkxCUkUiLAogICAgICAgICJLR1BsZGxQQjM5NXhLSlJqSzhrMks1VXZzRW5zOVFoTDdPN0pVdTU5RVJrIgogICAgICBdCiAgICB9LAogICAgImNyZWRlbnRpYWxTdGF0dXMiOiB7CiAgICAgICJpZCI6ICJodHRwczovL3d3dy50ZXN0LXZjLmNvbS9zdGF0dXMvaWQiLAogICAgICAidHlwZSI6ICJUWVBFIiwKICAgICAgInN0YXR1c1B1cnBvc2UiOiAiUFVSUE9TRSIsCiAgICAgICJGaWVsZDEiOiAiVmFsMSIKICAgIH0KICB9LAogICJfc2RfYWxnIjogInNoYS0yNTYiCn0gCg";
    let token = format!(
        "{jwt_token}.QUJD~WyJNVEl6WVdKaiIsIm5hbWUiLCJKb2huIl0~WyJNVEl6WVdKaiIsImFnZSIsIjQyIl0"
    );

    let claim1 = "[\"MTIzYWJj\",\"name\",\"John\"]";
    let claim2 = "[\"MTIzYWJj\",\"age\",\"42\"]";

    let mut hasher = MockHasher::default();
    hasher
        .expect_hash_base64()
        .with(eq(claim1.as_bytes()))
        .returning(|_| Ok("rZjyxF4zE7fdRmkcUT8Hkr8_IHSBes1z1pZWP2vLBRE".to_string()));
    hasher
        .expect_hash_base64()
        .with(eq(claim2.as_bytes()))
        .returning(|_| Ok("KGPldlPB395xKJRjK8k2K5UvsEns9QhL7O7JUu59ERk".to_string()));
    let hasher = Arc::new(hasher);

    let mut crypto = MockCryptoProvider::default();

    crypto
        .expect_get_hasher()
        .once()
        .with(eq("sha-256"))
        .returning(move |_| Ok(hasher.clone()));

    let leeway = 45u64;

    let sd_formatter = SDJWTVCFormatter::new(
        Params {
            leeway,
            embed_layout_properties: false,
        },
        Arc::new(crypto),
    );

    let mut verify_mock = MockTokenVerifier::new();

    verify_mock
        .expect_verify()
        .withf(
            move |issuer_did_value, _key_id, algorithm, token, signature| {
                assert_eq!(
                    "did:issuer:test",
                    issuer_did_value.as_ref().unwrap().as_str()
                );
                assert_eq!("algorithm", algorithm);
                assert_eq!(jwt_token.as_bytes(), token);
                assert_eq!(vec![65u8, 66, 67], signature);
                true
            },
        )
        .return_once(|_, _, _, _, _| Ok(()));

    let result = sd_formatter
        .extract_credentials(&token, Box::new(verify_mock))
        .await;

    let credentials = result.unwrap();

    assert_eq!(
        credentials.issuer_did,
        Some(DidValue::from("did:issuer:test".to_string()))
    );
    assert_eq!(
        credentials.subject,
        Some(DidValue::from("did:holder:test".to_string()))
    );

    assert_eq!(1, credentials.status.len());
    let first_credential_status = credentials.status.first().unwrap();
    assert!(first_credential_status
        .id
        .as_ref()
        .is_some_and(|id| id.as_str() == "https://www.test-vc.com/status/id"));
    assert_eq!(first_credential_status.r#type, "TYPE");
    assert_eq!(
        first_credential_status.status_purpose.as_deref(),
        Some("PURPOSE")
    );
    assert_eq!(
        first_credential_status.additional_fields.get("Field1"),
        Some(&"Val1".into())
    );

    assert_eq!(credentials.claims.values.get("name").unwrap(), "John");
    assert_eq!(credentials.claims.values.get("age").unwrap(), "42");
}

#[tokio::test]
async fn test_extract_presentation() {
    let jwt_token = "eyJhbGciOiJhbGdvcml0aG0iLCJ0eXAiOiJ2YytzZC1qd3QifSAK.eyJpYXQiOjE2OT\
    kzNTE4NDEsImV4cCI6MTY5OTM1MjE0MSwibmJmIjoxNjk5MzUxNzk2LCJpc3MiOiJob2xkZXJfZGlkIiwic3ViIjoia\
    G9sZGVyX2RpZCIsImp0aSI6ImI0Y2M0OWQ1LThkMGUtNDgxZS1iMWViLThlNGU4Yjk2OTZiMSIsInZwIjp7IkBjb250\
    ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZVB\
    yZXNlbnRhdGlvbiJdLCJfc2Rfand0IjpbImV5SmhiR2NpT2lKaGJHZHZjbWwwYUcwaUxDSjBlWEFpT2lKVFJFcFhWQ0\
    o5LmV5SnBZWFFpT2pFMk9Ua3lOekF5TmpZc0ltVjRjQ0k2TVRjMk1qTTBNakkyTml3aWJtSm1Jam94TmprNU1qY3dNa\
    kl4TENKcGMzTWlPaUpKYzNOMVpYSWdSRWxFSWl3aWMzVmlJam9pYUc5c1pHVnlYMlJwWkNJc0ltcDBhU0k2SWpsaE5E\
    RTBZVFl3TFRsbE5tSXRORGMxTnkwNE1ERXhMVGxoWVRnM01HVm1ORGM0T0NJc0luWmpJanA3SWtCamIyNTBaWGgwSWp\
    wYkltaDBkSEJ6T2k4dmQzZDNMbmN6TG05eVp5OHlNREU0TDJOeVpXUmxiblJwWVd4ekwzWXhJaXdpUTI5dWRHVjRkRE\
    VpWFN3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbFI1Y0dVeElsMHNJbU55WldSbGJuU\
    nBZV3hUZFdKcVpXTjBJanA3SWw5elpDSTZXeUpaVjBwcVRWUkplaUlzSWxsWFNtcE5WRWw2SWwxOUxDSmpjbVZrWlc1\
    MGFXRnNVM1JoZEhWeklqcDdJbWxrSWpvaVUxUkJWRlZUWDBsRUlpd2lkSGx3WlNJNklsUlpVRVVpTENKemRHRjBkWE5\
    RZFhKd2IzTmxJam9pVUZWU1VFOVRSU0lzSWtacFpXeGtNU0k2SWxaaGJERWlmWDBzSWw5elpGOWhiR2NpT2lKemFHRX\
    RNalUySW4wLlFVSkR-V3lKTlZFbDZXVmRLYWlJc0ltNWhiV1VpTENKS2IyaHVJbDB-V3lKTlZFbDZXVmRLYWlJc0ltR\
    m5aU0lzSWpReUlsMCJdfX0";
    let presentation_token = format!("{jwt_token}.QUJD");

    let crypto = MockCryptoProvider::default();

    let leeway = 45u64;

    let sd_formatter = SDJWTVCFormatter::new(
        Params {
            leeway,
            embed_layout_properties: false,
        },
        Arc::new(crypto),
    );

    let mut verify_mock = MockTokenVerifier::new();

    verify_mock
        .expect_verify()
        .withf(
            move |issuer_did_value, _key_id, algorithm, token, signature| {
                assert_eq!("holder_did", issuer_did_value.as_ref().unwrap().as_str());
                assert_eq!("algorithm", algorithm);
                assert_eq!(jwt_token.as_bytes(), token);
                assert_eq!(vec![65u8, 66, 67], signature);
                true
            },
        )
        .return_once(|_, _, _, _, _| Ok(()));

    let result = sd_formatter
        .extract_presentation(
            &presentation_token,
            Box::new(verify_mock),
            ExtractPresentationCtx::default(),
        )
        .await;

    assert!(result.is_ok());

    let presentation = result.unwrap();

    assert_eq!(
        presentation.expires_at,
        Some(presentation.issued_at.unwrap() + Duration::minutes(5)),
    );

    assert_eq!(presentation.credentials.len(), 1);
    assert_eq!(
        presentation.issuer_did,
        Some(DidValue::from("holder_did".to_string()))
    );
}
