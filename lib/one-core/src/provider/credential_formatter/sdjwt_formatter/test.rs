use std::collections::HashMap;
use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use mockall::predicate::eq;
use serde_json::json;
use shared_types::DidValue;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::disclosures::DisclosureArray;
use super::{prepare_sd_presentation, verify_claims, SDJWTFormatter};
use crate::crypto::hasher::sha256::SHA256;
use crate::crypto::{MockCryptoProvider, MockHasher};
#[cfg(test)]
use crate::provider::credential_formatter::common::MockAuth;
use crate::provider::credential_formatter::json_ld::model::ContextType;
use crate::provider::credential_formatter::jwt::model::JWTPayload;
use crate::provider::credential_formatter::model::{
    CredentialData, CredentialPresentation, CredentialSchemaData, CredentialStatus,
    ExtractPresentationCtx, Issuer, MockTokenVerifier, PublishedClaim, PublishedClaimValue,
};
use crate::provider::credential_formatter::sdjwt_formatter::disclosures::{
    extract_claims_from_disclosures, gather_disclosures, get_disclosures_by_claim_name,
    get_subdisclosures, parse_disclosure, sort_published_claims_by_indices,
};
use crate::provider::credential_formatter::sdjwt_formatter::{Disclosure, Params, Sdvc};
use crate::provider::credential_formatter::CredentialFormatter;

impl From<&str> for DisclosureArray {
    fn from(value: &str) -> Self {
        serde_json::from_str(value).unwrap()
    }
}

impl DisclosureArray {
    fn from_b64(value: &str) -> Self {
        let part_decoded = Base64UrlSafeNoPadding::decode_to_vec(value, None).unwrap();
        serde_json::from_slice(&part_decoded).unwrap()
    }
}

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

    let sd_formatter = SDJWTFormatter {
        crypto: Arc::new(crypto),
        params: Params {
            leeway,
            embed_layout_properties: false,
        },
    };

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
            None,
            None,
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
            r##"{"alg":"algorithm","kid":"#key0","typ":"SDJWT"}"##
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
async fn test_format_credential_with_array() {
    let claim1 = ("array", "[\"array_item\"]");
    let claim2 = ("nested", "nested_item");
    let claim3 = ("root", "{\"_sd\":[\"MPQIfncdJvNwYLbpw4L0lU9MEK_bYA9JDVGO7qb0abs\",\"r69eqe07S9rE27Ing-l997ofg85RS_nRuVXucVQ9Ehw\"]}");
    let claim4 = ("root_item", "root_item");

    let hash1 = "MPQIfncdJvNwYLbpw4L0lU9MEK_bYA9JDVGO7qb0abs";
    let hash2 = "r69eqe07S9rE27Ing-l997ofg85RS_nRuVXucVQ9Ehw";
    let hash3 = "sadrIPfvvuqIBTdMxsmvGh77Z89M3JyX2qQQEGzmkYg";
    let hash4 = "GBcm8QZO2Pr4n_jmJlP4By1iwcoU0eQDVhin2AidMq4";

    let mut hasher = MockHasher::default();
    hasher.expect_hash_base64().returning(move |input| {
        let input = DisclosureArray::from(std::str::from_utf8(input).unwrap());
        if input.key.eq(claim1.0) {
            Ok(hash1.to_string())
        } else if input.key.eq(claim2.0) {
            Ok(hash2.to_string())
        } else if input.key.eq(claim3.0) {
            Ok(hash3.to_string())
        } else if input.key.eq(claim4.0) {
            Ok(hash4.to_string())
        } else {
            panic!("Unexpected input")
        }
    });

    let hasher: Arc<MockHasher> = Arc::new(hasher);

    let mut crypto = MockCryptoProvider::default();

    crypto
        .expect_get_hasher()
        .times(2)
        .with(eq("sha-256"))
        .returning(move |_| Ok(hasher.clone()));

    let leeway = 45u64;

    let sd_formatter = SDJWTFormatter {
        crypto: Arc::new(crypto),
        params: Params {
            leeway,
            embed_layout_properties: false,
        },
    };

    let credential_data = get_credential_data_with_array(
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
            None,
            None,
        )
        .await;

    assert!(result.is_ok());

    let token = result.unwrap();

    let parts: Vec<&str> = token.split('~').collect();
    assert_eq!(parts.len(), 5);

    let part = DisclosureArray::from_b64(parts[1]);
    assert_eq!(part.key, claim1.0);
    assert_eq!(part.value, claim1.1);

    let part = DisclosureArray::from_b64(parts[2]);
    assert_eq!(part.key, claim2.0);
    assert_eq!(part.value, claim2.1);

    let part = DisclosureArray::from_b64(parts[3]);
    assert_eq!(part.key, claim3.0);
    assert_eq!(part.value.to_string(), claim3.1);

    let part = DisclosureArray::from_b64(parts[4]);
    assert_eq!(part.key, claim4.0);
    assert_eq!(part.value, claim4.1);

    let jwt_parts: Vec<&str> = parts[0].splitn(3, '.').collect();

    assert_eq!(
        jwt_parts[0],
        &Base64UrlSafeNoPadding::encode_to_string(
            r##"{"alg":"algorithm","kid":"#key0","typ":"SDJWT"}"##
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

    assert_eq!(payload.issuer, Some(String::from("did:issuer:test")));
    assert_eq!(payload.subject, Some(String::from("holder_did")));

    let vc = payload.custom.vc;

    assert_eq!(vec![hash4, hash3], vc.credential_subject.claims);
}

#[tokio::test]
async fn test_extract_credentials() {
    let jwt_token = "ewogICJhbGciOiAiYWxnb3JpdGhtIiwKICAidHlwIjogIlNESldUIgp9.ewogICJpYXQiOiAxNjk5MjcwMjY2LAogICJleHAiOiAxNzYyMzQyMjY2LAogICJuYmYiOiAxNjk5MjcwMjIxLAogICJpc3MiOiAiZGlkOmlzc3Vlcjp0ZXN0IiwKICAic3ViIjogImRpZDpob2xkZXI6dGVzdCIsCiAgImp0aSI6ICI5YTQxNGE2MC05ZTZiLTQ3NTctODAxMS05YWE4NzBlZjQ3ODgiLAogICJ2YyI6IHsKICAgICJAY29udGV4dCI6IFsKICAgICAgImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwKICAgICAgImh0dHBzOi8vd3d3LnR5cGUxLWNvbnRleHQuY29tL3YxIgogICAgXSwKICAgICJ0eXBlIjogWwogICAgICAiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLAogICAgICAiVHlwZTEiCiAgICBdLAogICAgImNyZWRlbnRpYWxTdWJqZWN0IjogewogICAgICAiX3NkIjogWwogICAgICAgICJyWmp5eEY0ekU3ZmRSbWtjVVQ4SGtyOF9JSFNCZXMxejFwWldQMnZMQlJFIiwKICAgICAgICAiS0dQbGRsUEIzOTV4S0pSaks4azJLNVV2c0VuczlRaEw3TzdKVXU1OUVSayIKICAgICAgXQogICAgfSwKICAgICJjcmVkZW50aWFsU3RhdHVzIjogewogICAgICAiaWQiOiAiaHR0cHM6Ly93d3cudGVzdC12Yy5jb20vc3RhdHVzL2lkIiwKICAgICAgInR5cGUiOiAiVFlQRSIsCiAgICAgICJzdGF0dXNQdXJwb3NlIjogIlBVUlBPU0UiLAogICAgICAiRmllbGQxIjogIlZhbDEiCiAgICB9CiAgfSwKICAiX3NkX2FsZyI6ICJzaGEtMjU2Igp9";
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

    let sd_formatter = SDJWTFormatter {
        crypto: Arc::new(crypto),
        params: Params {
            leeway,
            embed_layout_properties: false,
        },
    };

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
async fn test_extract_credentials_with_array() {
    let jwt_token = "ewogICJhbGciOiAiYWxnb3JpdGhtIiwKICAia2lkIjogIiNrZXkwIiwKICAidHlwIjogIlNESldUIgp9.ewogICJpYXQiOiAxNzE4MzU5MDYzLAogICJleHAiOiAxNzgxNDMxMDYzLAogICJuYmYiOiAxNzE4MzU5MDE4LAogICJpc3MiOiAiSXNzdWVyIERJRCIsCiAgInN1YiI6ICJob2xkZXJfZGlkIiwKICAianRpIjogImh0dHA6Ly9iYXNlX3VybC9zc2kvY3JlZGVudGlhbC92MS85YTQxNGE2MC05ZTZiLTQ3NTctODAxMS05YWE4NzBlZjQ3ODgiLAogICJ2YyI6IHsKICAgICJAY29udGV4dCI6IFsKICAgICAgImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwKICAgICAgImh0dHBzOi8vd3d3LnRlc3Rjb250ZXh0LmNvbS92MSIKICAgIF0sCiAgICAiaWQiOiAiaHR0cDovL2Jhc2VfdXJsL3NzaS9jcmVkZW50aWFsL3YxLzlhNDE0YTYwLTllNmItNDc1Ny04MDExLTlhYTg3MGVmNDc4OCIsCiAgICAidHlwZSI6IFsKICAgICAgIlZlcmlmaWFibGVDcmVkZW50aWFsIiwKICAgICAgIlR5cGUxIgogICAgXSwKICAgICJjcmVkZW50aWFsU3ViamVjdCI6IHsKICAgICAgIl9zZCI6IFsKICAgICAgICAicERPZTlDQ2hNLVlSZ0hCSUx5VDFrUFRCbUNxYnJBZWt0MnhPSkxiOEhFcyIsCiAgICAgICAgIkdCY204UVpPMlByNG5fam1KbFA0QnkxaXdjb1UwZVFEVmhpbjJBaWRNcTQiCiAgICAgIF0KICAgIH0sCiAgICAiY3JlZGVudGlhbFN0YXR1cyI6IHsKICAgICAgImlkIjogImh0dHBzOi8vcHJvY2l2aXMuY2gvc3RhdHVzL2lkIiwKICAgICAgInR5cGUiOiAiVFlQRSIsCiAgICAgICJzdGF0dXNQdXJwb3NlIjogIlBVUlBPU0UiCiAgICB9LAogICAgImNyZWRlbnRpYWxTY2hlbWEiOiB7CiAgICAgICJpZCI6ICJodHRwczovL3Byb2NpdmlzLmNoL2NyZWRlbnRpYWwtc2NoZW1hL2lkIiwKICAgICAgInR5cGUiOiAiUHJvY2l2aXNPbmVTY2hlbWEyMDI0IgogICAgfQogIH0sCiAgIl9zZF9hbGciOiAic2hhLTI1NiIKfQ";
    let token = format!(
        "{jwt_token}.QUJD~WyJNVEl6WVdKaiIsImFycmF5IixbImFycmF5X2l0ZW0iXV0~WyJNVEl6WVdKaiIs\
            Im5lc3RlZCIsIm5lc3RlZF9pdGVtIl0~WyJNVEl6WVdKaiIsInJvb3QiLHsiX3NkIjpbIldRbmQycW\
            xNa3U3RzVJdE01M1FSdmRVZjRHYWNYR3pMV3ZUTl93RGhhcmMiLCJyNjllcWUwN1M5ckUyN0luZy1s\
            OTk3b2ZnODVSU19uUnVWWHVjVlE5RWh3Il19XQ~WyJNVEl6WVdKaiIsInJvb3RfaXRlbSIsInJvb3R\
            faXRlbSJd"
    );

    let claim1 = "[\"MTIzYWJj\",\"array\",[\"array_item\"]]";
    let claim2 = "[\"MTIzYWJj\",\"nested\",\"nested_item\"]";
    let claim3 = "[\"MTIzYWJj\",\"root\",{\"_sd\":[\"WQnd2qlMku7G5ItM53QRvdUf4GacXGzLWvTN_wDharc\",\"r69eqe07S9rE27Ing-l997ofg85RS_nRuVXucVQ9Ehw\"]}]";
    let claim4 = "[\"MTIzYWJj\",\"root_item\",\"root_item\"]";

    let mut hasher = MockHasher::default();
    hasher
        .expect_hash_base64()
        .with(eq(claim1.as_bytes()))
        .returning(|_| Ok("WQnd2qlMku7G5ItM53QRvdUf4GacXGzLWvTN_wDharc".to_string()));
    hasher
        .expect_hash_base64()
        .with(eq(claim2.as_bytes()))
        .returning(|_| Ok("r69eqe07S9rE27Ing-l997ofg85RS_nRuVXucVQ9Ehw".to_string()));
    hasher
        .expect_hash_base64()
        .with(eq(claim3.as_bytes()))
        .returning(|_| Ok("pDOe9CChM-YRgHBILyT1kPTBmCqbrAekt2xOJLb8HEs".to_string()));
    hasher
        .expect_hash_base64()
        .with(eq(claim4.as_bytes()))
        .returning(|_| Ok("GBcm8QZO2Pr4n_jmJlP4By1iwcoU0eQDVhin2AidMq4".to_string()));
    let hasher = Arc::new(hasher);

    let mut crypto = MockCryptoProvider::default();

    crypto
        .expect_get_hasher()
        .once()
        .with(eq("sha-256"))
        .returning(move |_| Ok(hasher.clone()));

    let leeway = 45u64;

    let sd_formatter = SDJWTFormatter {
        crypto: Arc::new(crypto),
        params: Params {
            leeway,
            embed_layout_properties: false,
        },
    };

    let mut verify_mock = MockTokenVerifier::new();

    verify_mock
        .expect_verify()
        .withf(
            move |issuer_did_value, _key_id, algorithm, token, signature| {
                assert_eq!("Issuer DID", issuer_did_value.as_ref().unwrap().as_str());
                assert_eq!("algorithm", algorithm);
                assert_eq!(jwt_token.as_bytes(), token);
                assert_eq!(vec![65u8, 66, 67], signature);
                true
            },
        )
        .return_once(|_, _, _, _, _| Ok(()));

    let credentials = sd_formatter
        .extract_credentials(&token, Box::new(verify_mock))
        .await
        .unwrap();

    let root_item = credentials.claims.values.get("root_item").unwrap();
    assert_eq!(root_item.as_str(), Some("root_item"));

    let root = credentials.claims.values.get("root").unwrap();
    let nested = root.get("nested").unwrap();
    assert_eq!(nested.as_str(), Some("nested_item"));

    let array = root.get("array").unwrap().as_array().unwrap();
    assert_eq!(array[0].as_str(), Some("array_item"));
}

#[tokio::test]
async fn test_extract_credentials_with_array_stripped() {
    let jwt_token = "ewogICJhbGciOiAiYWxnb3JpdGhtIiwKICAia2lkIjogIiNrZXkwIiwKICAidHlwIjogIlNESldUIgp9.ewogICJpYXQiOiAxNzE4MzU5MDYzLAogICJleHAiOiAxNzgxNDMxMDYzLAogICJuYmYiOiAxNzE4MzU5MDE4LAogICJpc3MiOiAiSXNzdWVyIERJRCIsCiAgInN1YiI6ICJob2xkZXJfZGlkIiwKICAianRpIjogImh0dHA6Ly9iYXNlX3VybC9zc2kvY3JlZGVudGlhbC92MS85YTQxNGE2MC05ZTZiLTQ3NTctODAxMS05YWE4NzBlZjQ3ODgiLAogICJ2YyI6IHsKICAgICJAY29udGV4dCI6IFsKICAgICAgImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwKICAgICAgImh0dHBzOi8vd3d3LnR5cGUxY3R4Lm9yZyIKICAgIF0sCiAgICAiaWQiOiAiaHR0cDovL2Jhc2VfdXJsL3NzaS9jcmVkZW50aWFsL3YxLzlhNDE0YTYwLTllNmItNDc1Ny04MDExLTlhYTg3MGVmNDc4OCIsCiAgICAidHlwZSI6IFsKICAgICAgIlZlcmlmaWFibGVDcmVkZW50aWFsIiwKICAgICAgIlR5cGUxIgogICAgXSwKICAgICJjcmVkZW50aWFsU3ViamVjdCI6IHsKICAgICAgIl9zZCI6IFsKICAgICAgICAicERPZTlDQ2hNLVlSZ0hCSUx5VDFrUFRCbUNxYnJBZWt0MnhPSkxiOEhFcyIsCiAgICAgICAgIkdCY204UVpPMlByNG5fam1KbFA0QnkxaXdjb1UwZVFEVmhpbjJBaWRNcTQiCiAgICAgIF0KICAgIH0sCiAgICAiY3JlZGVudGlhbFN0YXR1cyI6IHsKICAgICAgImlkIjogImh0dHBzOi8vcHJvY2l2aXMuY2gvc3RhdHVzL2lkIiwKICAgICAgInR5cGUiOiAiVFlQRSIsCiAgICAgICJzdGF0dXNQdXJwb3NlIjogIlBVUlBPU0UiCiAgICB9LAogICAgImNyZWRlbnRpYWxTY2hlbWEiOiB7CiAgICAgICJpZCI6ICJodHRwczovL3Byb2NpdmlzLmNoL2NyZWRlbnRpYWwtc2NoZW1hL2lkIiwKICAgICAgInR5cGUiOiAiUHJvY2l2aXNPbmVTY2hlbWEyMDI0IgogICAgfQogIH0sCiAgIl9zZF9hbGciOiAic2hhLTI1NiIKfQ";
    let token = format!(
        "{jwt_token}.QUJD~WyJNVEl6WVdKaiIsImFycmF5IixbImFycmF5X2l0ZW0iXV0~WyJNVEl6WVdKaiIsInJvb3QiLHsiX3NkIjpbIldRbmQycW\
            xNa3U3RzVJdE01M1FSdmRVZjRHYWNYR3pMV3ZUTl93RGhhcmMiLCJyNjllcWUwN1M5ckUyN0luZy1s\
            OTk3b2ZnODVSU19uUnVWWHVjVlE5RWh3Il19XQ~WyJNVEl6WVdKaiIsInJvb3RfaXRlbSIsInJvb3R\
            faXRlbSJd"
    );

    let claim1 = "[\"MTIzYWJj\",\"array\",[\"array_item\"]]";
    let claim2 = "[\"MTIzYWJj\",\"nested\",\"nested_item\"]";
    let claim3 = "[\"MTIzYWJj\",\"root\",{\"_sd\":[\"WQnd2qlMku7G5ItM53QRvdUf4GacXGzLWvTN_wDharc\",\"r69eqe07S9rE27Ing-l997ofg85RS_nRuVXucVQ9Ehw\"]}]";
    let claim4 = "[\"MTIzYWJj\",\"root_item\",\"root_item\"]";

    let mut hasher = MockHasher::default();
    hasher
        .expect_hash_base64()
        .with(eq(claim1.as_bytes()))
        .returning(|_| Ok("WQnd2qlMku7G5ItM53QRvdUf4GacXGzLWvTN_wDharc".to_string()));
    hasher
        .expect_hash_base64()
        .never()
        .with(eq(claim2.as_bytes()))
        .returning(|_| Ok("r69eqe07S9rE27Ing-l997ofg85RS_nRuVXucVQ9Ehw".to_string()));
    hasher
        .expect_hash_base64()
        .with(eq(claim3.as_bytes()))
        .returning(|_| Ok("pDOe9CChM-YRgHBILyT1kPTBmCqbrAekt2xOJLb8HEs".to_string()));
    hasher
        .expect_hash_base64()
        .with(eq(claim4.as_bytes()))
        .returning(|_| Ok("GBcm8QZO2Pr4n_jmJlP4By1iwcoU0eQDVhin2AidMq4".to_string()));
    let hasher = Arc::new(hasher);

    let mut crypto = MockCryptoProvider::default();

    crypto
        .expect_get_hasher()
        .once()
        .with(eq("sha-256"))
        .returning(move |_| Ok(hasher.clone()));

    let leeway = 45u64;

    let sd_formatter = SDJWTFormatter {
        crypto: Arc::new(crypto),
        params: Params {
            leeway,
            embed_layout_properties: false,
        },
    };

    let mut verify_mock = MockTokenVerifier::new();

    verify_mock
        .expect_verify()
        .withf(
            move |issuer_did_value, _key_id, algorithm, token, signature| {
                assert_eq!("Issuer DID", issuer_did_value.as_ref().unwrap().as_str());
                assert_eq!("algorithm", algorithm);
                assert_eq!(jwt_token.as_bytes(), token);
                assert_eq!(vec![65u8, 66, 67], signature);
                true
            },
        )
        .return_once(|_, _, _, _, _| Ok(()));

    let credentials = sd_formatter
        .extract_credentials(&token, Box::new(verify_mock))
        .await
        .unwrap();

    let root_item = credentials.claims.values.get("root_item").unwrap();
    assert_eq!(root_item.as_str(), Some("root_item"));

    let root = credentials.claims.values.get("root").unwrap();
    assert!(root.get("nested").is_none());

    let array = root.get("array").unwrap().as_array().unwrap();
    assert_eq!(array[0].as_str(), Some("array_item"));
}

#[tokio::test]
async fn test_extract_presentation() {
    let jwt_token = "eyJhbGciOiJhbGdvcml0aG0iLCJ0eXAiOiJTREpXVCJ9.eyJpYXQiOjE2OT\
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

    let sd_formatter = SDJWTFormatter {
        crypto: Arc::new(crypto),
        params: Params {
            leeway,
            embed_layout_properties: false,
        },
    };

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

#[test]
fn test_prepare_sd_presentation() {
    let claim1 = "[\"MTIzYWJj\",\"name\",\"John\"]";
    let claim2 = "[\"MTIzYWJj\",\"age\",\"42\"]";

    let mut hasher = MockHasher::default();
    hasher
        .expect_hash_base64()
        .times(4)
        .with(eq(claim1.as_bytes()))
        .returning(|_| Ok("rZjyxF4zE7fdRmkcUT8Hkr8_IHSBes1z1pZWP2vLBRE".to_string()));
    hasher
        .expect_hash_base64()
        .times(4)
        .with(eq(claim2.as_bytes()))
        .returning(|_| Ok("KGPldlPB395xKJRjK8k2K5UvsEns9QhL7O7JUu59ERk".to_string()));
    let hasher = Arc::new(hasher);

    let mut crypto = MockCryptoProvider::default();

    crypto
        .expect_get_hasher()
        .with(eq("sha-256"))
        .returning(move |_| Ok(hasher.clone()));

    let jwt_token = "ewogICJhbGciOiAiYWxnb3JpdGhtIiwKICAidHlwIjogIlNESldUIgp9.ewogICJpYXQiOiAxNjk5MjcwMjY2LAogICJleHAiOiAxNzYyMzQyMjY2LAogICJuYmYiOiAxNjk5MjcwMjIxLAogICJpc3MiOiAiZGlkOmlzc3Vlcjp0ZXN0IiwKICAic3ViIjogImRpZDpob2xkZXI6dGVzdCIsCiAgImp0aSI6ICI5YTQxNGE2MC05ZTZiLTQ3NTctODAxMS05YWE4NzBlZjQ3ODgiLAogICJ2YyI6IHsKICAgICJAY29udGV4dCI6IFsKICAgICAgImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwKICAgICAgImh0dHBzOi8vd3d3LnRlc3Rjb250ZXh0LmNvbS92MSIKICAgIF0sCiAgICAidHlwZSI6IFsKICAgICAgIlZlcmlmaWFibGVDcmVkZW50aWFsIiwKICAgICAgIlR5cGUxIgogICAgXSwKICAgICJjcmVkZW50aWFsU3ViamVjdCI6IHsKICAgICAgIl9zZCI6IFsKICAgICAgICAiWVdKak1USXoiLAogICAgICAgICJZV0pqTVRJeiIKICAgICAgXQogICAgfSwKICAgICJjcmVkZW50aWFsU3RhdHVzIjogewogICAgICAiaWQiOiAiZGlkOnN0YXR1czppZCIsCiAgICAgICJ0eXBlIjogIlRZUEUiLAogICAgICAic3RhdHVzUHVycG9zZSI6ICJQVVJQT1NFIiwKICAgICAgIkZpZWxkMSI6ICJWYWwxIgogICAgfQogIH0sCiAgIl9zZF9hbGciOiAic2hhLTI1NiIKfQ";

    let key_name = "WyJNVEl6WVdKaiIsIm5hbWUiLCJKb2huIl0";
    let key_age = "WyJNVEl6WVdKaiIsImFnZSIsIjQyIl0";

    let token = format!("{jwt_token}.QUJD~{key_name}~{key_age}");

    // Take name and age
    let presentation = CredentialPresentation {
        token: token.clone(),
        disclosed_keys: vec!["name".to_string(), "age".to_string()],
    };

    let result = prepare_sd_presentation(presentation, &crypto);
    assert!(result.is_ok_and(|token| token.contains(key_name) && token.contains(key_age)));

    // Take name
    let presentation = CredentialPresentation {
        token: token.clone(),
        disclosed_keys: vec!["name".to_string()],
    };

    let result = prepare_sd_presentation(presentation, &crypto);
    assert!(result.is_ok_and(|token| token.contains(key_name) && !token.contains(key_age)));

    // Take age
    let presentation = CredentialPresentation {
        token: token.clone(),
        disclosed_keys: vec!["age".to_string()],
    };

    let result = prepare_sd_presentation(presentation, &crypto);
    assert!(result.is_ok_and(|token| !token.contains(key_name) && token.contains(key_age)));

    // Take none
    let presentation = CredentialPresentation {
        token,
        disclosed_keys: vec![],
    };

    let result = prepare_sd_presentation(presentation, &crypto);
    assert!(result.is_ok_and(|token| !token.contains(key_name) && !token.contains(key_age)));
}

#[test]
fn test_get_capabilities() {
    let sd_formatter = SDJWTFormatter {
        crypto: Arc::new(MockCryptoProvider::default()),
        params: Params {
            leeway: 123u64,
            embed_layout_properties: false,
        },
    };

    assert_eq!(
        vec![
            "SELECTIVE_DISCLOSURE".to_string(),
            "SUPPORTS_CREDENTIAL_DESIGN".to_string()
        ],
        sd_formatter.get_capabilities().features
    );
}

#[test]
fn test_gather_disclosures_and_objects_without_nesting() {
    let algorithm = "sha-256";

    let street_address_disclosure = ("street_address", "Schulstr. 12");
    let hashed_b64_street_address_disclosure = "9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM";

    let locality_disclosure = ("locality", "Schulpforta");
    let hashed_b64_locality_disclosure = "6vh9bq-zS4GKM_7GpggVbYzzu6oOGXrmNVGPHP75Ud0";

    let region_disclosure = ("region", "Sachsen-Anhalt");
    let hashed_b64_region_disclosure = "KURDPh4ZC19-3tiz-Df39V8eidy1oV3a3H1Da2N0g88";

    let country_disclosure = ("country", "DE");
    let hashed_b64_country_disclosure = "WN9r9dCBJ8HTCsS2jKASxTjEyW5m5x65_Z_2ro2jfXM";

    let mut hasher = MockHasher::default();
    hasher.expect_hash_base64().returning(move |input| {
        let input = DisclosureArray::from(std::str::from_utf8(input).unwrap());
        if input.key.eq(street_address_disclosure.0) {
            Ok(hashed_b64_street_address_disclosure.to_string())
        } else if input.key.eq(locality_disclosure.0) {
            Ok(hashed_b64_locality_disclosure.to_string())
        } else if input.key.eq(region_disclosure.0) {
            Ok(hashed_b64_region_disclosure.to_string())
        } else if input.key.eq(country_disclosure.0) {
            Ok(hashed_b64_country_disclosure.to_string())
        } else {
            panic!("Unexpected input")
        }
    });
    let hasher = Arc::new(hasher);

    let mut crypto = MockCryptoProvider::default();
    crypto
        .expect_get_hasher()
        .with(eq(algorithm))
        .returning(move |_| Ok(hasher.clone()));

    let test_json = json!({
        "street_address": "Schulstr. 12",
        "locality": "Schulpforta",
        "region": "Sachsen-Anhalt",
        "country": "DE"
    });

    let (disclosures, result) = gather_disclosures(&test_json, algorithm, &crypto).unwrap();
    let disclosures: Vec<_> = disclosures
        .iter()
        .map(|val| DisclosureArray::from_b64(val))
        .collect();
    let expected_disclosures = &[
        street_address_disclosure,
        locality_disclosure,
        region_disclosure,
        country_disclosure,
    ];
    let expected_result = vec![
        hashed_b64_street_address_disclosure,
        hashed_b64_locality_disclosure,
        hashed_b64_region_disclosure,
        hashed_b64_country_disclosure,
    ];

    assert!(expected_disclosures.iter().all(|expected| {
        disclosures
            .iter()
            .any(|disc| disc.key == expected.0 && disc.value.to_string().contains(expected.1))
    }));
    assert_eq!(expected_result, result);
}

#[test]
fn test_gather_disclosures_and_objects_with_nesting() {
    let algorithm = "sha-256";

    let street_address_disclosure = ("street_address", "Schulstr. 12");
    let hashed_b64_street_address_disclosure = "9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM";

    let locality_disclosure = ("locality", "Schulpforta");
    let hashed_b64_locality_disclosure = "6vh9bq-zS4GKM_7GpggVbYzzu6oOGXrmNVGPHP75Ud0";

    let region_disclosure = ("region", "Sachsen-Anhalt");
    let hashed_b64_region_disclosure = "KURDPh4ZC19-3tiz-Df39V8eidy1oV3a3H1Da2N0g88";

    let country_disclosure = ("country", "DE");
    let hashed_b64_country_disclosure = "WN9r9dCBJ8HTCsS2jKASxTjEyW5m5x65_Z_2ro2jfXM";

    let address_disclosure = ("address", "{\"_sd\":[\"9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM\",\"6vh9bq-zS4GKM_7GpggVbYzzu6oOGXrmNVGPHP75Ud0\",\"KURDPh4ZC19-3tiz-Df39V8eidy1oV3a3H1Da2N0g88\",\"WN9r9dCBJ8HTCsS2jKASxTjEyW5m5x65_Z_2ro2jfXM\"]}");
    let hashed_b64_address_disclosure = "HvrKX6fPV0v9K_yCVFBiLFHsMaxcD_114Em6VT8x1lg";

    let mut hasher = MockHasher::default();
    hasher.expect_hash_base64().returning(move |input| {
        let input = DisclosureArray::from(std::str::from_utf8(input).unwrap());
        if input.key.eq(street_address_disclosure.0) {
            Ok(hashed_b64_street_address_disclosure.to_string())
        } else if input.key.eq(locality_disclosure.0) {
            Ok(hashed_b64_locality_disclosure.to_string())
        } else if input.key.eq(region_disclosure.0) {
            Ok(hashed_b64_region_disclosure.to_string())
        } else if input.key.eq(country_disclosure.0) {
            Ok(hashed_b64_country_disclosure.to_string())
        } else if input.key.eq(address_disclosure.0) {
            Ok(hashed_b64_address_disclosure.to_string())
        } else {
            panic!("Unexpected input")
        }
    });
    let hasher = Arc::new(hasher);

    // let mut seq = Sequence::new();
    let mut crypto = MockCryptoProvider::default();
    crypto
        .expect_get_hasher()
        .with(eq(algorithm))
        .returning(move |_| Ok(hasher.clone()));

    let test_json = json!({
        "address": {
            "street_address": "Schulstr. 12",
            "locality": "Schulpforta",
            "region": "Sachsen-Anhalt",
            "country": "DE"
        }
    });

    let (disclosures, result) = gather_disclosures(&test_json, algorithm, &crypto).unwrap();
    let disclosures: Vec<_> = disclosures
        .iter()
        .map(|val| DisclosureArray::from_b64(val))
        .collect();
    let expected_disclosures = &[
        street_address_disclosure,
        locality_disclosure,
        region_disclosure,
        country_disclosure,
        address_disclosure,
    ];

    assert!(expected_disclosures.iter().all(|expected| {
        disclosures
            .iter()
            .any(|disc| disc.key == expected.0 && disc.value.to_string().contains(expected.1))
    }));

    let expected_result = vec![hashed_b64_address_disclosure];
    assert_eq!(expected_result, result);
}

#[test]
fn test_parse_disclosure() {
    let mut easy_disclosure = Disclosure {
        salt: "123".to_string(),
        key: "456".to_string(),
        value: serde_json::Value::String("789".to_string()),
        original_disclosure: r#"["123","456","789"]"#.to_string(),
        base64_encoded_disclosure: "not passed".to_string(),
    };
    let easy_disclosure_no_spaces = r#"["123","456","789"]"#;
    assert_eq!(
        easy_disclosure,
        parse_disclosure(easy_disclosure_no_spaces, "not passed").unwrap()
    );

    let easy_disclosure_with_spaces = r#"      [ "123", "456", "789"]  "#;
    easy_disclosure.original_disclosure = easy_disclosure_with_spaces.to_string();
    assert_eq!(
        easy_disclosure,
        parse_disclosure(easy_disclosure_with_spaces, "not passed").unwrap()
    );

    let easy_but_different_spacing = "      [ \"123\"  \n , \"456\" , \"789\" \t\t   ]  ";
    easy_disclosure.original_disclosure = easy_but_different_spacing.to_string();
    assert_eq!(
        easy_disclosure,
        parse_disclosure(easy_but_different_spacing, "not passed").unwrap()
    );
}

fn generic_disclosures() -> Vec<Disclosure> {
    vec![
        Disclosure {
            salt: "cTgNF-AtESuivLBdhN0t8A".to_string(),
            key: "str".to_string(),
            value: serde_json::Value::String("stronk".to_string()),
            original_disclosure: "[\"cTgNF-AtESuivLBdhN0t8A\",\"str\",\"stronk\"]".to_string(),
            base64_encoded_disclosure: "WyJjVGdORi1BdEVTdWl2TEJkaE4wdDhBIiwic3RyIiwic3Ryb25rIl0".to_string()
        },
        Disclosure {
            salt: "nEP135SkAyOTnMA67CNTAA".to_string(),
            key: "another".to_string(),
            value: serde_json::Value::String("week".to_string()),
            original_disclosure: "[\"nEP135SkAyOTnMA67CNTAA\",\"another\",\"week\"]".to_string(),
            base64_encoded_disclosure: "WyJuRVAxMzVTa0F5T1RuTUE2N0NOVEFBIiwiYW5vdGhlciIsIndlZWsiXQ".to_string()
        },
        Disclosure {
            salt: "xtyBeqglpTfvXrqQzsXMFw".to_string(),
            key: "obj".to_string(),
            value: json!({
              "_sd": [
                "hNm6iOV--i33lAvTeuH_rYQBwx8g_mtDQ9T7QLNdH8s",
                "gXsBjCI5V6KfQrjmDlKXttwD5v-HoRwHH_BW_uWsu6U"
              ]
            }),
            original_disclosure: "[\"xtyBeqglpTfvXrqQzsXMFw\",\"obj\",{\"_sd\":[\"hNm6iOV--i33lAvTeuH_rYQBwx8g_mtDQ9T7QLNdH8s\",\"gXsBjCI5V6KfQrjmDlKXttwD5v-HoRwHH_BW_uWsu6U\"]}]".to_string(),
            base64_encoded_disclosure:"WyJ4dHlCZXFnbHBUZnZYcnFRenNYTUZ3Iiwib2JqIix7Il9zZCI6WyJoTm02aU9WLS1pMzNsQXZUZXVIX3JZUUJ3eDhnX210RFE5VDdRTE5kSDhzIiwiZ1hzQmpDSTVWNktmUXJqbURsS1h0dHdENXYtSG9Sd0hIX0JXX3VXc3U2VSJdfV0".to_string(),
        }
    ]
}

#[test]
fn test_verify_claims_nested_success() {
    let hasher = SHA256 {};

    let hashed_claims = vec!["bvvBS7QQFb8-9K8PVvZ4W3iJNfafA51YUF6wNOW807I".to_string()];
    let disclosures = generic_disclosures();

    verify_claims(&hashed_claims, &disclosures, &hasher).unwrap();

    let hashed_claims_containing_unknown_hash = vec![
        "DECOYHASH2".to_string(),
        "bvvBS7QQFb8-9K8PVvZ4W3iJNfafA51YUF6wNOW807I".to_string(),
        "DECOYHASH1".to_string(),
    ];
    verify_claims(
        &hashed_claims_containing_unknown_hash,
        &disclosures,
        &hasher,
    )
    .unwrap();

    let missing_disclosure = disclosures[1..3].to_vec();
    assert!(verify_claims(&hashed_claims, &missing_disclosure, &hasher).is_ok());
}

#[test]
fn test_extract_claims_from_disclosures() {
    let hasher = SHA256 {};

    let disclosures = generic_disclosures();
    let first_two_disclosures = disclosures[0..2].to_vec();

    let expected = json!({
        "str": "stronk",
        "another": "week"
    });
    assert_eq!(
        expected,
        extract_claims_from_disclosures(&first_two_disclosures, &hasher).unwrap()
    );

    let expected = json!({
        "obj": {
            "str": "stronk",
            "another": "week"
        }
    });
    assert_eq!(
        expected,
        extract_claims_from_disclosures(&disclosures, &hasher).unwrap()
    );
}

#[test]
fn test_get_subdisclosures() {
    let hasher = SHA256 {};

    let disclosures = generic_disclosures();
    let first_two_disclosures = disclosures[0..2].to_vec();

    let disclosure_hashes = disclosures
        .iter()
        .map(|d| d.hash(&hasher).unwrap())
        .collect::<Vec<String>>();
    let first_two_to_resolve = disclosure_hashes[0..2].to_vec();
    let resolve_only_objects = disclosure_hashes[2..3].to_vec();

    let expected = json!({
        "str": "stronk",
        "another": "week"
    });
    let (result, resolved) =
        get_subdisclosures(&first_two_disclosures, &first_two_to_resolve, &hasher).unwrap();
    assert_eq!(expected, result);
    assert_eq!(resolved, first_two_to_resolve);

    let expected = json!({
        "obj": {
            "str": "stronk",
            "another": "week"
        }
    });
    let (result, resolved) =
        get_subdisclosures(&disclosures, &resolve_only_objects, &hasher).unwrap();
    assert_eq!(expected, result);
    assert_eq!(resolved, disclosure_hashes);

    let expected = json!({
        "obj": {
            "str": "stronk",
            "another": "week"
        }
    });
    let (result, resolved) =
        get_subdisclosures(&disclosures, &resolve_only_objects, &hasher).unwrap();
    assert_eq!(expected, result);
    assert_eq!(resolved, disclosure_hashes);
}

#[test]
fn test_get_disclosures_by_claim_name() {
    let hasher = SHA256 {};

    let disclosures = generic_disclosures();

    let expected = vec![disclosures[0].to_owned()];
    let result = get_disclosures_by_claim_name("str", &disclosures, &hasher).unwrap();
    assert_eq!(expected, result);

    let expected = vec![disclosures[1].to_owned()];
    let result = get_disclosures_by_claim_name("another", &disclosures, &hasher).unwrap();
    assert_eq!(expected, result);

    let expected = vec![
        disclosures[0].to_owned(),
        disclosures[1].to_owned(),
        disclosures[2].to_owned(),
    ];
    let result = get_disclosures_by_claim_name("obj", &disclosures, &hasher).unwrap();
    assert_eq!(expected, result);

    let expected = vec![disclosures[0].to_owned(), disclosures[2].to_owned()];
    let result = get_disclosures_by_claim_name("obj/str", &disclosures, &hasher).unwrap();
    assert_eq!(expected, result);

    let expected = vec![disclosures[1].to_owned(), disclosures[2].to_owned()];
    let result = get_disclosures_by_claim_name("obj/another", &disclosures, &hasher).unwrap();
    assert_eq!(expected, result);

    let root_contains_obj_disclosures = vec![
        disclosures[0].to_owned(),
        disclosures[1].to_owned(),
        disclosures[2].to_owned(),
        Disclosure {
          salt: "xtyBeqglpTfvXrqQzsXMFw".to_string(),
          key: "root".to_string(),
          value: json!({
              "_sd": [
                "bvvBS7QQFb8-9K8PVvZ4W3iJNfafA51YUF6wNOW807I"
              ]
          }),
          original_disclosure: "[\"xtyBeqglpTfvXrqQzsXMFw\",\"obj\",{\"_sd\":[\"bvvBS7QQFb8-9K8PVvZ4W3iJNfafA51YUF6wNOW807I\"]}]".to_string(),
          base64_encoded_disclosure: "WyJ4dHlCZXFnbHBUZnZYcnFRenNYTUZ3Iiwib2JqIix7Il9zZCI6WyJidnZCUzdRUUZiOC05SzhQVnZaNFczaUpOZmFmQTUxWVVGNndOT1c4MDdJIl19XQ".to_string(),
      }];

    let expected = vec![
        root_contains_obj_disclosures[1].to_owned(),
        root_contains_obj_disclosures[2].to_owned(),
        root_contains_obj_disclosures[3].to_owned(),
    ];
    let result =
        get_disclosures_by_claim_name("root/obj/another", &root_contains_obj_disclosures, &hasher)
            .unwrap();
    assert_eq!(expected, result);
}

fn generate_published_claim(key: &str) -> PublishedClaim {
    PublishedClaim {
        key: key.to_string(),
        value: PublishedClaimValue::String("irrelevant for tests".to_string()),
        datatype: Some("STRING".to_string()),
        array_item: false,
    }
}

#[test]
fn test_sort_claims_by_indices() {
    let indices = vec![
        generate_published_claim("root/object_array/0/field2"),
        generate_published_claim("root/object_array/1/field2"),
        generate_published_claim("root/object_array/2/field2"),
        generate_published_claim("root/object_array/4/field2"),
        generate_published_claim("root/object_array/3/field2"),
        generate_published_claim("root/array/0"),
        generate_published_claim("root/array/2"),
        generate_published_claim("root/array/10"),
        generate_published_claim("root/array/1"),
    ];

    let expected = vec![
        generate_published_claim("root/object_array/0/field2"),
        generate_published_claim("root/object_array/1/field2"),
        generate_published_claim("root/object_array/2/field2"),
        generate_published_claim("root/object_array/3/field2"),
        generate_published_claim("root/object_array/4/field2"),
        generate_published_claim("root/array/0"),
        generate_published_claim("root/array/1"),
        generate_published_claim("root/array/2"),
        generate_published_claim("root/array/10"),
    ];

    assert_eq!(expected, sort_published_claims_by_indices(&indices));
}

fn get_credential_data(status: Vec<CredentialStatus>, core_base_url: &str) -> CredentialData {
    let id = Some(Uuid::new_v4().to_string());
    let issuance_date = OffsetDateTime::now_utc();
    let valid_for = time::Duration::days(365 * 2);
    let schema = CredentialSchemaData {
        id: Some("http://schema.test/id".to_owned()),
        r#type: Some("TestType".to_owned()),
        context: Some(format!("{core_base_url}/ssi/context/v1/{}", Uuid::new_v4())),
        name: "".to_owned(),
        metadata: None,
    };

    CredentialData {
        id,
        issuance_date,
        valid_for,
        claims: vec![
            PublishedClaim {
                key: "name".into(),
                value: "John".into(),
                datatype: Some("STRING".to_owned()),
                array_item: false,
            },
            PublishedClaim {
                key: "age".into(),
                value: "42".into(),
                datatype: Some("NUMBER".to_owned()),
                array_item: false,
            },
        ],
        issuer_did: Issuer::Url("did:issuer:test".parse().unwrap()),
        status,
        schema,
        name: None,
        description: None,
        terms_of_use: vec![],
        evidence: vec![],
        related_resource: None,
    }
}

fn get_credential_data_with_array(
    status: Vec<CredentialStatus>,
    core_base_url: &str,
) -> CredentialData {
    let id = Some(Uuid::new_v4().to_string());
    let issuance_date = OffsetDateTime::now_utc();
    let valid_for = time::Duration::days(365 * 2);
    let schema = CredentialSchemaData {
        id: Some("CredentialSchemaId".to_owned()),
        r#type: Some("TestType".to_owned()),
        context: Some(format!("{core_base_url}/ssi/context/v1/{}", Uuid::new_v4())),
        name: "".to_owned(),
        metadata: None,
    };

    CredentialData {
        id,
        issuance_date,
        valid_for,
        claims: vec![
            PublishedClaim {
                key: "root/array/0".into(),
                value: "array_item".into(),
                datatype: Some("STRING".to_owned()),
                array_item: true,
            },
            PublishedClaim {
                key: "root/nested".into(),
                value: "nested_item".into(),
                datatype: Some("STRING".to_owned()),
                array_item: false,
            },
            PublishedClaim {
                key: "root_item".into(),
                value: "root_item".into(),
                datatype: Some("STRING".to_owned()),
                array_item: false,
            },
        ],
        issuer_did: Issuer::Url("did:issuer:test".parse().unwrap()),
        status,
        schema,
        name: None,
        description: None,
        terms_of_use: vec![],
        evidence: vec![],
        related_resource: None,
    }
}
