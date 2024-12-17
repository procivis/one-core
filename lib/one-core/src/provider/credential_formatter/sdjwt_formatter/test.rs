use std::collections::HashMap;
use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use mockall::predicate::eq;
use one_crypto::{MockCryptoProvider, MockHasher};
use shared_types::DidValue;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::SDJWTFormatter;
#[cfg(test)]
use crate::provider::credential_formatter::common::MockAuth;
use crate::provider::credential_formatter::json_ld::model::ContextType;
use crate::provider::credential_formatter::jwt::model::JWTPayload;
use crate::provider::credential_formatter::model::{
    CredentialData, CredentialSchemaData, CredentialStatus, ExtractPresentationCtx, Features,
    Issuer, MockTokenVerifier, PublishedClaim,
};
use crate::provider::credential_formatter::sdjwt::disclosures::DisclosureArray;
use crate::provider::credential_formatter::sdjwt::test::get_credential_data;
use crate::provider::credential_formatter::sdjwt_formatter::{Params, Sdvc};
use crate::provider::credential_formatter::CredentialFormatter;

impl From<&str> for DisclosureArray {
    fn from(value: &str) -> Self {
        serde_json::from_str(value).unwrap()
    }
}

impl DisclosureArray {
    pub fn from_b64(value: &str) -> Self {
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
            vec![ContextType::Url("http://context.com".parse().unwrap())],
            vec!["Type1".to_string()],
            Box::new(auth_fn),
        )
        .await;

    assert!(result.is_ok());

    let token = result.unwrap();

    let parts: Vec<&str> = token.splitn(4, '~').collect();
    assert_eq!(parts.len(), 3);

    let disclosures = [
        DisclosureArray::from_b64(parts[1]),
        DisclosureArray::from_b64(parts[2]),
    ];
    assert!(disclosures
        .iter()
        .any(|disc| disc.key == "name" && disc.value == "John"));
    assert!(disclosures
        .iter()
        .any(|disc| disc.key == "age" && disc.value == "42"));

    let jwt_parts: Vec<&str> = parts[0].splitn(3, '.').collect();

    assert_eq!(
        jwt_parts[0],
        &Base64UrlSafeNoPadding::encode_to_string(
            r##"{"alg":"ES256","kid":"#key0","typ":"SD_JWT"}"##
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
            vec![ContextType::Url("http://context.com".parse().unwrap())],
            vec!["Type1".to_string()],
            Box::new(auth_fn),
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
            r##"{"alg":"ES256","kid":"#key0","typ":"SD_JWT"}"##
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
            Features::SelectiveDisclosure,
            Features::SupportsCredentialDesign
        ],
        sd_formatter.get_capabilities().features
    );
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
