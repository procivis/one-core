use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use mockall::predicate::eq;
use one_crypto::{MockCryptoProvider, MockHasher};
use shared_types::DidValue;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use super::SDJWTFormatter;
#[cfg(test)]
use crate::provider::credential_formatter::common::MockAuth;
use crate::provider::credential_formatter::jwt::model::{JWTPayload, ProofOfPossessionKey};
use crate::provider::credential_formatter::model::{
    CredentialData, CredentialSchema, CredentialStatus, ExtractPresentationCtx, Features, Issuer,
    MockTokenVerifier, PublishedClaim,
};
use crate::provider::credential_formatter::sdjwt::disclosures::DisclosureArray;
use crate::provider::credential_formatter::sdjwt::test::get_credential_data;
use crate::provider::credential_formatter::sdjwt_formatter::{Params, VcClaim};
use crate::provider::credential_formatter::vcdm::{
    ContextType, VcdmCredential, VcdmCredentialSubject,
};
use crate::provider::credential_formatter::{nest_claims, CredentialFormatter};
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::service::test_utilities::{dummy_did_document, dummy_jwk};

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
    let mut credential_data = get_credential_data(
        CredentialStatus {
            id: Some("did:status:id".parse().unwrap()),
            r#type: "TYPE".to_string(),
            status_purpose: Some("PURPOSE".to_string()),
            additional_fields: HashMap::from([("Field1".to_owned(), "Val1".into())]),
        },
        "http://base_url",
    );
    credential_data
        .vcdm
        .context
        .insert(ContextType::Url("http://context.com".parse().unwrap()));
    credential_data.vcdm.r#type.push("Type1".to_string());

    let mut did_method_provider = MockDidMethodProvider::new();
    let holder_did = credential_data.holder_did.as_ref().unwrap().clone();
    did_method_provider
        .expect_resolve()
        .return_once(move |_| Ok(dummy_did_document(&holder_did)));
    let sd_formatter = SDJWTFormatter {
        crypto: Arc::new(crypto),
        did_method_provider: Arc::new(did_method_provider),
        params: Params {
            leeway,
            embed_layout_properties: false,
        },
    };

    let auth_fn = MockAuth(|_| vec![65u8, 66, 67]);
    let result = sd_formatter
        .format_credential(credential_data, Box::new(auth_fn))
        .await;

    assert!(result.is_ok());

    let token = result.unwrap();

    let parts: Vec<&str> = token.splitn(4, '~').collect();
    assert_eq!(parts.len(), 4);
    assert_eq!(parts[3], "");

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

    let payload: JWTPayload<VcClaim> = serde_json::from_str(
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
    assert_eq!(payload.subject, Some(String::from("did:example:123")));
    assert_eq!(
        payload.proof_of_possession_key,
        Some(ProofOfPossessionKey {
            key_id: None,
            jwk: dummy_jwk().into(),
        })
    );

    let vc = payload.custom.vc;

    assert!(vc.credential_subject[0].claims["_sd"]
        .as_array()
        .unwrap()
        .iter()
        .all(|hashed_claim| hashed_claim.as_str().unwrap() == "YWJjMTIz"));

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
        let input = Base64UrlSafeNoPadding::decode_to_vec(input, None).unwrap();
        let input = DisclosureArray::from(std::str::from_utf8(&input).unwrap());
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
        .once()
        .with(eq("sha-256"))
        .returning(move |_| Ok(hasher.clone()));

    let leeway = 45u64;

    let credential_data = get_credential_data_with_array(
        CredentialStatus {
            id: Some("did:status:id".parse().unwrap()),
            r#type: "TYPE".to_string(),
            status_purpose: Some("PURPOSE".to_string()),
            additional_fields: HashMap::from([("Field1".to_owned(), "Val1".into())]),
        },
        "http://base_url",
    );

    let mut did_method_provider = MockDidMethodProvider::new();
    let holder_did = dummy_did_document(&credential_data.holder_did.as_ref().unwrap().clone());
    did_method_provider
        .expect_resolve()
        .return_once(move |_| Ok(holder_did));

    let sd_formatter = SDJWTFormatter {
        crypto: Arc::new(crypto),
        did_method_provider: Arc::new(did_method_provider),
        params: Params {
            leeway,
            embed_layout_properties: false,
        },
    };

    let auth_fn = MockAuth(|_| vec![65u8, 66, 67]);

    let result = sd_formatter
        .format_credential(credential_data, Box::new(auth_fn))
        .await;

    assert!(result.is_ok());

    let token = result.unwrap();

    let parts: Vec<&str> = token.split('~').collect();
    assert_eq!(parts.len(), 6);

    assert_eq!("", parts[5]);

    let part = DisclosureArray::from_b64(parts[1]);
    assert_eq!(part.key, claim1.0);
    assert_eq!(part.value.to_string(), claim1.1);

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

    let payload: JWTPayload<VcClaim> = serde_json::from_str(
        &String::from_utf8(Base64UrlSafeNoPadding::decode_to_vec(jwt_parts[1], None).unwrap())
            .unwrap(),
    )
    .unwrap();

    assert_eq!(payload.issuer, Some(String::from("did:issuer:test")));
    assert_eq!(payload.subject, Some(String::from("did:example:123")));
    assert_eq!(
        payload.proof_of_possession_key,
        Some(ProofOfPossessionKey {
            key_id: None,
            jwk: dummy_jwk().into(),
        })
    );

    let vc = payload.custom.vc;

    assert_eq!(
        HashSet::<&str>::from_iter([hash4, hash3]),
        HashSet::from_iter(
            vc.credential_subject[0].claims["_sd"]
                .as_array()
                .unwrap()
                .iter()
                .map(|d| d.as_str().unwrap())
        )
    );
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
        .withf(move |disclosure| {
            disclosure == base64_urlsafe(claim1).as_bytes() || disclosure == claim1.as_bytes()
        })
        .returning(|_| Ok("rZjyxF4zE7fdRmkcUT8Hkr8_IHSBes1z1pZWP2vLBRE".to_string()));
    hasher
        .expect_hash_base64()
        .withf(move |disclosure| {
            disclosure == base64_urlsafe(claim2).as_bytes() || disclosure == claim2.as_bytes()
        })
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
        did_method_provider: Arc::new(MockDidMethodProvider::new()),
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

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .once()
        .returning(|_| {
            let mut key_algorithm = MockKeyAlgorithm::default();
            key_algorithm
                .expect_algorithm_id()
                .return_once(|| "algorithm".to_string());

            Some(("algorithm".to_string(), Arc::new(key_algorithm)))
        });
    verify_mock
        .expect_key_algorithm_provider()
        .return_const(Box::new(key_algorithm_provider));

    let result = sd_formatter
        .extract_credentials(&token, Box::new(verify_mock), None)
        .await;

    let credentials = result.unwrap();

    assert_eq!(
        credentials.issuer_did,
        Some("did:issuer:test".parse().unwrap())
    );
    assert_eq!(
        credentials.subject,
        Some("did:holder:test".parse().unwrap())
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

    assert_eq!(credentials.claims.claims.get("name").unwrap(), "John");
    assert_eq!(credentials.claims.claims.get("age").unwrap(), "42");
}

#[tokio::test]
async fn test_extract_credentials_with_array() {
    let jwt_token = "ewogICJhbGciOiAiYWxnb3JpdGhtIiwKICAia2lkIjogIiNrZXkwIiwKICAidHlwIjogIlNESldUIgp9.ewogICJpYXQiOiAxNzE4MzU5MDYzLAogICJleHAiOiAxNzgxNDMxMDYzLAogICJuYmYiOiAxNzE4MzU5MDE4LAogICJpc3MiOiAiZGlkOmlzc3VlcjoxMjMiLAogICJzdWIiOiAiZGlkOmhvbGRlcjoxMjMiLAogICJqdGkiOiAiaHR0cDovL2Jhc2VfdXJsL3NzaS9jcmVkZW50aWFsL3YxLzlhNDE0YTYwLTllNmItNDc1Ny04MDExLTlhYTg3MGVmNDc4OCIsCiAgInZjIjogewogICAgIkBjb250ZXh0IjogWwogICAgICAiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLAogICAgICAiaHR0cHM6Ly93d3cudGVzdGNvbnRleHQuY29tL3YxIgogICAgXSwKICAgICJpZCI6ICJodHRwOi8vYmFzZV91cmwvc3NpL2NyZWRlbnRpYWwvdjEvOWE0MTRhNjAtOWU2Yi00NzU3LTgwMTEtOWFhODcwZWY0Nzg4IiwKICAgICJ0eXBlIjogWwogICAgICAiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLAogICAgICAiVHlwZTEiCiAgICBdLAogICAgImNyZWRlbnRpYWxTdWJqZWN0IjogewogICAgICAiX3NkIjogWwogICAgICAgICJwRE9lOUNDaE0tWVJnSEJJTHlUMWtQVEJtQ3FickFla3QyeE9KTGI4SEVzIiwKICAgICAgICAiR0JjbThRWk8yUHI0bl9qbUpsUDRCeTFpd2NvVTBlUURWaGluMkFpZE1xNCIKICAgICAgXQogICAgfSwKICAgICJjcmVkZW50aWFsU3RhdHVzIjogewogICAgICAiaWQiOiAiaHR0cHM6Ly9wcm9jaXZpcy5jaC9zdGF0dXMvaWQiLAogICAgICAidHlwZSI6ICJUWVBFIiwKICAgICAgInN0YXR1c1B1cnBvc2UiOiAiUFVSUE9TRSIKICAgIH0sCiAgICAiY3JlZGVudGlhbFNjaGVtYSI6IHsKICAgICAgImlkIjogImh0dHBzOi8vcHJvY2l2aXMuY2gvY3JlZGVudGlhbC1zY2hlbWEvaWQiLAogICAgICAidHlwZSI6ICJQcm9jaXZpc09uZVNjaGVtYTIwMjQiCiAgICB9CiAgfSwKICAiX3NkX2FsZyI6ICJzaGEtMjU2Igp9";
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
        .withf(move |disclosure| {
            disclosure == base64_urlsafe(claim1).as_bytes() || disclosure == claim1.as_bytes()
        })
        .returning(|_| Ok("WQnd2qlMku7G5ItM53QRvdUf4GacXGzLWvTN_wDharc".to_string()));
    hasher
        .expect_hash_base64()
        .withf(move |disclosure| {
            disclosure == base64_urlsafe(claim2).as_bytes() || disclosure == claim2.as_bytes()
        })
        .returning(|_| Ok("r69eqe07S9rE27Ing-l997ofg85RS_nRuVXucVQ9Ehw".to_string()));
    hasher
        .expect_hash_base64()
        .withf(move |disclosure| {
            disclosure == base64_urlsafe(claim3).as_bytes() || disclosure == claim3.as_bytes()
        })
        .returning(|_| Ok("pDOe9CChM-YRgHBILyT1kPTBmCqbrAekt2xOJLb8HEs".to_string()));
    hasher
        .expect_hash_base64()
        .withf(move |disclosure| {
            disclosure == base64_urlsafe(claim4).as_bytes() || disclosure == claim4.as_bytes()
        })
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
        did_method_provider: Arc::new(MockDidMethodProvider::new()),
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
                    "did:issuer:123",
                    issuer_did_value.as_ref().unwrap().as_str()
                );
                assert_eq!("algorithm", algorithm);
                assert_eq!(jwt_token.as_bytes(), token);
                assert_eq!(vec![65u8, 66, 67], signature);
                true
            },
        )
        .return_once(|_, _, _, _, _| Ok(()));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .once()
        .returning(|_| {
            let mut key_algorithm = MockKeyAlgorithm::default();
            key_algorithm
                .expect_algorithm_id()
                .return_once(|| "algorithm".to_string());

            Some(("algorithm".to_string(), Arc::new(key_algorithm)))
        });
    verify_mock
        .expect_key_algorithm_provider()
        .return_const(Box::new(key_algorithm_provider));

    let credentials = sd_formatter
        .extract_credentials(&token, Box::new(verify_mock), None)
        .await
        .unwrap();

    let root_item = credentials.claims.claims.get("root_item").unwrap();
    assert_eq!(root_item.as_str(), Some("root_item"));

    let root = credentials.claims.claims.get("root").unwrap();
    let nested = root.get("nested").unwrap();
    assert_eq!(nested.as_str(), Some("nested_item"));

    let array = root.get("array").unwrap().as_array().unwrap();
    assert_eq!(array[0].as_str(), Some("array_item"));
}

#[tokio::test]
async fn test_extract_credentials_with_array_stripped() {
    let jwt_token = "ewogICJhbGciOiAiYWxnb3JpdGhtIiwKICAia2lkIjogIiNrZXkwIiwKICAidHlwIjogIlNESldUIgp9.ewogICJpYXQiOiAxNzE4MzU5MDYzLAogICJleHAiOiAxNzgxNDMxMDYzLAogICJuYmYiOiAxNzE4MzU5MDE4LAogICJpc3MiOiAiZGlkOmlzc3VlcjoxMjMiLAogICJzdWIiOiAiZGlkOmhvbGRlcjoxMjMiLAogICJqdGkiOiAiaHR0cDovL2Jhc2VfdXJsL3NzaS9jcmVkZW50aWFsL3YxLzlhNDE0YTYwLTllNmItNDc1Ny04MDExLTlhYTg3MGVmNDc4OCIsCiAgInZjIjogewogICAgIkBjb250ZXh0IjogWwogICAgICAiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLAogICAgICAiaHR0cHM6Ly93d3cudHlwZTFjdHgub3JnIgogICAgXSwKICAgICJpZCI6ICJodHRwOi8vYmFzZV91cmwvc3NpL2NyZWRlbnRpYWwvdjEvOWE0MTRhNjAtOWU2Yi00NzU3LTgwMTEtOWFhODcwZWY0Nzg4IiwKICAgICJ0eXBlIjogWwogICAgICAiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLAogICAgICAiVHlwZTEiCiAgICBdLAogICAgImNyZWRlbnRpYWxTdWJqZWN0IjogewogICAgICAiX3NkIjogWwogICAgICAgICJwRE9lOUNDaE0tWVJnSEJJTHlUMWtQVEJtQ3FickFla3QyeE9KTGI4SEVzIiwKICAgICAgICAiR0JjbThRWk8yUHI0bl9qbUpsUDRCeTFpd2NvVTBlUURWaGluMkFpZE1xNCIKICAgICAgXQogICAgfSwKICAgICJjcmVkZW50aWFsU3RhdHVzIjogewogICAgICAiaWQiOiAiaHR0cHM6Ly9wcm9jaXZpcy5jaC9zdGF0dXMvaWQiLAogICAgICAidHlwZSI6ICJUWVBFIiwKICAgICAgInN0YXR1c1B1cnBvc2UiOiAiUFVSUE9TRSIKICAgIH0sCiAgICAiY3JlZGVudGlhbFNjaGVtYSI6IHsKICAgICAgImlkIjogImh0dHBzOi8vcHJvY2l2aXMuY2gvY3JlZGVudGlhbC1zY2hlbWEvaWQiLAogICAgICAidHlwZSI6ICJQcm9jaXZpc09uZVNjaGVtYTIwMjQiCiAgICB9CiAgfSwKICAiX3NkX2FsZyI6ICJzaGEtMjU2Igp9";
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
        .withf(move |disclosure| {
            disclosure == base64_urlsafe(claim1).as_bytes() || disclosure == claim1.as_bytes()
        })
        .returning(|_| Ok("WQnd2qlMku7G5ItM53QRvdUf4GacXGzLWvTN_wDharc".to_string()));
    hasher
        .expect_hash_base64()
        .never()
        .withf(move |disclosure| {
            disclosure == base64_urlsafe(claim2).as_bytes() || disclosure == claim2.as_bytes()
        })
        .returning(|_| Ok("r69eqe07S9rE27Ing-l997ofg85RS_nRuVXucVQ9Ehw".to_string()));
    hasher
        .expect_hash_base64()
        .withf(move |disclosure| {
            disclosure == base64_urlsafe(claim3).as_bytes() || disclosure == claim3.as_bytes()
        })
        .returning(|_| Ok("pDOe9CChM-YRgHBILyT1kPTBmCqbrAekt2xOJLb8HEs".to_string()));
    hasher
        .expect_hash_base64()
        .withf(move |disclosure| {
            disclosure == base64_urlsafe(claim4).as_bytes() || disclosure == claim4.as_bytes()
        })
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
        did_method_provider: Arc::new(MockDidMethodProvider::new()),
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
                    "did:issuer:123",
                    issuer_did_value.as_ref().unwrap().as_str()
                );
                assert_eq!("algorithm", algorithm);
                assert_eq!(jwt_token.as_bytes(), token);
                assert_eq!(vec![65u8, 66, 67], signature);
                true
            },
        )
        .return_once(|_, _, _, _, _| Ok(()));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .once()
        .returning(|_| {
            let mut key_algorithm = MockKeyAlgorithm::default();
            key_algorithm
                .expect_algorithm_id()
                .return_once(|| "algorithm".to_string());

            Some(("algorithm".to_string(), Arc::new(key_algorithm)))
        });
    verify_mock
        .expect_key_algorithm_provider()
        .return_const(Box::new(key_algorithm_provider));

    let credentials = sd_formatter
        .extract_credentials(&token, Box::new(verify_mock), None)
        .await
        .unwrap();

    let root_item = credentials.claims.claims.get("root_item").unwrap();
    assert_eq!(root_item.as_str(), Some("root_item"));

    let root = credentials.claims.claims.get("root").unwrap();
    assert!(root.get("nested").is_none());

    let array = root.get("array").unwrap().as_array().unwrap();
    assert_eq!(array[0].as_str(), Some("array_item"));
}

#[tokio::test]
async fn test_extract_presentation() {
    let jwt_token = "eyJhbGciOiJhbGdvcml0aG0iLCJ0eXAiOiJTREpXVCJ9.ewogICJpYXQiOiAxNjk5MzUxODQxLAogICJleHAiOiAxNjk5MzUyMTQxLAogICJuYmYiOiAxNjk5MzUxNzk2LAogICJpc3MiOiAiZGlkOmhvbGRlcjoxMjMiLAogICJzdWIiOiAiZGlkOmhvbGRlcjoxMjMiLAogICJqdGkiOiAiYjRjYzQ5ZDUtOGQwZS00ODFlLWIxZWItOGU0ZThiOTY5NmIxIiwKICAidnAiOiB7CiAgICAiQGNvbnRleHQiOiBbCiAgICAgICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIKICAgIF0sCiAgICAidHlwZSI6IFsKICAgICAgIlZlcmlmaWFibGVQcmVzZW50YXRpb24iCiAgICBdLAogICAgIl9zZF9qd3QiOiBbCiAgICAgICJleUpoYkdjaU9pSmhiR2R2Y21sMGFHMGlMQ0owZVhBaU9pSlRSRXBYVkNKOS5leUpwWVhRaU9qRTJPVGt5TnpBeU5qWXNJbVY0Y0NJNk1UYzJNak0wTWpJMk5pd2libUptSWpveE5qazVNamN3TWpJeExDSnBjM01pT2lKSmMzTjFaWElnUkVsRUlpd2ljM1ZpSWpvaWFHOXNaR1Z5WDJScFpDSXNJbXAwYVNJNklqbGhOREUwWVRZd0xUbGxObUl0TkRjMU55MDRNREV4TFRsaFlUZzNNR1ZtTkRjNE9DSXNJblpqSWpwN0lrQmpiMjUwWlhoMElqcGJJbWgwZEhCek9pOHZkM2QzTG5jekxtOXlaeTh5TURFNEwyTnlaV1JsYm5ScFlXeHpMM1l4SWl3aVEyOXVkR1Y0ZERFaVhTd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiQ0lzSWxSNWNHVXhJbDBzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0lsOXpaQ0k2V3lKWlYwcHFUVlJKZWlJc0lsbFhTbXBOVkVsNklsMTlMQ0pqY21Wa1pXNTBhV0ZzVTNSaGRIVnpJanA3SW1sa0lqb2lVMVJCVkZWVFgwbEVJaXdpZEhsd1pTSTZJbFJaVUVVaUxDSnpkR0YwZFhOUWRYSndiM05sSWpvaVVGVlNVRTlUUlNJc0lrWnBaV3hrTVNJNklsWmhiREVpZlgwc0lsOXpaRjloYkdjaU9pSnphR0V0TWpVMkluMC5RVUpEfld5Sk5WRWw2V1ZkS2FpSXNJbTVoYldVaUxDSktiMmh1SWwwfld5Sk5WRWw2V1ZkS2FpSXNJbUZuWlNJc0lqUXlJbDAiCiAgICBdCiAgfQp9";
    let presentation_token = format!("{jwt_token}.QUJD");

    let crypto = MockCryptoProvider::default();

    let leeway = 45u64;

    let sd_formatter = SDJWTFormatter {
        crypto: Arc::new(crypto),
        did_method_provider: Arc::new(MockDidMethodProvider::new()),
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
                    "did:holder:123",
                    issuer_did_value.as_ref().unwrap().as_str()
                );
                assert_eq!("algorithm", algorithm);
                assert_eq!(jwt_token.as_bytes(), token);
                assert_eq!(vec![65u8, 66, 67], signature);
                true
            },
        )
        .return_once(|_, _, _, _, _| Ok(()));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .once()
        .returning(|_| {
            let mut key_algorithm = MockKeyAlgorithm::default();
            key_algorithm
                .expect_algorithm_id()
                .return_once(|| "algorithm".to_string());

            Some(("algorithm".to_string(), Arc::new(key_algorithm)))
        });
    verify_mock
        .expect_key_algorithm_provider()
        .return_const(Box::new(key_algorithm_provider));

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
        Some("did:holder:123".parse().unwrap())
    );
}

#[test]
fn test_get_capabilities() {
    let sd_formatter = SDJWTFormatter {
        crypto: Arc::new(MockCryptoProvider::default()),
        did_method_provider: Arc::new(MockDidMethodProvider::new()),
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

fn get_credential_data_with_array(status: CredentialStatus, core_base_url: &str) -> CredentialData {
    let issuance_date = OffsetDateTime::now_utc();
    let valid_for = time::Duration::days(365 * 2);

    let schema_context: ContextType = format!("{core_base_url}/ssi/context/v1/{}", Uuid::new_v4())
        .parse::<Url>()
        .unwrap()
        .into();
    let schema = CredentialSchema {
        id: "CredentialSchemaId".to_owned(),
        r#type: "TestType".to_owned(),
        metadata: None,
    };

    let holder_did: DidValue = "did:example:123".parse().unwrap();

    let claims = vec![
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
    ];

    let issuer_did = Issuer::Url("did:issuer:test".parse().unwrap());
    let credential_subject = VcdmCredentialSubject::new(nest_claims(claims.clone()).unwrap());

    let vcdm = VcdmCredential::new_v2(issuer_did, credential_subject)
        .add_context(schema_context)
        .add_credential_schema(schema)
        .add_credential_status(status)
        .with_valid_from(issuance_date)
        .with_valid_until(issuance_date + valid_for);

    CredentialData {
        vcdm,
        claims,
        holder_did: Some(holder_did),
        holder_key_id: Some("did-vm-id".to_string()),
    }
}

fn base64_urlsafe(s: &str) -> String {
    Base64UrlSafeNoPadding::encode_to_string(s).unwrap()
}
