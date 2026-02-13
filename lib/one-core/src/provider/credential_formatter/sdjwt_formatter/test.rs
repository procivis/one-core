use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use assert2::let_assert;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use maplit::hashmap;
use mockall::predicate::eq;
use one_crypto::hasher::sha256::SHA256;
use one_crypto::{MockCryptoProvider, MockHasher};
use serde_json::json;
use shared_types::DidValue;
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use super::SDJWTFormatter;
use crate::config::core_config::KeyAlgorithmType;
use crate::model::did::Did;
use crate::model::identifier::Identifier;
use crate::proto::http_client::MockHttpClient;
use crate::proto::jwt::model::{JWTPayload, ProofOfPossessionJwk, ProofOfPossessionKey};
#[cfg(test)]
use crate::provider::credential_formatter::common::MockAuth;
use crate::provider::credential_formatter::model::{
    CredentialClaim, CredentialClaimValue, CredentialData, CredentialSchema, CredentialStatus,
    Features, IdentifierDetails, Issuer, MockTokenVerifier, PublicKeySource, PublishedClaim,
};
use crate::provider::credential_formatter::sdjwt::disclosures::{
    DisclosureArray, DisclosureArrayElement,
};
use crate::provider::credential_formatter::sdjwt::test::get_credential_data;
use crate::provider::credential_formatter::sdjwt_formatter::{Params, VcClaim};
use crate::provider::credential_formatter::vcdm::{
    ContextType, VcdmCredential, VcdmCredentialSubject,
};
use crate::provider::credential_formatter::{CredentialFormatter, nest_claims};
use crate::provider::data_type::provider::MockDataTypeProvider;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::service::test_utilities::{dummy_did, dummy_did_document, dummy_identifier, dummy_jwk};

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

impl DisclosureArrayElement {
    pub fn from_b64(value: &str) -> Self {
        let part_decoded = Base64UrlSafeNoPadding::decode_to_vec(value, None).unwrap();
        serde_json::from_slice(&part_decoded).unwrap()
    }
}

#[tokio::test]
async fn test_format_credential_a() {
    let mut hasher = MockHasher::default();
    hasher
        .expect_hash_base64_url()
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

    let holder_did = credential_data
        .holder_identifier
        .as_ref()
        .and_then(|identifier| identifier.did.as_ref().map(|did| did.did.clone()))
        .unwrap();

    let did_document = dummy_did_document(&holder_did);

    did_method_provider
        .expect_resolve()
        .return_once(move |_| Ok(did_document));
    let sd_formatter = SDJWTFormatter {
        crypto: Arc::new(crypto),
        did_method_provider: Arc::new(did_method_provider),
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
        data_type_provider: Arc::new(MockDataTypeProvider::new()),
        params: Params {
            leeway,
            embed_layout_properties: false,
            sd_array_elements: true,
            expiration_time: Duration::days(1),
        },
        client: Arc::new(MockHttpClient::new()),
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
    assert!(
        disclosures
            .iter()
            .any(|disc| disc.key == "name" && disc.value == "John")
    );
    assert!(
        disclosures
            .iter()
            .any(|disc| disc.key == "age" && disc.value == "42")
    );

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
    assert_eq!(payload.invalid_before, Some(payload.issued_at.unwrap()),);

    assert_eq!(payload.issuer, Some(String::from("did:issuer:test")));
    assert_eq!(payload.subject, Some(String::from("did:example:123")));
    assert_eq!(
        payload.proof_of_possession_key,
        Some(ProofOfPossessionKey {
            key_id: None,
            jwk: ProofOfPossessionJwk::Jwk { jwk: dummy_jwk() },
        })
    );

    let vc = payload.custom.vc;

    assert!(
        vc.credential_subject[0].claims["_sd"]
            .value
            .as_array()
            .unwrap()
            .iter()
            .all(|hashed_claim| hashed_claim.value.as_str().unwrap() == "YWJjMTIz")
    );

    assert!(
        vc.context
            .contains(&ContextType::Url("http://context.com".parse().unwrap()))
    );
    assert!(vc.r#type.contains(&String::from("Type1")));

    assert_eq!(1, vc.credential_status.len());
    let first_credential_status = vc.credential_status.first().unwrap();
    assert!(
        first_credential_status
            .id
            .as_ref()
            .is_some_and(|id| id.as_str() == "did:status:id")
    );
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
    let claim3 = (
        "root",
        "{\"_sd\":[\"MPQIfncdJvNwYLbpw4L0lU9MEK_bYA9JDVGO7qb0abs\",\"r69eqe07S9rE27Ing-l997ofg85RS_nRuVXucVQ9Ehw\"]}",
    );
    let claim4 = ("root_item", "root_item");

    let hash1 = "MPQIfncdJvNwYLbpw4L0lU9MEK_bYA9JDVGO7qb0abs";
    let hash2 = "r69eqe07S9rE27Ing-l997ofg85RS_nRuVXucVQ9Ehw";
    let hash3 = "sadrIPfvvuqIBTdMxsmvGh77Z89M3JyX2qQQEGzmkYg";
    let hash4 = "GBcm8QZO2Pr4n_jmJlP4By1iwcoU0eQDVhin2AidMq4";

    let mut hasher = MockHasher::default();
    hasher.expect_hash_base64_url().returning(move |input| {
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
    let holder_did = credential_data
        .holder_identifier
        .as_ref()
        .and_then(|identifier| identifier.did.as_ref().map(|did| did.did.clone()))
        .unwrap();

    let did_document = dummy_did_document(&holder_did);
    did_method_provider
        .expect_resolve()
        .return_once(move |_| Ok(did_document));

    let sd_formatter = SDJWTFormatter {
        crypto: Arc::new(crypto),
        did_method_provider: Arc::new(did_method_provider),
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
        data_type_provider: Arc::new(MockDataTypeProvider::new()),
        params: Params {
            leeway,
            embed_layout_properties: false,
            sd_array_elements: false,
            expiration_time: Duration::days(1),
        },
        client: Arc::new(MockHttpClient::new()),
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
            jwk: ProofOfPossessionJwk::Jwk { jwk: dummy_jwk() },
        })
    );

    let vc = payload.custom.vc;

    assert_eq!(
        HashSet::<&str>::from_iter([hash4, hash3]),
        HashSet::from_iter(
            vc.credential_subject[0].claims["_sd"]
                .value
                .as_array()
                .unwrap()
                .iter()
                .map(|d| d.value.as_str().unwrap())
        )
    );
}

#[tokio::test]
async fn test_format_credential_with_array_sd() {
    let claim1 = "\"array_item\"";
    let claim2 = ("array", "[\"array_item\"]");
    let claim3 = ("nested", "nested_item");
    let claim4 = "root";
    let claim5 = ("root_item", "root_item");

    let mut crypto = MockCryptoProvider::default();
    crypto
        .expect_get_hasher()
        .once()
        .with(eq("sha-256"))
        .returning(move |_| Ok(Arc::new(SHA256)));

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
    let holder_did = credential_data
        .holder_identifier
        .as_ref()
        .and_then(|identifier| identifier.did.as_ref().map(|did| did.did.clone()))
        .unwrap();

    let did_document = dummy_did_document(&holder_did);
    did_method_provider
        .expect_resolve()
        .return_once(move |_| Ok(did_document));

    let sd_formatter = SDJWTFormatter {
        crypto: Arc::new(crypto),
        did_method_provider: Arc::new(did_method_provider),
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
        data_type_provider: Arc::new(MockDataTypeProvider::new()),
        params: Params {
            leeway,
            embed_layout_properties: false,
            sd_array_elements: true,
            expiration_time: Duration::days(1),
        },
        client: Arc::new(MockHttpClient::new()),
    };

    let auth_fn = MockAuth(|_| vec![65u8, 66, 67]);

    let result = sd_formatter
        .format_credential(credential_data, Box::new(auth_fn))
        .await;

    assert!(result.is_ok());

    let token = result.unwrap();

    let parts: Vec<&str> = token.split('~').collect();
    assert_eq!(parts.len(), 7);

    assert_eq!("", parts[6]);

    // array element disclosure
    let part = DisclosureArrayElement::from_b64(parts[1]);
    assert_eq!(part.value.to_string(), claim1);

    // array disclosure with nested element disclosure objects
    let part = DisclosureArray::from_b64(parts[2]);
    assert_eq!(part.key, claim2.0);
    let_assert!(Some(arr) = part.value.as_array());
    let_assert!(Some(obj) = arr[0].as_object());
    assert_eq!(obj.len(), 1);
    assert!(obj.contains_key("..."));

    let part = DisclosureArray::from_b64(parts[3]);
    assert_eq!(part.key, claim3.0);
    assert_eq!(part.value, claim3.1);

    let part = DisclosureArray::from_b64(parts[4]);
    assert_eq!(part.key, claim4);
    // expect two subdisclosures
    assert_eq!(part.value["_sd"].as_array().unwrap().len(), 2);
    let part = DisclosureArray::from_b64(parts[5]);
    assert_eq!(part.key, claim5.0);
    assert_eq!(part.value, claim5.1);

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
            jwk: ProofOfPossessionJwk::Jwk { jwk: dummy_jwk() },
        })
    );

    let vc = payload.custom.vc;
    assert_eq!(
        vc.credential_subject[0].claims["_sd"]
            .value
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn test_extract_credentials() {
    let jwt_token = "ewogICJhbGciOiAiYWxnb3JpdGhtIiwKICAidHlwIjogIlNESldUIgp9.ewogICJpYXQiOiAxNjk5MjcwMjY2LAogICJleHAiOiAxNzYyMzQyMjY2LAogICJuYmYiOiAxNjk5MjcwMjIxLAogICJpc3MiOiAiZGlkOmlzc3Vlcjp0ZXN0IiwKICAic3ViIjogImRpZDpob2xkZXI6dGVzdCIsCiAgImp0aSI6ICI5YTQxNGE2MC05ZTZiLTQ3NTctODAxMS05YWE4NzBlZjQ3ODgiLAogICJ2YyI6IHsKICAgICJAY29udGV4dCI6IFsKICAgICAgImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwKICAgICAgImh0dHBzOi8vd3d3LnR5cGUxLWNvbnRleHQuY29tL3YxIgogICAgXSwKICAgICJ0eXBlIjogWwogICAgICAiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLAogICAgICAiVHlwZTEiCiAgICBdLAogICAgImNyZWRlbnRpYWxTdWJqZWN0IjogewogICAgICAiX3NkIjogWwogICAgICAgICJyWmp5eEY0ekU3ZmRSbWtjVVQ4SGtyOF9JSFNCZXMxejFwWldQMnZMQlJFIiwKICAgICAgICAiS0dQbGRsUEIzOTV4S0pSaks4azJLNVV2c0VuczlRaEw3TzdKVXU1OUVSayIKICAgICAgXQogICAgfSwKICAgICJjcmVkZW50aWFsU3RhdHVzIjogewogICAgICAiaWQiOiAiaHR0cHM6Ly93d3cudGVzdC12Yy5jb20vc3RhdHVzL2lkIiwKICAgICAgInR5cGUiOiAiVFlQRSIsCiAgICAgICJzdGF0dXNQdXJwb3NlIjogIlBVUlBPU0UiLAogICAgICAiRmllbGQxIjogIlZhbDEiCiAgICB9CiAgfSwKICAiX3NkX2FsZyI6ICJzaGEtMjU2Igp9";
    let token = format!(
        "{jwt_token}.QUJD~WyJNVEl6WVdKaiIsIm5hbWUiLCJKb2huIl0~WyJNVEl6WVdKaiIsImFnZSIsIjQyIl0~"
    );

    let claim1 = "[\"MTIzYWJj\",\"name\",\"John\"]";
    let claim2 = "[\"MTIzYWJj\",\"age\",\"42\"]";

    let mut hasher = MockHasher::default();
    hasher
        .expect_hash_base64_url()
        .withf(move |disclosure| {
            disclosure == base64_urlsafe(claim1).as_bytes() || disclosure == claim1.as_bytes()
        })
        .returning(|_| Ok("rZjyxF4zE7fdRmkcUT8Hkr8_IHSBes1z1pZWP2vLBRE".to_string()));
    hasher
        .expect_hash_base64_url()
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
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
        data_type_provider: Arc::new(MockDataTypeProvider::new()),
        params: Params {
            leeway,
            embed_layout_properties: false,
            sd_array_elements: true,
            expiration_time: Duration::days(1),
        },
        client: Arc::new(MockHttpClient::new()),
    };

    let mut verify_mock = MockTokenVerifier::new();
    verify_mock
        .expect_verify()
        .withf(
            move |params, algorithm, token, signature| {
                assert!(matches!(params, PublicKeySource::Did {did, ..} if did.to_string() == "did:issuer:test"));
                assert_eq!(KeyAlgorithmType::Eddsa, *algorithm);
                assert_eq!(jwt_token.as_bytes(), token);
                assert_eq!(vec![65u8, 66, 67], signature);
                true
            },
        )
        .return_once(|_,  _, _, _| Ok(()));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .once()
        .returning(|_| {
            let mut key_algorithm = MockKeyAlgorithm::default();
            key_algorithm
                .expect_algorithm_type()
                .return_once(|| KeyAlgorithmType::Eddsa);

            Some((KeyAlgorithmType::Eddsa, Arc::new(key_algorithm)))
        });
    verify_mock
        .expect_key_algorithm_provider()
        .return_const(Box::new(key_algorithm_provider));

    let result = sd_formatter
        .extract_credentials(&token, None, Box::new(verify_mock))
        .await;

    let credentials = result.unwrap();

    assert_eq!(
        credentials.issuer,
        IdentifierDetails::Did("did:issuer:test".parse().unwrap())
    );
    assert_eq!(
        credentials.subject,
        Some(IdentifierDetails::Did("did:holder:test".parse().unwrap()))
    );

    assert_eq!(1, credentials.status.len());
    let first_credential_status = credentials.status.first().unwrap();
    assert!(
        first_credential_status
            .id
            .as_ref()
            .is_some_and(|id| id.as_str() == "https://www.test-vc.com/status/id")
    );
    assert_eq!(first_credential_status.r#type, "TYPE");
    assert_eq!(
        first_credential_status.status_purpose.as_deref(),
        Some("PURPOSE")
    );
    assert_eq!(
        first_credential_status.additional_fields.get("Field1"),
        Some(&"Val1".into())
    );

    assert_eq!(
        credentials
            .claims
            .claims
            .get("name")
            .unwrap()
            .value
            .as_str()
            .unwrap(),
        "John"
    );
    assert!(
        credentials
            .claims
            .claims
            .get("name")
            .unwrap()
            .selectively_disclosable
    );
    assert_eq!(
        credentials
            .claims
            .claims
            .get("age")
            .unwrap()
            .value
            .as_str()
            .unwrap(),
        "42"
    );
    assert!(
        credentials
            .claims
            .claims
            .get("age")
            .unwrap()
            .selectively_disclosable
    );
}

#[tokio::test]
async fn test_extract_credentials_with_array() {
    let jwt_token = "ewogICJhbGciOiAiYWxnb3JpdGhtIiwKICAia2lkIjogIiNrZXkwIiwKICAidHlwIjogIlNESldUIgp9.ewogICJpYXQiOiAxNzE4MzU5MDYzLAogICJleHAiOiAxNzgxNDMxMDYzLAogICJuYmYiOiAxNzE4MzU5MDE4LAogICJpc3MiOiAiZGlkOmlzc3VlcjoxMjMiLAogICJzdWIiOiAiZGlkOmhvbGRlcjoxMjMiLAogICJqdGkiOiAiaHR0cDovL2Jhc2VfdXJsL3NzaS9jcmVkZW50aWFsL3YxLzlhNDE0YTYwLTllNmItNDc1Ny04MDExLTlhYTg3MGVmNDc4OCIsCiAgInZjIjogewogICAgIkBjb250ZXh0IjogWwogICAgICAiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLAogICAgICAiaHR0cHM6Ly93d3cudGVzdGNvbnRleHQuY29tL3YxIgogICAgXSwKICAgICJpZCI6ICJodHRwOi8vYmFzZV91cmwvc3NpL2NyZWRlbnRpYWwvdjEvOWE0MTRhNjAtOWU2Yi00NzU3LTgwMTEtOWFhODcwZWY0Nzg4IiwKICAgICJ0eXBlIjogWwogICAgICAiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLAogICAgICAiVHlwZTEiCiAgICBdLAogICAgImNyZWRlbnRpYWxTdWJqZWN0IjogewogICAgICAiX3NkIjogWwogICAgICAgICJwRE9lOUNDaE0tWVJnSEJJTHlUMWtQVEJtQ3FickFla3QyeE9KTGI4SEVzIiwKICAgICAgICAiR0JjbThRWk8yUHI0bl9qbUpsUDRCeTFpd2NvVTBlUURWaGluMkFpZE1xNCIKICAgICAgXQogICAgfSwKICAgICJjcmVkZW50aWFsU3RhdHVzIjogewogICAgICAiaWQiOiAiaHR0cHM6Ly9wcm9jaXZpcy5jaC9zdGF0dXMvaWQiLAogICAgICAidHlwZSI6ICJUWVBFIiwKICAgICAgInN0YXR1c1B1cnBvc2UiOiAiUFVSUE9TRSIKICAgIH0sCiAgICAiY3JlZGVudGlhbFNjaGVtYSI6IHsKICAgICAgImlkIjogImh0dHBzOi8vcHJvY2l2aXMuY2gvY3JlZGVudGlhbC1zY2hlbWEvaWQiLAogICAgICAidHlwZSI6ICJQcm9jaXZpc09uZVNjaGVtYTIwMjQiCiAgICB9CiAgfSwKICAiX3NkX2FsZyI6ICJzaGEtMjU2Igp9";
    let token = format!(
        "{jwt_token}.QUJD~WyJNVEl6WVdKaiIsImFycmF5IixbImFycmF5X2l0ZW0iXV0~WyJNVEl6WVdKaiIs\
            Im5lc3RlZCIsIm5lc3RlZF9pdGVtIl0~WyJNVEl6WVdKaiIsInJvb3QiLHsiX3NkIjpbIldRbmQycW\
            xNa3U3RzVJdE01M1FSdmRVZjRHYWNYR3pMV3ZUTl93RGhhcmMiLCJyNjllcWUwN1M5ckUyN0luZy1s\
            OTk3b2ZnODVSU19uUnVWWHVjVlE5RWh3Il19XQ~WyJNVEl6WVdKaiIsInJvb3RfaXRlbSIsInJvb3R\
            faXRlbSJd~"
    );

    let claim1 = "[\"MTIzYWJj\",\"array\",[\"array_item\"]]";
    let claim2 = "[\"MTIzYWJj\",\"nested\",\"nested_item\"]";
    let claim3 = "[\"MTIzYWJj\",\"root\",{\"_sd\":[\"WQnd2qlMku7G5ItM53QRvdUf4GacXGzLWvTN_wDharc\",\"r69eqe07S9rE27Ing-l997ofg85RS_nRuVXucVQ9Ehw\"]}]";
    let claim4 = "[\"MTIzYWJj\",\"root_item\",\"root_item\"]";

    let mut hasher = MockHasher::default();
    hasher
        .expect_hash_base64_url()
        .withf(move |disclosure| {
            disclosure == base64_urlsafe(claim1).as_bytes() || disclosure == claim1.as_bytes()
        })
        .returning(|_| Ok("WQnd2qlMku7G5ItM53QRvdUf4GacXGzLWvTN_wDharc".to_string()));
    hasher
        .expect_hash_base64_url()
        .withf(move |disclosure| {
            disclosure == base64_urlsafe(claim2).as_bytes() || disclosure == claim2.as_bytes()
        })
        .returning(|_| Ok("r69eqe07S9rE27Ing-l997ofg85RS_nRuVXucVQ9Ehw".to_string()));
    hasher
        .expect_hash_base64_url()
        .withf(move |disclosure| {
            disclosure == base64_urlsafe(claim3).as_bytes() || disclosure == claim3.as_bytes()
        })
        .returning(|_| Ok("pDOe9CChM-YRgHBILyT1kPTBmCqbrAekt2xOJLb8HEs".to_string()));
    hasher
        .expect_hash_base64_url()
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
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
        data_type_provider: Arc::new(MockDataTypeProvider::new()),
        params: Params {
            leeway,
            embed_layout_properties: false,
            sd_array_elements: true,
            expiration_time: Duration::days(1),
        },
        client: Arc::new(MockHttpClient::new()),
    };

    let mut verify_mock = MockTokenVerifier::new();
    verify_mock
        .expect_verify()
        .withf(
            move |params, algorithm, token, signature| {
                assert!(matches!(params, PublicKeySource::Did {did, ..} if did.to_string() == "did:issuer:123"));
                assert_eq!(KeyAlgorithmType::Eddsa, *algorithm);
                assert_eq!(jwt_token.as_bytes(), token);
                assert_eq!(vec![65u8, 66, 67], signature);
                true
            },
        )
        .return_once(|_, _,  _, _| Ok(()));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .once()
        .returning(|_| {
            let mut key_algorithm = MockKeyAlgorithm::default();
            key_algorithm
                .expect_algorithm_type()
                .return_once(|| KeyAlgorithmType::Eddsa);

            Some((KeyAlgorithmType::Eddsa, Arc::new(key_algorithm)))
        });
    verify_mock
        .expect_key_algorithm_provider()
        .return_const(Box::new(key_algorithm_provider));

    let credentials = sd_formatter
        .extract_credentials(&token, None, Box::new(verify_mock))
        .await
        .unwrap();

    let root_item = &credentials.claims.claims.get("root_item").unwrap().value;
    assert_eq!(root_item.as_str(), Some("root_item"));

    let root = credentials
        .claims
        .claims
        .get("root")
        .unwrap()
        .value
        .as_object()
        .unwrap();
    let nested = &root.get("nested").unwrap().value;
    assert_eq!(nested.as_str(), Some("nested_item"));

    let array = root.get("array").unwrap().value.as_array().unwrap();
    assert_eq!(array[0].value.as_str(), Some("array_item"));
}

#[tokio::test]
async fn test_extract_credentials_with_array_stripped() {
    let jwt_token = "ewogICJhbGciOiAiYWxnb3JpdGhtIiwKICAia2lkIjogIiNrZXkwIiwKICAidHlwIjogIlNESldUIgp9.ewogICJpYXQiOiAxNzE4MzU5MDYzLAogICJleHAiOiAxNzgxNDMxMDYzLAogICJuYmYiOiAxNzE4MzU5MDE4LAogICJpc3MiOiAiZGlkOmlzc3VlcjoxMjMiLAogICJzdWIiOiAiZGlkOmhvbGRlcjoxMjMiLAogICJqdGkiOiAiaHR0cDovL2Jhc2VfdXJsL3NzaS9jcmVkZW50aWFsL3YxLzlhNDE0YTYwLTllNmItNDc1Ny04MDExLTlhYTg3MGVmNDc4OCIsCiAgInZjIjogewogICAgIkBjb250ZXh0IjogWwogICAgICAiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLAogICAgICAiaHR0cHM6Ly93d3cudHlwZTFjdHgub3JnIgogICAgXSwKICAgICJpZCI6ICJodHRwOi8vYmFzZV91cmwvc3NpL2NyZWRlbnRpYWwvdjEvOWE0MTRhNjAtOWU2Yi00NzU3LTgwMTEtOWFhODcwZWY0Nzg4IiwKICAgICJ0eXBlIjogWwogICAgICAiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLAogICAgICAiVHlwZTEiCiAgICBdLAogICAgImNyZWRlbnRpYWxTdWJqZWN0IjogewogICAgICAiX3NkIjogWwogICAgICAgICJwRE9lOUNDaE0tWVJnSEJJTHlUMWtQVEJtQ3FickFla3QyeE9KTGI4SEVzIiwKICAgICAgICAiR0JjbThRWk8yUHI0bl9qbUpsUDRCeTFpd2NvVTBlUURWaGluMkFpZE1xNCIKICAgICAgXQogICAgfSwKICAgICJjcmVkZW50aWFsU3RhdHVzIjogewogICAgICAiaWQiOiAiaHR0cHM6Ly9wcm9jaXZpcy5jaC9zdGF0dXMvaWQiLAogICAgICAidHlwZSI6ICJUWVBFIiwKICAgICAgInN0YXR1c1B1cnBvc2UiOiAiUFVSUE9TRSIKICAgIH0sCiAgICAiY3JlZGVudGlhbFNjaGVtYSI6IHsKICAgICAgImlkIjogImh0dHBzOi8vcHJvY2l2aXMuY2gvY3JlZGVudGlhbC1zY2hlbWEvaWQiLAogICAgICAidHlwZSI6ICJQcm9jaXZpc09uZVNjaGVtYTIwMjQiCiAgICB9CiAgfSwKICAiX3NkX2FsZyI6ICJzaGEtMjU2Igp9";
    let token = format!(
        "{jwt_token}.QUJD~WyJNVEl6WVdKaiIsImFycmF5IixbImFycmF5X2l0ZW0iXV0~WyJNVEl6WVdKaiIsInJvb3QiLHsiX3NkIjpbIldRbmQycW\
            xNa3U3RzVJdE01M1FSdmRVZjRHYWNYR3pMV3ZUTl93RGhhcmMiLCJyNjllcWUwN1M5ckUyN0luZy1s\
            OTk3b2ZnODVSU19uUnVWWHVjVlE5RWh3Il19XQ~WyJNVEl6WVdKaiIsInJvb3RfaXRlbSIsInJvb3R\
            faXRlbSJd~"
    );

    let claim1 = "[\"MTIzYWJj\",\"array\",[\"array_item\"]]";
    let claim2 = "[\"MTIzYWJj\",\"nested\",\"nested_item\"]";
    let claim3 = "[\"MTIzYWJj\",\"root\",{\"_sd\":[\"WQnd2qlMku7G5ItM53QRvdUf4GacXGzLWvTN_wDharc\",\"r69eqe07S9rE27Ing-l997ofg85RS_nRuVXucVQ9Ehw\"]}]";
    let claim4 = "[\"MTIzYWJj\",\"root_item\",\"root_item\"]";

    let mut hasher = MockHasher::default();
    hasher
        .expect_hash_base64_url()
        .withf(move |disclosure| {
            disclosure == base64_urlsafe(claim1).as_bytes() || disclosure == claim1.as_bytes()
        })
        .returning(|_| Ok("WQnd2qlMku7G5ItM53QRvdUf4GacXGzLWvTN_wDharc".to_string()));
    hasher
        .expect_hash_base64_url()
        .never()
        .withf(move |disclosure| {
            disclosure == base64_urlsafe(claim2).as_bytes() || disclosure == claim2.as_bytes()
        })
        .returning(|_| Ok("r69eqe07S9rE27Ing-l997ofg85RS_nRuVXucVQ9Ehw".to_string()));
    hasher
        .expect_hash_base64_url()
        .withf(move |disclosure| {
            disclosure == base64_urlsafe(claim3).as_bytes() || disclosure == claim3.as_bytes()
        })
        .returning(|_| Ok("pDOe9CChM-YRgHBILyT1kPTBmCqbrAekt2xOJLb8HEs".to_string()));
    hasher
        .expect_hash_base64_url()
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
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
        data_type_provider: Arc::new(MockDataTypeProvider::new()),
        params: Params {
            leeway,
            embed_layout_properties: false,
            sd_array_elements: true,
            expiration_time: Duration::days(1),
        },
        client: Arc::new(MockHttpClient::new()),
    };

    let mut verify_mock = MockTokenVerifier::new();
    verify_mock
        .expect_verify()
        .withf(
            move |params, algorithm, token, signature| {
                assert!(matches!(params, PublicKeySource::Did {did, ..} if did.to_string() == "did:issuer:123"));
                assert_eq!(KeyAlgorithmType::Eddsa, *algorithm);
                assert_eq!(jwt_token.as_bytes(), token);
                assert_eq!(vec![65u8, 66, 67], signature);
                true
            },
        )
        .return_once(|_,  _, _, _| Ok(()));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .once()
        .returning(|_| {
            let mut key_algorithm = MockKeyAlgorithm::default();
            key_algorithm
                .expect_algorithm_type()
                .return_once(|| KeyAlgorithmType::Eddsa);

            Some((KeyAlgorithmType::Eddsa, Arc::new(key_algorithm)))
        });
    verify_mock
        .expect_key_algorithm_provider()
        .return_const(Box::new(key_algorithm_provider));

    let credential = sd_formatter
        .extract_credentials(&token, None, Box::new(verify_mock))
        .await
        .unwrap();

    let root_item = &credential.claims.claims.get("root_item").unwrap().value;
    assert_eq!(root_item.as_str(), Some("root_item"));

    let expected: HashMap<String, CredentialClaim> = hashmap! {
        "root".into() => CredentialClaim {
            selectively_disclosable: true,
            metadata: false,
            value: CredentialClaimValue::Object(
                hashmap! {
                    "array".into() => CredentialClaim {
                            selectively_disclosable: true,
                            metadata: false,
                            value: json!(["array_item"]).try_into().unwrap(), // individual items not selectively disclosable
                        },
                }
            )
        },
        "root_item".into() => CredentialClaim {
            selectively_disclosable: true,
            metadata: false,
            value: json!("root_item").try_into().unwrap(),
        },
        "jti".into()=> CredentialClaim {
            selectively_disclosable: false,
            metadata: true,
            value: CredentialClaimValue::String("http://base_url/ssi/credential/v1/9a414a60-9e6b-4757-8011-9aa870ef4788".to_owned())
        },
        "sub".into()=> CredentialClaim {
            selectively_disclosable: false,
            metadata: true,
            value: CredentialClaimValue::String("did:holder:123".to_owned()),
        },
        "iss".into()=> CredentialClaim {
            selectively_disclosable: false,
            metadata: true,
            value:  CredentialClaimValue::String("did:issuer:123".to_owned()),
        },
        "exp".into()=> CredentialClaim {
            selectively_disclosable: false,
            metadata: true,
            value: json!(credential.valid_until.unwrap().unix_timestamp()).try_into().unwrap(),
        },
        "vc".into()=> CredentialClaim {
            selectively_disclosable: false,
            metadata: true,
            value: CredentialClaimValue::Object(
                hashmap! {
                    "id".into()=> CredentialClaim {
                        selectively_disclosable: false,
                        metadata: true,
                        value: CredentialClaimValue::String(
                            "http://base_url/ssi/credential/v1/9a414a60-9e6b-4757-8011-9aa870ef4788".to_owned()),
                    },
                    "type".into()=> CredentialClaim {
                        selectively_disclosable: false,
                        metadata: true,
                        value: CredentialClaimValue::Array(
                            vec![
                                CredentialClaim {
                                    selectively_disclosable: false,
                                    metadata: true,
                                    value: CredentialClaimValue::String("VerifiableCredential".to_owned(),),
                                },
                                CredentialClaim {
                                    selectively_disclosable: false,
                                    metadata: true,
                                    value: CredentialClaimValue::String("Type1".to_owned()),
                                },
                            ],
                        ),
                    },
                },
            ),
        },
        "iat".into()=> CredentialClaim {
            selectively_disclosable: false,
            metadata: true,
            value: json!(credential.issuance_date.unwrap().unix_timestamp()).try_into().unwrap(),
        },
        "nbf".into()=> CredentialClaim {
            selectively_disclosable: false,
            metadata: true,
            value: json!(credential.invalid_before.unwrap().unix_timestamp()).try_into().unwrap(),
        },
    };
    assert_eq!(credential.claims.claims, expected);
}

#[test]
fn test_get_capabilities() {
    let sd_formatter = SDJWTFormatter {
        crypto: Arc::new(MockCryptoProvider::default()),
        did_method_provider: Arc::new(MockDidMethodProvider::new()),
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
        data_type_provider: Arc::new(MockDataTypeProvider::new()),
        params: Params {
            leeway: 123u64,
            embed_layout_properties: false,
            sd_array_elements: true,
            expiration_time: Duration::days(1),
        },
        client: Arc::new(MockHttpClient::new()),
    };

    assert_eq!(
        vec![
            Features::SelectiveDisclosure,
            Features::SupportsCredentialDesign,
            Features::SupportsCombinedPresentation,
            Features::SupportsTxCode
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
    let credential_subject =
        VcdmCredentialSubject::new(nest_claims(claims.clone()).unwrap()).unwrap();

    let vcdm = VcdmCredential::new_v2(issuer_did, credential_subject)
        .add_context(schema_context)
        .add_credential_schema(schema)
        .add_credential_status(status)
        .with_valid_from(issuance_date)
        .with_valid_until(issuance_date + valid_for);

    let holder_identifier = Identifier {
        did: Some(Did {
            did: holder_did,
            ..dummy_did()
        }),
        ..dummy_identifier()
    };
    CredentialData {
        vcdm,
        claims,
        holder_identifier: Some(holder_identifier),
        holder_key_id: Some("did-vm-id".to_string()),
        issuer_certificate: None,
    }
}

fn base64_urlsafe(s: &str) -> String {
    Base64UrlSafeNoPadding::encode_to_string(s).unwrap()
}

#[tokio::test]
async fn test_parse_credential() {
    const CREDENTIAL: &str = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVidnlWcHdHM1I3UWoxem5yVnk5cnRzaTZOOFRnaldQS1poeUJkYTJxdjU4dyN6RG5hZWJ2eVZwd0czUjdRajF6bnJWeTlydHNpNk44VGdqV1BLWmh5QmRhMnF2NTh3IiwidHlwIjoiU0RfSldUIn0.eyJpYXQiOjE3NjA1NDEyNzcsImV4cCI6MTgyMzYxMzI3NywibmJmIjoxNzYwNTQxMjc3LCJpc3MiOiJkaWQ6a2V5OnpEbmFlYnZ5VnB3RzNSN1FqMXpuclZ5OXJ0c2k2TjhUZ2pXUEtaaHlCZGEycXY1OHciLCJzdWIiOiJkaWQ6a2V5OnpEbmFla29NQzJzRmtnY0ZMcDNLNG5uR1VGVXFZbzhnb1dzanQzc0FmaE5BVjlFUzkiLCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiTHFQNWlyNGFYRW5na3N3SnZIeEpoLVFDUmNLYjBDZzBiUkxCMXZydUVXWSIsInkiOiJXLVNfZUlPbHp1d1BGcVpaYzBkZFlSbDNOVzZNdlRTQUtXMkpKS3lkNjJVIn19LCJ2YyI6eyJpc3N1ZXIiOiJkaWQ6a2V5OnpEbmFlYnZ5VnB3RzNSN1FqMXpuclZ5OXJ0c2k2TjhUZ2pXUEtaaHlCZGEycXY1OHciLCJ2YWxpZEZyb20iOiIyMDI1LTEwLTE1VDE1OjE0OjM3LjgyMTU4NzAxOFoiLCJ2YWxpZFVudGlsIjoiMjAyNy0xMC0xNVQxNToxNDozNy44MjE1ODcwMThaIiwiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaHR0cHM6Ly9jb3JlLmRldi5wcm9jaXZpcy1vbmUuY29tL3NzaS9jb250ZXh0L3YxLzMwOTk0ODg5LTJkYzYtNGE4Mi1hYzQxLTc0ZWM1Y2MxODdiYSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiQXJyYXlzQW5kT2JqZWN0cyJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJfc2QiOlsiUFdxMVZFRVRuTDBsWWU0OG84QllrWnRzdzZFSGltZ1c5MmNHcXZ1REtmQSIsInA4b0t2YzEzeHJxYUdpeFVZbjdfU00wM2RjM2hkSG5uTmhVdjRyVy1yY0EiLCJ3WWRoOGZibW1kbThHREVCQ0xvaVZ5ZGEzRFZlUEFMX01vZW52NWRDRjdZIl19LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoidXJuOnV1aWQ6ZjZkOWVmNDUtNWNlYy00ZTA2LWFlZjMtODExN2JjMmRlZTdhIiwidHlwZSI6IkJpdHN0cmluZ1N0YXR1c0xpc3RFbnRyeSIsInN0YXR1c1B1cnBvc2UiOiJyZXZvY2F0aW9uIiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwczovL2NvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20vc3NpL3Jldm9jYXRpb24vdjEvbGlzdC82NWZhOTUwNS0wNTVkLTRkNDAtODI2MC1jZGY2ODBmOWQ5YzciLCJzdGF0dXNMaXN0SW5kZXgiOiI3In0sImNyZWRlbnRpYWxTY2hlbWEiOnsiaWQiOiJodHRwczovL2NvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20vc3NpL3NjaGVtYS92MS8zMDk5NDg4OS0yZGM2LTRhODItYWM0MS03NGVjNWNjMTg3YmEiLCJ0eXBlIjoiUHJvY2l2aXNPbmVTY2hlbWEyMDI0In19LCJfc2RfYWxnIjoic2hhLTI1NiJ9.aq6OyVAF39Zx6KZsUq6dBbfTR5uVofnf2mAkBZVglfc6Hdvf-PIlI161XXCn7hp4vw_Zi8e0bCDkW-93YgUpKg~WyJ5ZjJKSGktSzI2UFFDU0lnYllCamdRIiwiaG91c2UiLCJ0ZXN0IGhvdXNlIl0~WyI0Vm1KVHY1U2R3emNvV2gzRnhsYjBBIiwic3RyZWV0IiwidGVzdCBzdHJlZXQiXQ~WyJLNnNUaEJfcm02a1h4c0ZudXBSTGhnIiwiQWRkcmVzcyIseyJfc2QiOlsiS19pT1EybVFXSl9Zekt1VEhWSEdVZDVoUUVBTVVjakVmUFZFUlBDTk5LNCIsImVTTjVxemVuZXFaT2JpQXluQ1NrMWlZR3VDeUhNVm5MNXhXWWJpY2hYUzgiXX1d~WyJJZC13bDZPVjRwQVdrbUt1bkFWemRRIiwiTmFtZSIsIlRlc3QgTmFtZSJd~WyJ4MGp6dGhHNGplRFlBNnZHQjk5b09RIiwiQ0giXQ~WyJ2cFNBbnZ3R0hkUldoVXctNDZuVE5BIiwiVVQiXQ~WyJwUjdpa3RRaVVUeTRxMTFySGg4eURRIiwiTmF0aW9uYWxpdGllcyIsW3siLi4uIjoidDNGek1kTlFXbU5OLUNlSk1tdGx0T3lrd1MxeTdyLW5SeU5vd2tLU0hPOCJ9LHsiLi4uIjoiaWxDdWpaQWxZWlFuWWpsZTJfNmlELWFIdWc1NG1kWWFsMXdYOWkteXUtayJ9XV0~";

    let params = Params {
        leeway: 60,
        embed_layout_properties: false,
        sd_array_elements: true,
        expiration_time: Duration::days(1),
    };

    let hashers = hashmap! {
        "sha-256".to_string() => Arc::new(SHA256) as Arc<dyn one_crypto::Hasher>
    };
    let crypto = Arc::new(one_crypto::CryptoProviderImpl::new(hashers));

    let mut datatype_provider = crate::provider::data_type::provider::MockDataTypeProvider::new();
    datatype_provider
        .expect_extract_json_claim()
        .returning(|value| {
            use crate::provider::data_type::model::ExtractedClaim;
            match value {
                serde_json::Value::Bool(b) => Ok(ExtractedClaim {
                    data_type: "BOOLEAN".to_string(),
                    value: b.to_string(),
                }),
                serde_json::Value::String(s) => Ok(ExtractedClaim {
                    data_type: "STRING".to_string(),
                    value: s.clone(),
                }),
                serde_json::Value::Number(n) => Ok(ExtractedClaim {
                    data_type: "NUMBER".to_string(),
                    value: n.to_string(),
                }),
                _ => Err(
                    crate::provider::data_type::error::DataTypeProviderError::UnableToExtract(
                        crate::provider::data_type::model::JsonOrCbor::Json(value.clone()),
                    ),
                ),
            }
        });

    let formatter = SDJWTFormatter::new(
        params,
        crypto,
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(datatype_provider),
        Arc::new(MockHttpClient::new()),
    );
    let mut verify_mock = MockTokenVerifier::new();
    verify_mock.expect_verify().return_once(|_, _, _, _| Ok(()));
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .once()
        .returning(|_| {
            let mut key_algorithm = MockKeyAlgorithm::default();
            key_algorithm
                .expect_algorithm_type()
                .return_once(|| KeyAlgorithmType::Eddsa);

            Some((KeyAlgorithmType::Eddsa, Arc::new(key_algorithm)))
        });
    verify_mock
        .expect_key_algorithm_provider()
        .return_const(Box::new(key_algorithm_provider));
    let result = formatter
        .parse_credential(CREDENTIAL, Box::new(verify_mock))
        .await
        .unwrap();

    // Verify basic credential properties
    assert!(result.claims.is_some());
    let claims = result.claims.as_ref().unwrap();

    // Should have parsed claims including disclosed ones and metadata
    assert!(!claims.is_empty());

    // Verify issuer identifier
    assert!(result.issuer_identifier.is_some());
    let issuer = result.issuer_identifier.as_ref().unwrap();
    assert!(issuer.did.is_some());
    assert_eq!(
        issuer.did.as_ref().unwrap().did.to_string(),
        "did:key:zDnaebvyVpwG3R7Qj1znrVy9rtsi6N8TgjWPKZhyBda2qv58w"
    );

    // Verify holder identifier
    assert!(result.holder_identifier.is_some());
    let holder = result.holder_identifier.as_ref().unwrap();
    assert!(holder.did.is_some());
    assert_eq!(
        holder.did.as_ref().unwrap().did.to_string(),
        "did:key:zDnaekoMC2sFkgcFLp3K4nnGUFUqYo8goWsjt3sAfhNAV9ES9"
    );

    // Verify credential schema
    assert!(result.schema.is_some());
    let schema = result.schema.as_ref().unwrap();
    assert_eq!(schema.name, "ArraysAndObjects");
    assert_eq!(
        schema.schema_id,
        "https://core.dev.procivis-one.com/ssi/schema/v1/30994889-2dc6-4a82-ac41-74ec5cc187ba"
    );

    // Verify disclosed claims exist
    let name_claim = claims.iter().find(|c| c.path == "Name");
    assert!(name_claim.is_some());
    let name_claim = name_claim.unwrap();
    assert_eq!(name_claim.value.as_deref(), Some("Test Name"));
    assert_eq!(name_claim.selectively_disclosable, true);
    assert!(name_claim.schema.is_some());
    assert_eq!(name_claim.schema.as_ref().unwrap().key, "Name");
    assert_eq!(name_claim.schema.as_ref().unwrap().data_type, "STRING");
    assert_eq!(name_claim.schema.as_ref().unwrap().array, false);

    // Verify Address object claim
    let address_claim = claims.iter().find(|c| c.path == "Address");
    assert!(address_claim.is_some());
    let address_claim = address_claim.unwrap();
    assert_eq!(address_claim.value, None); // Object claims don't have values
    assert_eq!(address_claim.selectively_disclosable, true);
    assert!(address_claim.schema.is_some());
    assert_eq!(address_claim.schema.as_ref().unwrap().key, "Address");
    assert_eq!(address_claim.schema.as_ref().unwrap().data_type, "OBJECT");

    // Verify nested Address claims
    let house_claim = claims.iter().find(|c| c.path == "Address/house");
    assert!(house_claim.is_some());
    let house_claim = house_claim.unwrap();
    assert_eq!(house_claim.value.as_deref(), Some("test house"));
    assert_eq!(house_claim.selectively_disclosable, true); // nested claims can be individually disclosed
    assert_eq!(house_claim.schema.as_ref().unwrap().key, "Address/house");

    let street_claim = claims.iter().find(|c| c.path == "Address/street");
    assert!(street_claim.is_some());
    let street_claim = street_claim.unwrap();
    assert_eq!(street_claim.value.as_deref(), Some("test street"));
    assert_eq!(street_claim.selectively_disclosable, true);
    assert_eq!(street_claim.schema.as_ref().unwrap().key, "Address/street");

    // Verify Nationalities array
    let nationalities_array = claims.iter().find(|c| c.path == "Nationalities");
    assert!(nationalities_array.is_some());
    let nationalities_array = nationalities_array.unwrap();
    assert_eq!(nationalities_array.value, None); // Array claims don't have values
    assert_eq!(nationalities_array.selectively_disclosable, true);
    assert!(nationalities_array.schema.is_some());
    assert_eq!(
        nationalities_array.schema.as_ref().unwrap().key,
        "Nationalities"
    );
    assert_eq!(nationalities_array.schema.as_ref().unwrap().array, true);

    // Verify array elements
    let ch_claim = claims.iter().find(|c| c.path == "Nationalities/0");
    assert!(ch_claim.is_some());
    let ch_claim = ch_claim.unwrap();
    assert_eq!(ch_claim.value.as_deref(), Some("CH"));
    assert_eq!(ch_claim.schema.as_ref().unwrap().array, true);

    let ut_claim = claims.iter().find(|c| c.path == "Nationalities/1");
    assert!(ut_claim.is_some());
    let ut_claim = ut_claim.unwrap();
    assert_eq!(ut_claim.value.as_deref(), Some("UT"));

    // Verify metadata claims
    let vc_claim = claims.iter().find(|c| c.path == "vc");
    assert!(vc_claim.is_some());
    let vc_claim = vc_claim.unwrap();
    assert_eq!(vc_claim.selectively_disclosable, false);
    assert!(vc_claim.schema.is_some());
    assert_eq!(vc_claim.schema.as_ref().unwrap().metadata, true);

    // Verify claim schemas are deduplicated
    assert!(schema.claim_schemas.is_some());
    let claim_schemas = schema.claim_schemas.as_ref().unwrap();

    // Array schema should be present (array:true)
    let nationalities_schema = claim_schemas
        .iter()
        .find(|s| s.schema.key == "Nationalities");
    assert!(nationalities_schema.is_some());
    assert_eq!(nationalities_schema.unwrap().schema.array, true);

    // Individual claims should reuse schema IDs
    let ch_schema_id = ch_claim.schema.as_ref().unwrap().id;
    let ut_schema_id = ut_claim.schema.as_ref().unwrap().id;
    assert_eq!(ch_schema_id, ut_schema_id); // Both array elements share same schema ID

    // Verify revocation method
    assert_eq!(schema.revocation_method, Some("BITSTRINGSTATUSLIST".into()));
}

#[tokio::test]
async fn test_parse_credential_with_lvvc() {
    // This credential has LVVC as the revocation method
    const CREDENTIAL: &str = "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWI6Y29yZS5kZXYucHJvY2l2aXMtb25lLmNvbTpzc2k6ZGlkLXdlYjp2MTphYmE1ZjljNy03Yjk1LTQ0OTItODJlMi05N2VmY2I5Yjk5MDMja2V5LTliNzcxZmYxLWFiZTEtNDNmNS1hMWJiLWMzNGJhM2UyNzUzYyIsInR5cCI6IlNEX0pXVCJ9.eyJpYXQiOjE3NjA1NDIyMjAsImV4cCI6MTgyMzYxNDIyMCwibmJmIjoxNzYwNTQyMjIwLCJpc3MiOiJkaWQ6d2ViOmNvcmUuZGV2LnByb2NpdmlzLW9uZS5jb206c3NpOmRpZC13ZWI6djE6YWJhNWY5YzctN2I5NS00NDkyLTgyZTItOTdlZmNiOWI5OTAzIiwic3ViIjoiZGlkOmtleTp6RG5hZWtvTUMyc0ZrZ2NGTHAzSzRubkdVRlVxWW84Z29Xc2p0M3NBZmhOQVY5RVM5IiwianRpIjoidXJuOnV1aWQ6ZjcwOTZkM2QtYmY2Ny00ZTBiLTk3MTYtYzA3OWY4YWVkNjJlIiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IkxxUDVpcjRhWEVuZ2tzd0p2SHhKaC1RQ1JjS2IwQ2cwYlJMQjF2cnVFV1kiLCJ5IjoiVy1TX2VJT2x6dXdQRnFaWmMwZGRZUmwzTlc2TXZUU0FLVzJKSkt5ZDYyVSJ9fSwidmMiOnsiaXNzdWVyIjoiZGlkOndlYjpjb3JlLmRldi5wcm9jaXZpcy1vbmUuY29tOnNzaTpkaWQtd2ViOnYxOmFiYTVmOWM3LTdiOTUtNDQ5Mi04MmUyLTk3ZWZjYjliOTkwMyIsInZhbGlkRnJvbSI6IjIwMjUtMTAtMTVUMTU6MzA6MjAuNDg2ODg0ODMzWiIsInZhbGlkVW50aWwiOiIyMDI3LTEwLTE1VDE1OjMwOjIwLjQ4Njg4NDgzM1oiLCJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL2NvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20vc3NpL2NvbnRleHQvdjEvbHZ2Yy5qc29uIiwiaHR0cHM6Ly9jb3JlLmRldi5wcm9jaXZpcy1vbmUuY29tL3NzaS9jb250ZXh0L3YxLzQ2OWJjMGYyLTlmZjMtNDg5ZC04ODc5LWMxZjNhZjliY2VmYiJdLCJpZCI6InVybjp1dWlkOmY3MDk2ZDNkLWJmNjctNGUwYi05NzE2LWMwNzlmOGFlZDYyZSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJUZXN0MjM0Il0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Il9zZCI6WyJZdWx3YXhXZGZZNFZENkdXQnhteFlzWWxZeUJkYlZrZFc2Vm1KYnlQbEpRIl19LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiaHR0cHM6Ly9jb3JlLmRldi5wcm9jaXZpcy1vbmUuY29tL3NzaS9yZXZvY2F0aW9uL3YxL2x2dmMvZjcwOTZkM2QtYmY2Ny00ZTBiLTk3MTYtYzA3OWY4YWVkNjJlIiwidHlwZSI6IkxWVkMifSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vY29yZS5kZXYucHJvY2l2aXMtb25lLmNvbS9zc2kvc2NoZW1hL3YxLzQ2OWJjMGYyLTlmZjMtNDg5ZC04ODc5LWMxZjNhZjliY2VmYiIsInR5cGUiOiJQcm9jaXZpc09uZVNjaGVtYTIwMjQifX0sIl9zZF9hbGciOiJzaGEtMjU2In0.BAatDC1kYd4UOlqPmpgc5MTmYYbTN3TvmZqIYbIerB-4JvrojP0OYnvt9qxcS3qHQAsRDVbV9_aZgrMbSmCBBQ~WyJXenBBeHltOGd1UnV6VW1aRjBGUGJ3IiwiTmFtZSIsIlRlc3QgTmFtZSJd~";

    let params = Params {
        leeway: 60,
        embed_layout_properties: false,
        sd_array_elements: true,
        expiration_time: Duration::days(1),
    };

    let hashers = hashmap! {
        "sha-256".to_string() => Arc::new(SHA256) as Arc<dyn one_crypto::Hasher>
    };
    let crypto = Arc::new(one_crypto::CryptoProviderImpl::new(hashers));

    let mut datatype_provider = crate::provider::data_type::provider::MockDataTypeProvider::new();
    datatype_provider
        .expect_extract_json_claim()
        .returning(|json_value| {
            use crate::provider::data_type::model::ExtractedClaim;
            Ok(ExtractedClaim {
                data_type: "STRING".to_string(),
                value: json_value.to_string().trim_matches('"').to_string(),
            })
        });

    let formatter = SDJWTFormatter::new(
        params,
        crypto.clone(),
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(datatype_provider),
        Arc::new(MockHttpClient::new()),
    );
    let mut verify_mock = MockTokenVerifier::new();
    verify_mock.expect_verify().return_once(|_, _, _, _| Ok(()));
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .once()
        .returning(|_| {
            let mut key_algorithm = MockKeyAlgorithm::default();
            key_algorithm
                .expect_algorithm_type()
                .return_once(|| KeyAlgorithmType::Eddsa);

            Some((KeyAlgorithmType::Eddsa, Arc::new(key_algorithm)))
        });
    verify_mock
        .expect_key_algorithm_provider()
        .return_const(Box::new(key_algorithm_provider));
    let credential = formatter
        .parse_credential(CREDENTIAL, Box::new(verify_mock))
        .await
        .unwrap();

    // Verify revocation method is LVVC
    let schema = credential.schema.as_ref().unwrap();
    assert_eq!(schema.revocation_method, Some("LVVC".into()));
}
