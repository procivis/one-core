use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use maplit::hashmap;
use mockall::predicate::eq;
use one_crypto::hasher::sha256::SHA256;
use one_crypto::signer::eddsa::EDDSASigner;
use one_crypto::{CryptoProviderImpl, Hasher, MockCryptoProvider, MockHasher, Signer};
use serde_json::json;
use shared_types::{CredentialSchemaId, DidValue, OrganisationId};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::model::credential_schema::LayoutType;
use crate::model::did::KeyRole;
use crate::model::key::Key;
use crate::provider::credential_formatter::common::MockAuth;
use crate::provider::credential_formatter::json_ld::model::ContextType;
use crate::provider::credential_formatter::jwt::model::JWTPayload;
use crate::provider::credential_formatter::model::{
    CredentialData, CredentialSchemaData, CredentialStatus, ExtractPresentationCtx, Issuer,
    MockSignatureProvider, MockTokenVerifier, PublishedClaim, PublishedClaimValue,
};
use crate::provider::credential_formatter::sdjwt::disclosures::DisclosureArray;
use crate::provider::credential_formatter::sdjwt::test::get_credential_data;
use crate::provider::credential_formatter::sdjwtvc_formatter::model::SDJWTVCVc;
use crate::provider::credential_formatter::sdjwtvc_formatter::{Params, SDJWTVCFormatter};
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::did_method::jwk::JWKDidMethod;
use crate::provider::did_method::provider::DidMethodProviderImpl;
use crate::provider::did_method::resolver::DidCachingLoader;
use crate::provider::did_method::DidMethod;
use crate::provider::key_algorithm::eddsa::{Eddsa, EddsaParams};
use crate::provider::key_algorithm::provider::KeyAlgorithmProviderImpl;
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::provider::remote_entity_storage::RemoteEntityType;
use crate::service::credential_schema::dto::CreateCredentialSchemaRequestDTO;
use crate::util::key_verification::KeyVerification;

#[tokio::test]
async fn test_format_credential() {
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
    assert_eq!(parts.len(), 4);

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
            r##"{"alg":"algorithm","kid":"#key0","typ":"vc+sd-jwt"}"##
        )
        .unwrap()
    );
    assert_eq!(
        jwt_parts[2],
        &Base64UrlSafeNoPadding::encode_to_string(r#"ABC"#).unwrap()
    );

    let payload: JWTPayload<SDJWTVCVc> = serde_json::from_str(
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

    let vc = payload.custom;

    assert!(vc
        .disclosures
        .iter()
        .all(|hashed_claim| hashed_claim == "YWJjMTIz"));

    assert!(vc.public_claims.is_empty()); // Empty until we support issuing public_claims
}

#[tokio::test]
async fn test_extract_credentials() {
    // Token from: https://paradym.id/tools/sd-jwt-vc
    let jwt_token = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rdHF0WE5HOENEVVk5UHJydG9TdEZ6ZUNuaHBNbWd4WUwxZ2lrY1czQnp2TlcifQ.eyJ2Y3QiOiJJZGVudGl0eUNyZWRlbnRpYWwiLCJmYW1pbHlfbmFtZSI6IkRvZSIsInBob25lX251bWJlciI6IisxLTIwMi01NTUtMDEwMSIsImFkZHJlc3MiOnsic3RyZWV0X2FkZHJlc3MiOiIxMjMgTWFpbiBTdCIsImxvY2FsaXR5IjoiQW55dG93biIsIl9zZCI6WyJOSm5tY3QwQnFCTUUxSmZCbEM2alJRVlJ1ZXZwRU9OaVl3N0E3TUh1SnlRIiwib201Wnp0WkhCLUdkMDBMRzIxQ1ZfeE00RmFFTlNvaWFPWG5UQUpOY3pCNCJdfSwiY25mIjp7Imp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Im9FTlZzeE9VaUg1NFg4d0pMYVZraWNDUmswMHdCSVE0c1JnYms1NE44TW8ifX0sImlzcyI6ImRpZDprZXk6ejZNa3RxdFhORzhDRFVZOVBycnRvU3RGemVDbmhwTW1neFlMMWdpa2NXM0J6dk5XIiwiaWF0IjoxNjk4MTUxNTMyLCJfc2QiOlsiMUN1cjJrMkEyb0lCNUNzaFNJZl9BX0tnLWwyNnVfcUt1V1E3OVAwVmRhcyIsIlIxelRVdk9ZSGdjZXBqMGpIeXBHSHo5RUh0dFZLZnQweXN3YmM5RVRQYlUiLCJlRHFRcGRUWEpYYldoZi1Fc0k3enc1WDZPdlltRk4tVVpRUU1lc1h3S1B3IiwicGREazJfWEFLSG83Z09BZndGMWI3T2RDVVZUaXQya0pIYXhTRUNROXhmYyIsInBzYXVLVU5XRWkwOW51M0NsODl4S1hnbXBXRU5abDV1eTFOMW55bl9qTWsiLCJzTl9nZTBwSFhGNnFtc1luWDFBOVNkd0o4Y2g4YUVOa3hiT0RzVDc0WXdJIl0sIl9zZF9hbGciOiJzaGEtMjU2In0";
    let token = format!(
        "{jwt_token}.QUJD~WyJzYWx0IiwicmVnaW9uIiwiQW55c3RhdGUiXQ~WyJzYWx0IiwiY291bnRyeSIsIlVTIl0~WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJzYWx0IiwiZW1haWwiLCJqb2huZG9lQGV4YW1wbGUuY29tIl0~WyJzYWx0IiwiYmlydGhkYXRlIiwiMTk0MC0wMS0wMSJd~WyJzYWx0IiwiaXNfb3Zlcl8xOCIsdHJ1ZV0~WyJzYWx0IiwiaXNfb3Zlcl8yMSIsdHJ1ZV0~WyJzYWx0IiwiaXNfb3Zlcl82NSIsdHJ1ZV0~"
    );

    let hasher = Arc::new(SHA256 {});

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

    let credentials = sd_formatter
        .extract_credentials_unverified(&token) //Box::new(verify_mock))
        .await
        .unwrap();

    assert_eq!(
        credentials.issuer_did,
        Some(DidValue::from(
            "did:key:z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW".to_string()
        ))
    );
    assert_eq!(credentials.subject, None);

    let expected_result = json!(
        {
            "is_over_18": true,
            "email": "johndoe@example.com",
            "phone_number": "+1-202-555-0101",
            "is_over_65": true,
            "given_name": "John",
            "birthdate": "1940-01-01",
            "address": {
                "street_address": "123 Main St",
                "locality": "Anytown",
                "region": "Anystate",
                "country": "US",
            },
            "is_over_21": true,
            "family_name": "Doe",
        }
    );

    let claim_values_as_json = credentials
        .claims
        .values
        .into_iter()
        .collect::<serde_json::Map<String, serde_json::Value>>();

    assert_eq!(claim_values_as_json, *expected_result.as_object().unwrap());
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

#[test]
fn test_schema_id() {
    let formatter = SDJWTVCFormatter::new(
        Params {
            leeway: 45u64,
            embed_layout_properties: false,
        },
        Arc::new(MockCryptoProvider::default()),
    );
    let vct_type = "xyz some_vct_type";
    let request_dto = CreateCredentialSchemaRequestDTO {
        name: "".to_string(),
        format: "".to_string(),
        revocation_method: "".to_string(),
        organisation_id: OrganisationId::from(Uuid::new_v4()),
        claims: vec![],
        wallet_storage_type: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: Some(vct_type.to_string()),
        allow_suspension: None,
    };

    let result = formatter.credential_schema_id(
        CredentialSchemaId::from(Uuid::new_v4()),
        &request_dto,
        "https://example.com",
    );
    assert!(result.is_ok());
    assert_eq!(
        result.unwrap(),
        format!(
            "https://example.com/ssi/vct/v1/{}/xyz%20some_vct_type",
            request_dto.organisation_id
        )
    )
}

#[tokio::test]
async fn test_format_extract_round_trip() {
    let now = OffsetDateTime::now_utc();
    let params = Params {
        leeway: 60,
        embed_layout_properties: false,
    };

    let caching_loader = DidCachingLoader::new(
        RemoteEntityType::DidDocument,
        Arc::new(InMemoryStorage::new(HashMap::new())),
        100,
        Duration::minutes(1),
        Duration::minutes(1),
    );

    let hashers = hashmap! {
        "sha-256".to_string() => Arc::new(SHA256 {}) as Arc<dyn Hasher>
    };
    let signers = hashmap! {
        "Ed25519".to_string() => Arc::new(EDDSASigner {}) as Arc<dyn Signer>,
    };
    let crypto = Arc::new(CryptoProviderImpl::new(hashers, signers));

    let key_alg = Eddsa::new(EddsaParams {
        algorithm: crate::provider::key_algorithm::eddsa::Algorithm::Ed25519,
    });
    let key_algorithm_provider = Arc::new(KeyAlgorithmProviderImpl::new(
        HashMap::from_iter(vec![(
            "EDDSA".to_owned(),
            Arc::new(key_alg) as Arc<dyn KeyAlgorithm>,
        )]),
        crypto.clone(),
    ));
    let key_pair = EDDSASigner::generate_key_pair();
    let key = Key {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        public_key: key_pair.public.clone(),
        name: "issuer key".to_string(),
        key_reference: vec![],
        storage_type: "INTERNAL".to_string(),
        key_type: "EDDSA".to_string(),
        organisation: None,
    };

    let issuer_did = JWKDidMethod::new(key_algorithm_provider.clone())
        .create(None, &None, Some(vec![key]))
        .await
        .unwrap();

    let credential_data = CredentialData {
        id: None,
        issuance_date: now,
        valid_for: Duration::seconds(10),
        claims: vec![
            PublishedClaim {
                key: "age".to_string(),
                value: PublishedClaimValue::Integer(22),
                datatype: Some("NUMBER".to_string()),
                array_item: false,
            },
            PublishedClaim {
                key: "object/name".to_string(),
                value: PublishedClaimValue::String("Mike".to_string()),
                datatype: Some("STRING".to_string()),
                array_item: false,
            },
            PublishedClaim {
                key: "is_over_18".to_string(),
                value: PublishedClaimValue::Bool(true),
                datatype: Some("BOOLEAN".to_string()),
                array_item: false,
            },
            PublishedClaim {
                key: "object/measurements/0/air pollution".to_string(),
                value: PublishedClaimValue::Float(24.6),
                datatype: Some("NUMBER".to_string()),
                array_item: true,
            },
        ],
        issuer_did: Issuer::Url(issuer_did.to_string().parse().unwrap()),
        status: vec![],
        schema: CredentialSchemaData {
            id: Some("credential-schema-id".to_string()),
            r#type: Some("FallbackSchema2024".to_string()),
            context: None,
            name: "credential-schema-name".to_string(),
            metadata: None,
        },
        name: None,
        description: None,
        terms_of_use: vec![],
        evidence: vec![],
        related_resource: None,
    };

    let did_method_provider = Arc::new(DidMethodProviderImpl::new(
        caching_loader,
        HashMap::from_iter(vec![(
            "JWK".to_owned(),
            Arc::new(JWKDidMethod::new(key_algorithm_provider.clone())) as Arc<dyn DidMethod>,
        )]),
        None,
    ));
    let formatter = SDJWTVCFormatter::new(params, crypto);

    let mut auth_fn = MockSignatureProvider::new();
    let public_key = key_pair.public.clone();
    let private_key = key_pair.private.clone();
    auth_fn
        .expect_sign()
        .returning(move |msg| EDDSASigner {}.sign(msg, &public_key.clone(), &private_key.clone()));
    auth_fn
        .expect_get_key_id()
        .returning(move || Some(format!("{}#0", issuer_did)));
    let public_key_clone = key_pair.public.clone();
    auth_fn
        .expect_get_public_key()
        .returning(move || public_key_clone.clone());

    let holder_did =
        DidValue::from_str("did:key:z6Mkv3HL52XJNh4rdtnPKPRndGwU8nAuVpE7yFFie5SNxZkX").unwrap();
    let key_verification = Box::new(KeyVerification {
        key_algorithm_provider,
        did_method_provider,
        key_role: KeyRole::AssertionMethod,
    });

    let token = formatter
        .format_credentials(
            credential_data,
            &Some(holder_did),
            "EDDSA",
            vec![],
            vec![],
            Box::new(auth_fn),
        )
        .await
        .unwrap();
    let result = formatter
        .extract_credentials(token.as_str(), key_verification)
        .await;

    assert2::let_assert!(Ok(credential) = result);
    assert_eq!(
        credential.claims.values,
        hashmap! {
            "object".into() => json!({
                "name": "Mike",
                "measurements": [{
                    "air pollution": 24.6
                }]
            }),
            "age".into() => json!(22),
            "is_over_18".into() => json!(true)
        }
    )
}
