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
use crate::provider::credential_formatter::jwt::model::JWTPayload;
use crate::provider::credential_formatter::model::{
    CredentialData, CredentialSchema, CredentialStatus, ExtractPresentationCtx, Issuer,
    MockSignatureProvider, MockTokenVerifier, PublishedClaim, PublishedClaimValue,
};
use crate::provider::credential_formatter::sdjwt::disclosures::DisclosureArray;
use crate::provider::credential_formatter::sdjwt::test::get_credential_data;
use crate::provider::credential_formatter::sdjwtvc_formatter::model::SdJwtVc;
use crate::provider::credential_formatter::sdjwtvc_formatter::{Params, SDJWTVCFormatter};
use crate::provider::credential_formatter::vcdm::{VcdmCredential, VcdmCredentialSubject};
use crate::provider::credential_formatter::{nest_claims, CredentialFormatter};
use crate::provider::did_method::jwk::JWKDidMethod;
use crate::provider::did_method::provider::DidMethodProviderImpl;
use crate::provider::did_method::resolver::DidCachingLoader;
use crate::provider::did_method::DidMethod;
use crate::provider::key_algorithm::eddsa::{Eddsa, EddsaParams};
use crate::provider::key_algorithm::provider::{
    KeyAlgorithmProviderImpl, MockKeyAlgorithmProvider,
};
use crate::provider::key_algorithm::{KeyAlgorithm, MockKeyAlgorithm};
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
        CredentialStatus {
            id: Some("did:status:id".parse().unwrap()),
            r#type: "TYPE".to_string(),
            status_purpose: Some("PURPOSE".to_string()),
            additional_fields: HashMap::from([("Field1".to_owned(), "Val1".into())]),
        },
        "http://base_url",
    );

    let auth_fn = MockAuth(|_| vec![65u8, 66, 67]);

    let result = sd_formatter
        .format_credential(credential_data, Box::new(auth_fn))
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
            r##"{"alg":"ES256","kid":"#key0","typ":"vc+sd-jwt"}"##
        )
        .unwrap()
    );
    assert_eq!(
        jwt_parts[2],
        &Base64UrlSafeNoPadding::encode_to_string(r#"ABC"#).unwrap()
    );

    let payload: JWTPayload<SdJwtVc> = serde_json::from_str(
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

    let vc = payload.custom;

    assert!(vc
        .digests
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
        Some(
            "did:key:z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW"
                .parse()
                .unwrap()
        )
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
        .claims
        .into_iter()
        .collect::<serde_json::Map<String, serde_json::Value>>();

    assert_eq!(claim_values_as_json, *expected_result.as_object().unwrap());
}

#[tokio::test]
async fn test_extract_presentation() {
    let jwt_token = "eyJhbGciOiJhbGdvcml0aG0iLCJ0eXAiOiJ2YytzZC1qd3QifSAK.ewogICJpYXQiOiAxNjk5MzUxODQxLAogICJleHAiOiAxNjk5MzUyMTQxLAogICJuYmYiOiAxNjk5MzUxNzk2LAogICJpc3MiOiAiZGlkOmhvbGRlcjoxMjMiLAogICJzdWIiOiAiZGlkOmhvbGRlcjoxMjMiLAogICJqdGkiOiAiYjRjYzQ5ZDUtOGQwZS00ODFlLWIxZWItOGU0ZThiOTY5NmIxIiwKICAidnAiOiB7CiAgICAiQGNvbnRleHQiOiBbCiAgICAgICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIKICAgIF0sCiAgICAidHlwZSI6IFsKICAgICAgIlZlcmlmaWFibGVQcmVzZW50YXRpb24iCiAgICBdLAogICAgIl9zZF9qd3QiOiBbCiAgICAgICJleUpoYkdjaU9pSmhiR2R2Y21sMGFHMGlMQ0owZVhBaU9pSlRSRXBYVkNKOS5leUpwWVhRaU9qRTJPVGt5TnpBeU5qWXNJbVY0Y0NJNk1UYzJNak0wTWpJMk5pd2libUptSWpveE5qazVNamN3TWpJeExDSnBjM01pT2lKSmMzTjFaWElnUkVsRUlpd2ljM1ZpSWpvaWFHOXNaR1Z5WDJScFpDSXNJbXAwYVNJNklqbGhOREUwWVRZd0xUbGxObUl0TkRjMU55MDRNREV4TFRsaFlUZzNNR1ZtTkRjNE9DSXNJblpqSWpwN0lrQmpiMjUwWlhoMElqcGJJbWgwZEhCek9pOHZkM2QzTG5jekxtOXlaeTh5TURFNEwyTnlaV1JsYm5ScFlXeHpMM1l4SWl3aVEyOXVkR1Y0ZERFaVhTd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiQ0lzSWxSNWNHVXhJbDBzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0lsOXpaQ0k2V3lKWlYwcHFUVlJKZWlJc0lsbFhTbXBOVkVsNklsMTlMQ0pqY21Wa1pXNTBhV0ZzVTNSaGRIVnpJanA3SW1sa0lqb2lVMVJCVkZWVFgwbEVJaXdpZEhsd1pTSTZJbFJaVUVVaUxDSnpkR0YwZFhOUWRYSndiM05sSWpvaVVGVlNVRTlUUlNJc0lrWnBaV3hrTVNJNklsWmhiREVpZlgwc0lsOXpaRjloYkdjaU9pSnphR0V0TWpVMkluMC5RVUpEfld5Sk5WRWw2V1ZkS2FpSXNJbTVoYldVaUxDSktiMmh1SWwwfld5Sk5WRWw2V1ZkS2FpSXNJbUZuWlNJc0lqUXlJbDAiCiAgICBdCiAgfQp9";
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
        external_schema: false,
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
    let key_algorithm_provider =
        Arc::new(KeyAlgorithmProviderImpl::new(HashMap::from_iter(vec![(
            "EDDSA".to_owned(),
            Arc::new(key_alg) as Arc<dyn KeyAlgorithm>,
        )])));
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

    let claims = vec![
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
    ];

    let schema = CredentialSchema {
        id: "credential-schema-id".to_string(),
        r#type: "FallbackSchema2024".to_string(),
        metadata: None,
    };
    let holder_did =
        DidValue::from_str("did:key:z6Mkv3HL52XJNh4rdtnPKPRndGwU8nAuVpE7yFFie5SNxZkX").unwrap();

    let issuer = Issuer::Url(issuer_did.to_string().parse().unwrap());
    let credential_subject = VcdmCredentialSubject::new(nest_claims(claims.clone()).unwrap())
        .with_id(holder_did.clone().into_url());

    let vcdm = VcdmCredential::new_v2(issuer, credential_subject)
        .add_credential_schema(schema)
        .with_valid_from(now)
        .with_valid_until(now + Duration::seconds(10));

    let credential_data = CredentialData {
        vcdm,
        claims,
        holder_did: Some(holder_did),
    };

    let did_method_provider = Arc::new(DidMethodProviderImpl::new(
        caching_loader,
        HashMap::from_iter(vec![(
            "JWK".to_owned(),
            Arc::new(JWKDidMethod::new(key_algorithm_provider.clone())) as Arc<dyn DidMethod>,
        )]),
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
    auth_fn
        .expect_jose_alg()
        .returning(|| Some("EdDSA".to_string()));

    let key_verification = Box::new(KeyVerification {
        key_algorithm_provider,
        did_method_provider,
        key_role: KeyRole::AssertionMethod,
    });

    let token = formatter
        .format_credential(credential_data, Box::new(auth_fn))
        .await
        .unwrap();
    let result = formatter
        .extract_credentials(token.as_str(), key_verification)
        .await
        .unwrap();

    assert_eq!(
        result.claims.claims,
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
