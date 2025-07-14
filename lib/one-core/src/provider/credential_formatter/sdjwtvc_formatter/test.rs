use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use indexmap::IndexMap;
use maplit::hashmap;
use mockall::predicate::eq;
use one_crypto::hasher::sha256::SHA256;
use one_crypto::signer::eddsa::EDDSASigner;
use one_crypto::{CryptoProviderImpl, Hasher, MockCryptoProvider, MockHasher, Signer};
use serde_json::json;
use shared_types::{CredentialSchemaId, DidValue, OrganisationId};
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config::core_config::KeyAlgorithmType;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::{CredentialSchemaClaim, CredentialSchemaType, LayoutType};
use crate::model::did::KeyRole;
use crate::model::key::Key;
use crate::provider::caching_loader::vct::{
    MockVctTypeMetadataFetcher, SdJwtVcTypeMetadataCacheItem,
};
use crate::provider::credential_formatter::common::MockAuth;
use crate::provider::credential_formatter::model::{
    CredentialData, CredentialSchema, CredentialStatus, IdentifierDetails, Issuer,
    MockSignatureProvider, MockTokenVerifier, PublicKeySource, PublishedClaim, PublishedClaimValue,
};
use crate::provider::credential_formatter::sdjwt::disclosures::DisclosureArray;
use crate::provider::credential_formatter::sdjwt::test::get_credential_data;
use crate::provider::credential_formatter::sdjwtvc_formatter::model::SdJwtVc;
use crate::provider::credential_formatter::sdjwtvc_formatter::{Params, SDJWTVCFormatter};
use crate::provider::credential_formatter::vcdm::{VcdmCredential, VcdmCredentialSubject};
use crate::provider::credential_formatter::{CredentialFormatter, nest_claims};
use crate::provider::did_method::jwk::JWKDidMethod;
use crate::provider::did_method::key::KeyDidMethod;
use crate::provider::did_method::provider::{DidMethodProviderImpl, MockDidMethodProvider};
use crate::provider::did_method::resolver::DidCachingLoader;
use crate::provider::did_method::{DidKeys, DidMethod};
use crate::provider::http_client::{
    Method, MockHttpClient, Request, RequestBuilder, Response, StatusCode,
};
use crate::provider::key_algorithm::eddsa::Eddsa;
use crate::provider::key_algorithm::provider::{
    KeyAlgorithmProviderImpl, MockKeyAlgorithmProvider,
};
use crate::provider::key_algorithm::{KeyAlgorithm, MockKeyAlgorithm};
use crate::provider::remote_entity_storage::RemoteEntityType;
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::service::certificate::validator::MockCertificateValidator;
use crate::service::credential_schema::dto::CreateCredentialSchemaRequestDTO;
use crate::service::ssi_issuer::dto::SdJwtVcTypeMetadataResponseDTO;
use crate::service::test_utilities::{dummy_did_document, dummy_jwk, generic_config};
use crate::util::jwt::model::{JWTPayload, ProofOfPossessionJwk, ProofOfPossessionKey};
use crate::util::key_verification::KeyVerification;

#[tokio::test]
async fn test_format_credential() {
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

    let credential_data = get_credential_data(
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

    let mut vct_metadata_cache = MockVctTypeMetadataFetcher::new();
    vct_metadata_cache
        .expect_get()
        .with(eq("http://schema.test/id"))
        .return_once(|_| {
            Ok(Some(SdJwtVcTypeMetadataCacheItem {
                metadata: SdJwtVcTypeMetadataResponseDTO {
                    vct: "http://schema.test/id".to_string(),
                    name: None,
                    display: vec![],
                    claims: vec![],
                    schema: None,
                    schema_uri: None,
                    layout_properties: None,
                },
                integrity: Some("integrity".to_string()),
            }))
        });

    let sd_formatter = SDJWTVCFormatter::new(
        Params {
            leeway,
            embed_layout_properties: false,
            swiyu_mode: false,
        },
        Arc::new(crypto),
        Arc::new(did_method_provider),
        Arc::new(vct_metadata_cache),
        Arc::new(MockCertificateValidator::new()),
        generic_config().core.datatype,
        Arc::new(MockHttpClient::new()),
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
    assert_eq!(
        payload.proof_of_possession_key,
        Some(ProofOfPossessionKey {
            key_id: None,
            jwk: ProofOfPossessionJwk::Jwk {
                jwk: dummy_jwk().into()
            },
        })
    );

    assert_eq!(payload.issuer, Some(String::from("did:issuer:test")));
    assert_eq!(payload.subject, Some(String::from("did:example:123")));

    let vc = payload.custom;

    assert_eq!(vc.vc_type, "http://schema.test/id".to_string());
    assert_eq!(vc.vct_integrity, Some("integrity".to_string()));

    assert!(
        vc.digests
            .iter()
            .all(|hashed_claim| hashed_claim == "YWJjMTIz")
    );

    assert!(vc.public_claims.is_empty()); // Empty until we support issuing public_claims
}

#[tokio::test]
async fn test_format_credential_swiyu() {
    const IMG_DATA: &str = "iVBORw0KGgoAAAAN";
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
    let picture_value = format!("data:image/jpeg;base64,{IMG_DATA}");
    credential_data
        .vcdm
        .credential_subject
        .get_mut(0)
        .unwrap()
        .claims
        .insert(
            "portrait".to_string(),
            serde_json::Value::String(picture_value.clone()),
        );
    credential_data.claims.push(PublishedClaim {
        key: "portrait".to_string(),
        value: PublishedClaimValue::String(picture_value),
        datatype: Some("SWIYU_PICTURE".to_string()),
        array_item: false,
    });
    let mut did_method_provider = MockDidMethodProvider::new();
    let holder_did = dummy_did_document(&credential_data.holder_did.as_ref().unwrap().clone());
    did_method_provider
        .expect_resolve()
        .return_once(move |_| Ok(holder_did));

    let mut vct_metadata_cache = MockVctTypeMetadataFetcher::new();
    vct_metadata_cache
        .expect_get()
        .with(eq("http://schema.test/id"))
        .return_once(|_| {
            Ok(Some(SdJwtVcTypeMetadataCacheItem {
                metadata: SdJwtVcTypeMetadataResponseDTO {
                    vct: "http://schema.test/id".to_string(),
                    name: None,
                    display: vec![],
                    claims: vec![],
                    schema: None,
                    schema_uri: None,
                    layout_properties: None,
                },
                integrity: Some("integrity".to_string()),
            }))
        });

    let sd_formatter = SDJWTVCFormatter::new(
        Params {
            leeway,
            embed_layout_properties: false,
            swiyu_mode: true,
        },
        Arc::new(crypto),
        Arc::new(did_method_provider),
        Arc::new(vct_metadata_cache),
        Arc::new(MockCertificateValidator::new()),
        generic_config().core.datatype,
        Arc::new(MockHttpClient::new()),
    );

    let auth_fn = MockAuth(|_| vec![65u8, 66, 67]);

    let result = sd_formatter
        .format_credential(credential_data, Box::new(auth_fn))
        .await;

    assert!(result.is_ok());

    let token = result.unwrap();
    let parts: Vec<&str> = token.splitn(5, '~').collect();
    assert_eq!(parts.len(), 5);

    let disclosures = [
        DisclosureArray::from_b64(parts[1]),
        DisclosureArray::from_b64(parts[2]),
        DisclosureArray::from_b64(parts[3]),
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
    assert!(
        disclosures
            .iter()
            .any(|disc| disc.key == "portrait" && disc.value == IMG_DATA)
    );

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
    assert_eq!(
        payload.proof_of_possession_key,
        Some(ProofOfPossessionKey {
            key_id: None,
            jwk: ProofOfPossessionJwk::Swiyu(dummy_jwk().into()),
        })
    );

    assert_eq!(payload.issuer, Some(String::from("did:issuer:test")));
    assert_eq!(payload.subject, Some(String::from("did:example:123")));

    let vc = payload.custom;

    assert_eq!(vc.vc_type, "http://schema.test/id".to_string());
    assert_eq!(vc.vct_integrity, Some("integrity".to_string()));

    assert!(
        vc.digests
            .iter()
            .all(|hashed_claim| hashed_claim == "YWJjMTIz")
    );

    assert!(vc.public_claims.is_empty()); // Empty until we support issuing public_claims
}

#[tokio::test]
async fn test_extract_credentials() {
    // Token from: https://paradym.id/tools/sd-jwt-vc
    let jwt_token = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rdHF0WE5HOENEVVk5UHJydG9TdEZ6ZUNuaHBNbWd4WUwxZ2lrY1czQnp2TlcifQ.eyJ2Y3QiOiJJZGVudGl0eUNyZWRlbnRpYWwiLCJmYW1pbHlfbmFtZSI6IkRvZSIsInBob25lX251bWJlciI6IisxLTIwMi01NTUtMDEwMSIsImFkZHJlc3MiOnsic3RyZWV0X2FkZHJlc3MiOiIxMjMgTWFpbiBTdCIsImxvY2FsaXR5IjoiQW55dG93biIsIl9zZCI6WyJOSm5tY3QwQnFCTUUxSmZCbEM2alJRVlJ1ZXZwRU9OaVl3N0E3TUh1SnlRIiwib201Wnp0WkhCLUdkMDBMRzIxQ1ZfeE00RmFFTlNvaWFPWG5UQUpOY3pCNCJdfSwiY25mIjp7Imp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Im9FTlZzeE9VaUg1NFg4d0pMYVZraWNDUmswMHdCSVE0c1JnYms1NE44TW8ifX0sImlzcyI6ImRpZDprZXk6ejZNa3RxdFhORzhDRFVZOVBycnRvU3RGemVDbmhwTW1neFlMMWdpa2NXM0J6dk5XIiwiaWF0IjoxNjk4MTUxNTMyLCJfc2QiOlsiMUN1cjJrMkEyb0lCNUNzaFNJZl9BX0tnLWwyNnVfcUt1V1E3OVAwVmRhcyIsIlIxelRVdk9ZSGdjZXBqMGpIeXBHSHo5RUh0dFZLZnQweXN3YmM5RVRQYlUiLCJlRHFRcGRUWEpYYldoZi1Fc0k3enc1WDZPdlltRk4tVVpRUU1lc1h3S1B3IiwicGREazJfWEFLSG83Z09BZndGMWI3T2RDVVZUaXQya0pIYXhTRUNROXhmYyIsInBzYXVLVU5XRWkwOW51M0NsODl4S1hnbXBXRU5abDV1eTFOMW55bl9qTWsiLCJzTl9nZTBwSFhGNnFtc1luWDFBOVNkd0o4Y2g4YUVOa3hiT0RzVDc0WXdJIl0sIl9zZF9hbGciOiJzaGEtMjU2In0";
    let kb_token = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImtleS1pZCIsInR5cCI6ImtiK2p3dCJ9.eyJpYXQiOjE3NDA3NTYwOTAsImF1ZCI6InNvbWUtYXVkIiwibm9uY2UiOiJub25jZSIsInNkX2hhc2giOiJ0ZXN0LWhhc2gifQ.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let token = format!(
        "{jwt_token}.QUJD~\
        WyJzYWx0IiwicmVnaW9uIiwiQW55c3RhdGUiXQ~\
        WyJzYWx0IiwiY291bnRyeSIsIlVTIl0~\
        WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~\
        WyJzYWx0IiwiZW1haWwiLCJqb2huZG9lQGV4YW1wbGUuY29tIl0~\
        WyJzYWx0IiwiYmlydGhkYXRlIiwiMTk0MC0wMS0wMSJd~\
        WyJzYWx0IiwiaXNfb3Zlcl8xOCIsdHJ1ZV0~\
        WyJzYWx0IiwiaXNfb3Zlcl8yMSIsdHJ1ZV0~\
        WyJzYWx0IiwiaXNfb3Zlcl82NSIsdHJ1ZV0~\
        {kb_token}"
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
            swiyu_mode: false,
        },
        Arc::new(crypto),
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(MockVctTypeMetadataFetcher::new()),
        Arc::new(MockCertificateValidator::new()),
        generic_config().core.datatype,
        Arc::new(MockHttpClient::new()),
    );

    let mut verify_mock = MockTokenVerifier::new();
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .returning(|_| {
            let mut alg = MockKeyAlgorithm::new();
            alg.expect_algorithm_type()
                .return_once(|| KeyAlgorithmType::Eddsa);
            Some((KeyAlgorithmType::Eddsa, Arc::new(alg)))
        });
    verify_mock
        .expect_key_algorithm_provider()
        .return_const(Box::new(key_algorithm_provider));

    verify_mock
        .expect_verify()
        .withf(
            move |params, algorithm, token, signature| {
                assert!(matches!(params, PublicKeySource::Did {did, ..} if did.to_string() == "did:key:z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW"));
                assert_eq!(KeyAlgorithmType::Eddsa, *algorithm);
                assert_eq!(jwt_token.as_bytes(), token);
                assert_eq!(vec![65u8, 66, 67], signature);
                true
            },
        )
        .return_once(|_,  _, _, _| Ok(()));

    let credentials = sd_formatter
        .extract_credentials(&token, None, Box::new(verify_mock), None)
        .await
        .unwrap();

    assert_eq!(
        credentials.issuer,
        IdentifierDetails::Did(
            "did:key:z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW"
                .parse()
                .unwrap()
        )
    );

    let expected_subject = "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Im9FTlZzeE9VaUg1NFg4d0pMYVZraWNDUmswMHdCSVE0c1JnYms1NE44TW8ifQ";
    assert_eq!(
        credentials.subject,
        Some(IdentifierDetails::Did(expected_subject.parse().unwrap()))
    );

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
async fn test_extract_credentials_swiyu() {
    let jwt_token = "eyJ2ZXIiOiIxLjAiLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDp0ZHc6UW1QRVpQaERGUjRuRVlTRks1Yk1udkVDcWRwZjF0UFRQSnVXczlRck1qQ3VtdzppZGVudGlmaWVyLXJlZy50cnVzdC1pbmZyYS5zd2l5dS1pbnQuYWRtaW4uY2g6YXBpOnYxOmRpZDo5YTU1NTlmMC1iODFjLTQzNjgtYTE3MC1lN2I0YWU0MjQ1MjcjYXNzZXJ0LWtleS1mNGJjMDMyZi1iZmUwLTRiYWItYWNiMy1iYzNlZjdmYjM0MDAifQ.eyJfc2QiOlsiMF9ONVlvRlB3Uk9Gb0ZLNVdhVEV4eDlMOVRIWmZqTUZkOHd2dWFKR2FKRSIsIjEzT3ZoTjNHNjZsS1g3TTRTZmJ2bDVRWU5xVU83akFTVmdJcEFmRDYzdEkiLCI0WlFaOEN1eUlUQ2J4WHM4S1dzTXZwMHVxQllSSlRjOHQzTV9aQlJDRmV3IiwiNTJFamM4VXJSRXAwV0JDaC1YQm9sUURESmJYOUdHNmVBWXhJSURtaExfWSIsIjVsLTRlLTlQUkdiWUFxdW1qb0lyUmFNcGVBWm9jeHpyMF82ZXRyZWQtOWsiLCI5U3RwV00zTFJZNE9wM3JLSElNdDRlWVY1VzAwYWktdFFIbHBHckw3QTRnIiwiOXJDMEF1OXBCbGpMZGJmX0Z6RUxxRTU3d25UbFJVMkVrdVJsQTRwV3MzdyIsIkNJUTFvaktOQ293Mlp5ckNHRW1BR00wa2lrRFpDczg5X3RZOHlqMF8zME0iLCJDTnBMVFhaeEZaXzdxOE85WEdNSVpWNUQwemVWV2Jwc0RDSG1HdUh0b2hJIiwiRHFYZ1lldG1uQkZ3X3F6dUlpb0lGaVQ0aUpuaWRLT0lRdHpsakVUZnhKNCIsIkdYSk5Gb196cWxzMzdRT3lnRnNvMVhYa2NxRl9xYU1MZXNyaElDNmxGWHMiLCJIX3ctQkQwTkZWSkg2bGx6dzh1Vm9WdHNEVXRGSUlKNlRlZkpWQ2hNaEVJIiwiSWE0bUFqYmxsNmZwTXduakJncnBhc1JEQzRUSXUzRl9LbjBVNkRMbUYwcyIsIktOVk9hVEFyQ0cyMjlHZGZldFQya3JzTHhpaWdEUGRTdVpPU1J3VHFOcVUiLCJLdGlZcDh2VFJad3ZpaXpCaW9uRGpQcnBfZ25tSUxkOGZzalhXTy0wME5JIiwiT2RuUGNBeVNNcEhVQVM3SGMzU21heWhuSVphU0g2LTRIYmxTNkh0QWZFcyIsIl9CRHQwUFI3dnA0V082amN6T2dIc19uSjJMMG9mYTdFTk00MlR3QkFtcDQiLCJiVXVNeFl5YlZvYldPam5BREpWU21rUkFZV3V2LVRKWFRXdG9leFFhQWR3IiwiZDBUTWdQa0l4UVJxR2VpRWRfTXpDa0JnSEM0M0xLenFGeGExSU16Ny1MQSIsImlkVlRSWHY5MVpUOXk3clRUOUx5X20wal8wQnZzemlEMVd6MFFxOGlyNE0iLCJraF9zSlM5WG9mZ0tXc0JXbnM1ZFE1XzdQcWlPZ0FVQ09KbnRrYnU0MHNrIiwibU55TDBUTEhYQmhUay1ld0JWYlJGeFVDUnRrbmE4dEFzVjBiV0wyNmJDVSIsInl4MXdzNDF1TkxfTU9hbTEwMmktVE1sd3BpSk1PVUJQNzRRbl9TQ1pNRzQiXSwidmN0IjoiYmV0YWlkLXNkand0IiwiX3NkX2FsZyI6InNoYS0yNTYiLCJpc3MiOiJkaWQ6dGR3OlFtUEVaUGhERlI0bkVZU0ZLNWJNbnZFQ3FkcGYxdFBUUEp1V3M5UXJNakN1bXc6aWRlbnRpZmllci1yZWcudHJ1c3QtaW5mcmEuc3dpeXUtaW50LmFkbWluLmNoOmFwaTp2MTpkaWQ6OWE1NTU5ZjAtYjgxYy00MzY4LWExNzAtZTdiNGFlNDI0NTI3IiwiY25mIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiWnA5cUxhVEpNaHVQLWRwTWE5cExscHFaY1E0Y2hWREp5U1dyaXNBQWkyZyIsInkiOiJ4dVZ1NVhnUE5RSy1QMFRzRGxoYThwNU1mQURlWmhTZ1M3N0tVVjNoY3ZFIn0sImlhdCI6MTc0NjQ1NDM1NSwic3RhdHVzIjp7InN0YXR1c19saXN0Ijp7InR5cGUiOiJTd2lzc1Rva2VuU3RhdHVzTGlzdC0xLjAiLCJpZHgiOjc5NjQsInVyaSI6Imh0dHBzOi8vc3RhdHVzLXJlZy50cnVzdC1pbmZyYS5zd2l5dS1pbnQuYWRtaW4uY2gvYXBpL3YxL3N0YXR1c2xpc3QvMTkzZmRjOTgtMGIxMC00YjY1LTg3NmItZWY0NGY3YjEwMTkwLmp3dCJ9fX0";
    let token = format!(
        "{jwt_token}.QUJD~\
        WyJreGN6aFhIUW1SSXh5SVlHNk43dk9nIiwiaXNzdWFuY2VfZGF0ZSIsIjIwMjUtMDUtMDUiXQ~\
        WyJwcGtNNjQ3eXRyRmRENXhuSmk1aVRBIiwiZG9jdW1lbnRfbnVtYmVyIiwiQkVUQS1JRC1TS1dDNlBMRSJd~\
        WyI4dXREMUtpVTgwcmxjeVBrWFMxUmpBIiwiYWdlX292ZXJfMTgiLCJ0cnVlIl0~\
        WyJEU0loT3Z6bGRSbFhvYmRCUTkybHJnIiwicmVmZXJlbmNlX2lkX3R5cGUiLCJTZWxmLURlY2xhcmVkIl0~\
        WyI4eFRhOWFvN1BNOGJoR0F1d2F4YlNnIiwiYmlydGhfZGF0ZSIsIjE4NDgtMDktMTIiXQ~\
        WyJ1WXJBeUE0aGlFUzVyODQwZ19yZGRnIiwic2V4IiwiMiJd~\
        WyJNWXpuV2pOTHcxNFQzTDNuS3dsY3lRIiwiYWdlX292ZXJfMTYiLCJ0cnVlIl0~\
        WyJSNXd2TTFKVzFpal9tMjVFakhuemx3IiwiZXhwaXJ5X2RhdGUiLCIyMDI1LTA4LTA1Il0~\
        WyJ1N1laVGFpNzhKSlJsamh6aHdWOGdnIiwicGVyc29uYWxfYWRtaW5pc3RyYXRpdmVfbnVtYmVyIiwiNzU2LjM2NTguMTg4MS45MSJd~\
        WyJPMDBaaHc1bEx3aG90MTRJdFI4VkJnIiwiYmlydGhfcGxhY2UiLCJMdXplcm4iXQ~\
        WyJnNVdqTFo0dFUzR2R3RmFrTlp0VnBBIiwidmVyaWZpY2F0aW9uX3R5cGUiLCJTZWxmLVNlcnZpY2UiXQ~\
        WyI5NG9HdGkyWFMtQnpJTjZsaXBtZ2pRIiwiZ2l2ZW5fbmFtZSIsIkhlbHZldGlhIl0~\
        WyJycXV6SElES004eVV6dnhfUDYxbmFRIiwicG9ydHJhaXQiLCJpVkJPUncwS0dnb0FBQUFOU1VoRVVnQUFBVllBQUFIT0NBWUFBQUREbWlHdEFBQU9pa2xFUVZSNFh1M1VzUTBBQUFqRE1Qci8wenlSMFJ6UXdVTFpPUUlFQ0JCSUJaYXVHU05BZ0FDQkUxWlBRSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JBUVZqOUFnQUNCV0VCWVkxQnpCQWdRRUZZL1FJQUFnVmhBV0dOUWN3UUlFQkJXUDBDQUFJRllRRmhqVUhNRUNCQVFWajlBZ0FDQldFQllZMUJ6QkFnUUVGWS9RSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JBUVZqOUFnQUNCV0VCWVkxQnpCQWdRRUZZL1FJQUFnVmhBV0dOUWN3UUlFQkJXUDBDQUFJRllRRmhqVUhNRUNCQVFWajlBZ0FDQldFQllZMUJ6QkFnUUVGWS9RSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JBUVZqOUFnQUNCV0VCWVkxQnpCQWdRRUZZL1FJQUFnVmhBV0dOUWN3UUlFQkJXUDBDQUFJRllRRmhqVUhNRUNCQVFWajlBZ0FDQldFQllZMUJ6QkFnUUVGWS9RSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JBUVZqOUFnQUNCV0VCWVkxQnpCQWdRRUZZL1FJQUFnVmhBV0dOUWN3UUlFQkJXUDBDQUFJRllRRmhqVUhNRUNCQVFWajlBZ0FDQldFQllZMUJ6QkFnUUVGWS9RSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JBUVZqOUFnQUNCV0VCWVkxQnpCQWdRRUZZL1FJQUFnVmhBV0dOUWN3UUlFQkJXUDBDQUFJRllRRmhqVUhNRUNCQVFWajlBZ0FDQldFQllZMUJ6QkFnUUVGWS9RSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JBUVZqOUFnQUNCV0VCWVkxQnpCQWdRRUZZL1FJQUFnVmhBV0dOUWN3UUlFQkJXUDBDQUFJRllRRmhqVUhNRUNCQVFWajlBZ0FDQldFQllZMUJ6QkFnUUVGWS9RSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JBUVZqOUFnQUNCV0VCWVkxQnpCQWdRRUZZL1FJQUFnVmhBV0dOUWN3UUlFQkJXUDBDQUFJRllRRmhqVUhNRUNCQVFWajlBZ0FDQldFQllZMUJ6QkFnUUVGWS9RSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JBUVZqOUFnQUNCV0VCWVkxQnpCQWdRRUZZL1FJQUFnVmhBV0dOUWN3UUlFQkJXUDBDQUFJRllRRmhqVUhNRUNCQVFWajlBZ0FDQldFQllZMUJ6QkFnUUVGWS9RSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JBUVZqOUFnQUNCV0VCWVkxQnpCQWdRRUZZL1FJQUFnVmhBV0dOUWN3UUlFQkJXUDBDQUFJRllRRmhqVUhNRUNCQVFWajlBZ0FDQldFQllZMUJ6QkFnUUVGWS9RSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JBUVZqOUFnQUNCV0VCWVkxQnpCQWdRRUZZL1FJQUFnVmhBV0dOUWN3UUlFQkJXUDBDQUFJRllRRmhqVUhNRUNCQVFWajlBZ0FDQldFQllZMUJ6QkFnUUVGWS9RSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JBUVZqOUFnQUNCV0VCWVkxQnpCQWdRRUZZL1FJQUFnVmhBV0dOUWN3UUlFQkJXUDBDQUFJRllRRmhqVUhNRUNCQVFWajlBZ0FDQldFQllZMUJ6QkFnUUVGWS9RSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JBUVZqOUFnQUNCV0VCWVkxQnpCQWdRRUZZL1FJQUFnVmhBV0dOUWN3UUlFQkJXUDBDQUFJRllRRmhqVUhNRUNCQVFWajlBZ0FDQldFQllZMUJ6QkFnUUVGWS9RSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JBUVZqOUFnQUNCV0VCWVkxQnpCQWdRRUZZL1FJQUFnVmhBV0dOUWN3UUlFQkJXUDBDQUFJRllRRmhqVUhNRUNCQVFWajlBZ0FDQldFQllZMUJ6QkFnUUVGWS9RSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JBUVZqOUFnQUNCV0VCWVkxQnpCQWdRRUZZL1FJQUFnVmhBV0dOUWN3UUlFQkJXUDBDQUFJRllRRmhqVUhNRUNCQVFWajlBZ0FDQldFQllZMUJ6QkFnUUVGWS9RSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JBUVZqOUFnQUNCV0VCWVkxQnpCQWdRRUZZL1FJQUFnVmhBV0dOUWN3UUlFQkJXUDBDQUFJRllRRmhqVUhNRUNCQVFWajlBZ0FDQldFQllZMUJ6QkFnUUVGWS9RSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JBUVZqOUFnQUNCV0VCWVkxQnpCQWdRRUZZL1FJQUFnVmhBV0dOUWN3UUlFQkJXUDBDQUFJRllRRmhqVUhNRUNCQVFWajlBZ0FDQldFQllZMUJ6QkFnUUVGWS9RSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JBUVZqOUFnQUNCV0VCWVkxQnpCQWdRRUZZL1FJQUFnVmhBV0dOUWN3UUlFQkJXUDBDQUFJRllRRmhqVUhNRUNCQVFWajlBZ0FDQldFQllZMUJ6QkFnUUVGWS9RSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JBUVZqOUFnQUNCV0VCWVkxQnpCQWdRRUZZL1FJQUFnVmhBV0dOUWN3UUlFQkJXUDBDQUFJRllRRmhqVUhNRUNCQVFWajlBZ0FDQldFQllZMUJ6QkFnUUVGWS9RSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JBUVZqOUFnQUNCV0VCWVkxQnpCQWdRRUZZL1FJQUFnVmhBV0dOUWN3UUlFQkJXUDBDQUFJRllRRmhqVUhNRUNCQVFWajlBZ0FDQldFQllZMUJ6QkFnUUVGWS9RSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JBUVZqOUFnQUNCV0VCWVkxQnpCQWdRRUZZL1FJQUFnVmhBV0dOUWN3UUlFQkJXUDBDQUFJRllRRmhqVUhNRUNCQVFWajlBZ0FDQldFQllZMUJ6QkFnUUVGWS9RSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JBUVZqOUFnQUNCV0VCWVkxQnpCQWdRRUZZL1FJQUFnVmhBV0dOUWN3UUlFQkJXUDBDQUFJRllRRmhqVUhNRUNCQVFWajlBZ0FDQldFQllZMUJ6QkFnUUVGWS9RSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JBUVZqOUFnQUNCV0VCWVkxQnpCQWdRRUZZL1FJQUFnVmhBV0dOUWN3UUlFQkJXUDBDQUFJRllRRmhqVUhNRUNCQVFWajlBZ0FDQldFQllZMUJ6QkFnUUVGWS9RSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JBUVZqOUFnQUNCV0VCWVkxQnpCQWdRRUZZL1FJQUFnVmhBV0dOUWN3UUlFQkJXUDBDQUFJRllRRmhqVUhNRUNCQVFWajlBZ0FDQldFQllZMUJ6QkFnUUVGWS9RSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JBUVZqOUFnQUNCV0VCWVkxQnpCQWdRRUZZL1FJQUFnVmhBV0dOUWN3UUlFQkJXUDBDQUFJRllRRmhqVUhNRUNCQVFWajlBZ0FDQldFQllZMUJ6QkFnUUVGWS9RSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JBUVZqOUFnQUNCV0VCWVkxQnpCQWdRRUZZL1FJQUFnVmhBV0dOUWN3UUlFQkJXUDBDQUFJRllRRmhqVUhNRUNCQVFWajlBZ0FDQldFQllZMUJ6QkFnUUVGWS9RSUFBZ1ZoQVdHTlFjd1FJRUJCV1AwQ0FBSUZZUUZoalVITUVDQkFRVmo5QWdBQ0JXRUJZWTFCekJBZ1FFRlkvUUlBQWdWaEFXR05RY3dRSUVCQldQMENBQUlGWVFGaGpVSE1FQ0JCNFZmc0J6Nnk5aWNFQUFBQUFTVVZPUks1Q1lJSVx1MDAzZCJd~\
        WyJod2tyYlEwQUVUWFRRRU0tMTVuamtnIiwiYWRkaXRpb25hbF9wZXJzb25faW5mbyIsIk4vQSJd~\
        WyJJTUhCUkFuaVc3UnFEc1VGdTU5Ukh3IiwicGxhY2Vfb2Zfb3JpZ2luIiwiTi9BIl0~\
        WyJ1VWQ3ZDVTZEFIUTdBRFFuVjNRR013IiwibmF0aW9uYWxpdHkiLCJDSCJd~\
        WyJBQnk2SVp0dDJQcmRmajlKUjdjOUd3IiwiYWdlX2JpcnRoX3llYXIiLCIxODQ4Il0~\
        WyJlTmJJUjdra2RIMGUtSzg0QjFJalhRIiwiaXNzdWluZ19jb3VudHJ5IiwiQ0giXQ~\
        WyJobHJKZlloNk9xUXVxY0o2QWtGelR3IiwiaXNzdWluZ19hdXRob3JpdHkiLCJCZXRhIENyZWRlbnRpYWwgU2VydmljZSBCQ1MiXQ~\
        WyJBRWo2TWlvRGpsUldralpHUHJpU3R3IiwidmVyaWZpY2F0aW9uX29yZ2FuaXphdGlvbiIsIkJldGEgQ3JlZGVudGlhbCBTZXJ2aWNlIEJDUyJd~\
        WyJhYXJ0MHkxdjM3Wkh4VlViaXlweGd3IiwiZmFtaWx5X25hbWUiLCJOYXRpb25hbCJd~\
        WyJoTy1BYXBrVDRTRWFIT2MwMTJsS1BRIiwiYWdlX292ZXJfNjUiLCJ0cnVlIl0~\
        WyJJdldtNmU1RmNQckNiRFpYa0kzOEt3IiwicmVmZXJlbmNlX2lkX2V4cGlyeV9kYXRlIiwiMjAzMC0wNS0wNSJd~"
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
            swiyu_mode: true,
        },
        Arc::new(crypto),
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(MockVctTypeMetadataFetcher::new()),
        Arc::new(MockCertificateValidator::new()),
        generic_config().core.datatype,
        Arc::new(MockHttpClient::new()),
    );

    let mut verify_mock = MockTokenVerifier::new();
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .returning(|_| {
            let mut alg = MockKeyAlgorithm::new();
            alg.expect_algorithm_type()
                .return_once(|| KeyAlgorithmType::Eddsa);
            Some((KeyAlgorithmType::Eddsa, Arc::new(alg)))
        });
    verify_mock
        .expect_key_algorithm_provider()
        .return_const(Box::new(key_algorithm_provider));

    verify_mock
        .expect_verify()
        .withf(
            move |params, algorithm, token, signature| {
                assert!(matches!(params, PublicKeySource::Did {did, ..} if did.to_string() ==  "did:tdw:QmPEZPhDFR4nEYSFK5bMnvECqdpf1tPTPJuWs9QrMjCumw:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:9a5559f0-b81c-4368-a170-e7b4ae424527"));
                assert_eq!(KeyAlgorithmType::Eddsa, *algorithm);
                assert_eq!(jwt_token.as_bytes(), token);
                assert_eq!(vec![65u8, 66, 67], signature);
                true
            },
        )
        .return_once(|_,  _, _, _| Ok(()));

    let now = OffsetDateTime::now_utc();
    let credential_schema = crate::model::credential_schema::CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        created_date: now,
        last_modified: now,
        name: "".to_string(),
        format: "".to_string(),
        revocation_method: "".to_string(),
        wallet_storage_type: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: "".to_string(),
        schema_type: CredentialSchemaType::SdJwtVc,
        imported_source_url: "".to_string(),
        allow_suspension: false,
        external_schema: false,
        claim_schemas: Some(vec![CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "portrait".to_string(),
                data_type: "SWIYU_PICTURE".to_string(),
                created_date: now,
                last_modified: now,
                array: false,
            },
            required: false,
        }]),
        organisation: None,
    };

    let credentials = sd_formatter
        .extract_credentials(
            &token,
            Some(&credential_schema),
            Box::new(verify_mock),
            None,
        )
        .await
        .unwrap();

    assert_eq!(
        credentials.issuer,
        IdentifierDetails::Did(
            "did:tdw:QmPEZPhDFR4nEYSFK5bMnvECqdpf1tPTPJuWs9QrMjCumw:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:9a5559f0-b81c-4368-a170-e7b4ae424527"
                .parse()
                .unwrap()
        )
    );

    let expected_subject = "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlpwOXFMYVRKTWh1UC1kcE1hOXBMbHBxWmNRNGNoVkRKeVNXcmlzQUFpMmciLCJ5IjoieHVWdTVYZ1BOUUstUDBUc0RsaGE4cDVNZkFEZVpoU2dTNzdLVVYzaGN2RSJ9";
    assert_eq!(
        credentials.subject,
        Some(IdentifierDetails::Did(expected_subject.parse().unwrap()))
    );

    let expected_result = json!(
        {
            "place_of_origin": "N/A",
            "birth_place": "Luzern",
            "reference_id_type": "Self-Declared",
            "age_birth_year": "1848",
            "verification_type": "Self-Service",
            "issuing_authority": "Beta Credential Service BCS",
            "verification_organization": "Beta Credential Service BCS",
            "issuing_country": "CH",
            "reference_id_expiry_date": "2030-05-05",
            "age_over_16": "true",
            "age_over_18": "true",
            "age_over_65": "true",
            "family_name": "National",
            "additional_person_info": "N/A",
            "issuance_date": "2025-05-05",
            "document_number": "BETA-ID-SKWC6PLE",
            "given_name": "Helvetia",
            "sex": "2",
            "personal_administrative_number": "756.3658.1881.91",
            "portrait": "data:image/jpeg;base64,iVBORw0KGgoAAAANSUhEUgAAAVYAAAHOCAYAAADDmiGtAAAOiklEQVR4Xu3UsQ0AAAjDMPr/0zyR0RzQwULZOQIECBBIBZauGSNAgACBE1ZPQIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBAQVj9AgACBWEBYY1BzBAgQEFY/QIAAgVhAWGNQcwQIEBBWP0CAAIFYQFhjUHMECBB4VfsBz6y9icEAAAAASUVORK5CYII=",
            "nationality": "CH",
            "birth_date": "1848-09-12",
            "expiry_date": "2025-08-05"
        }
    );
    let claim_values_as_json = credentials
        .claims
        .claims
        .into_iter()
        .collect::<serde_json::Map<String, serde_json::Value>>();

    assert_eq!(claim_values_as_json, *expected_result.as_object().unwrap());
}

const ISSUER_URL: &str = "https://example.com/.well-known/jwt-vc-issuer/issuer";
const ISSUER_URL_RESPONSE: &str = r#"{
                           "issuer":"https://example.com/issuer",
                           "jwks":{
                              "keys":[
                                 {
                                    "kid":"doc-signer-05-25-2022",
                                    "e":"AQAB",
                                    "n":"nj3YJwsLUFl9BmpAbkOswCNVx17Eh9wMO-_AReZwBqfaWFcfGHrZXsIV2VMCNVNU8Tpb4obUaSXcRcQ-VMsfQPJm9IzgtRdAY8NN8Xb7PEcYyklBjvTtuPbpzIaqyiUepzUXNDFuAOOkrIol3WmflPUUgMKULBN0EUd1fpOD70pRM0rlp_gg_WNUKoW1V-3keYUJoXH9NztEDm_D2MQXj9eGOJJ8yPgGL8PAZMLe2R7jb9TxOCPDED7tY_TU4nFPlxptw59A42mldEmViXsKQt60s1SLboazxFKveqXC_jpLUt22OC6GUG63p-REw-ZOr3r845z50wMuzifQrMI9bQ",
                                    "kty":"RSA"
                                 }
                              ]
                           }
                        }"#;

#[tokio::test]
async fn test_extract_credentials_with_cnf_no_subject() {
    // https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html#section-4.2
    let jwt_token = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRjK3NkLWp3dCIsICJraWQiOiAiZG9jLXNpZ25lci0wNS0yNS0yMDIyIn0.eyJfc2QiOiBbIjA5dktySk1PbHlUV00wc2pwdV9wZE9CVkJRMk0xeTNLaHBINTE1blhrcFkiLCAiMnJzakdiYUMwa3k4bVQwcEpyUGlvV1RxMF9kYXcxc1g3NnBvVWxnQ3diSSIsICJFa084ZGhXMGRIRUpidlVIbEVfVkNldUM5dVJFTE9pZUxaaGg3WGJVVHRBIiwgIklsRHpJS2VpWmREd3BxcEs2WmZieXBoRnZ6NUZnbldhLXNONndxUVhDaXciLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiamRyVEU4WWNiWTRFaWZ1Z2loaUFlX0JQZWt4SlFaSUNlaVVRd1k5UXF4SSIsICJqc3U5eVZ1bHdRUWxoRmxNXzNKbHpNYVNGemdsaFFHMERwZmF5UXdMVUs0Il0sICJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiaWF0IjogMTY4MzAwMDAwMCwgImV4cCI6IDE4ODMwMDAwMDAsICJ2Y3QiOiAiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIiwgIl9zZF9hbGciOiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIlRDQUVSMTladnUzT0hGNGo0VzR2ZlNWb0hJUDFJTGlsRGxzN3ZDZUdlbWMiLCAieSI6ICJaeGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1ZWNDRTZ0NGpUOUYySFpRIn19fQ";
    let token_signature =
        "2CyX0v3AAFG9y-A_Z46uz9hHsNbr0yWTbDQaajLCrsxo-JxVh4a9dAMFVYZ8GFG2wgj2jKnA42wSgv7xVM64PA";
    let disclosures = "~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImlzX292ZXJfNjUiLCB0cnVlXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgImlhdCI6IDE3MzMyMzAxNDAsICJzZF9oYXNoIjogIkhWVjBCcG5FTHlHTnRVVFlCLU5nWHhmN2pvTjZBekprYVdEOUVkNVo1VjgifQ.FJLPPlBB2wOWEYLLtwd7WYlaTpIz0ALlRuskPi0fSYFDEn25gGkXSSJsQxjhryxqN4aLbwMRRfcvDdk1A_eLHQ";

    let expected_holder_did = DidValue::from_str("did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlRDQUVSMTladnUzT0hGNGo0VzR2ZlNWb0hJUDFJTGlsRGxzN3ZDZUdlbWMiLCJ5IjoiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9").unwrap();
    let expected_issuer_did = "did:jwk:eyJrdHkiOiJSU0EiLCJraWQiOiJkb2Mtc2lnbmVyLTA1LTI1LTIwMjIiLCJlIjoiQVFBQiIsIm4iOiJuajNZSndzTFVGbDlCbXBBYmtPc3dDTlZ4MTdFaDl3TU8tX0FSZVp3QnFmYVdGY2ZHSHJaWHNJVjJWTUNOVk5VOFRwYjRvYlVhU1hjUmNRLVZNc2ZRUEptOUl6Z3RSZEFZOE5OOFhiN1BFY1l5a2xCanZUdHVQYnB6SWFxeWlVZXB6VVhOREZ1QU9Pa3JJb2wzV21mbFBVVWdNS1VMQk4wRVVkMWZwT0Q3MHBSTTBybHBfZ2dfV05VS29XMVYtM2tlWVVKb1hIOU56dEVEbV9EMk1RWGo5ZUdPSko4eVBnR0w4UEFaTUxlMlI3amI5VHhPQ1BERUQ3dFlfVFU0bkZQbHhwdHc1OUE0Mm1sZEVtVmlYc0tRdDYwczFTTGJvYXp4Rkt2ZXFYQ19qcExVdDIyT0M2R1VHNjNwLVJFdy1aT3Izcjg0NXo1MHdNdXppZlFyTUk5YlEifQ";

    let mut crypto = MockCryptoProvider::default();
    crypto
        .expect_get_hasher()
        .with(eq("sha-256"))
        .returning(|_| Ok(Arc::new(SHA256 {})));

    let mut http_client = MockHttpClient::new();
    http_client
        .expect_get()
        .once()
        .with(eq(ISSUER_URL))
        .returning(|url| {
            let mut inner_client = MockHttpClient::new();
            inner_client.expect_send().once().returning(|_, _, _, _| {
                Ok(Response {
                    body: ISSUER_URL_RESPONSE.as_bytes().to_vec(),
                    headers: Default::default(),
                    status: StatusCode(200),
                    request: Request {
                        body: None,
                        headers: Default::default(),
                        method: Method::Get,
                        url: ISSUER_URL.to_string(),
                    },
                })
            });

            RequestBuilder::new(Arc::new(inner_client), Method::Get, url)
        });

    let sd_formatter = SDJWTVCFormatter::new(
        Params {
            leeway: 45u64,
            embed_layout_properties: false,
            swiyu_mode: false,
        },
        Arc::new(crypto),
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(MockVctTypeMetadataFetcher::new()),
        Arc::new(MockCertificateValidator::new()),
        generic_config().core.datatype,
        Arc::new(http_client),
    );

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .with(eq("ES256"))
        .once()
        .returning(|_| {
            let mut key_algorithm = MockKeyAlgorithm::default();
            key_algorithm
                .expect_algorithm_type()
                .return_once(|| KeyAlgorithmType::Ecdsa);

            Some((KeyAlgorithmType::Ecdsa, Arc::new(key_algorithm)))
        });

    let mut verify_mock = MockTokenVerifier::new();
    verify_mock
        .expect_key_algorithm_provider()
        .return_const(Box::new(key_algorithm_provider));

    verify_mock
        .expect_verify()
        .once()
        .withf(
            move |params, algorithm, token, received_signature| {
                assert!(matches!(params, PublicKeySource::Did {did, ..} if did.to_string() == expected_issuer_did));
                assert_eq!(KeyAlgorithmType::Ecdsa, *algorithm);
                assert_eq!(jwt_token.as_bytes(), token);
                assert_eq!(
                    received_signature,
                    Base64UrlSafeNoPadding::decode_to_vec(token_signature, None).unwrap()
                );
                true
            },
        )
        .return_once(|_, _, _, _| Ok(()));

    let credentials = sd_formatter
        .extract_credentials(
            &format!("{jwt_token}.{token_signature}.{disclosures}"),
            None,
            Box::new(verify_mock),
            None,
        )
        .await
        .unwrap();

    assert_eq!(
        credentials.subject,
        Some(IdentifierDetails::Did(expected_holder_did))
    );
}

#[test]
fn test_schema_id() {
    let formatter = SDJWTVCFormatter::new(
        Params {
            leeway: 45u64,
            embed_layout_properties: false,
            swiyu_mode: false,
        },
        Arc::new(MockCryptoProvider::default()),
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(MockVctTypeMetadataFetcher::new()),
        Arc::new(MockCertificateValidator::new()),
        generic_config().core.datatype,
        Arc::new(MockHttpClient::new()),
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
        swiyu_mode: false,
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

    let key_alg = Eddsa;
    let key_algorithm_provider =
        Arc::new(KeyAlgorithmProviderImpl::new(HashMap::from_iter(vec![(
            KeyAlgorithmType::Eddsa,
            Arc::new(key_alg) as Arc<dyn KeyAlgorithm>,
        )])));
    let key_pair = EDDSASigner::generate_key_pair();
    let key = Key {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        public_key: key_pair.public.clone(),
        name: "issuer key".to_string(),
        key_reference: None,
        storage_type: "INTERNAL".to_string(),
        key_type: "EDDSA".to_string(),
        organisation: None,
    };

    let keys = vec![key];
    let issuer_did = JWKDidMethod::new(key_algorithm_provider.clone())
        .create(
            None,
            &None,
            Some(DidKeys {
                authentication: keys.clone(),
                assertion_method: keys.clone(),
                key_agreement: keys.clone(),
                capability_invocation: keys.clone(),
                capability_delegation: keys.clone(),
                update_keys: None,
            }),
        )
        .await
        .unwrap()
        .did;

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
        holder_did: Some(holder_did.clone()),
        holder_key_id: Some(format!("{holder_did}#0")),
        issuer_certificate: None,
    };

    let did_method_provider = Arc::new(DidMethodProviderImpl::new(
        caching_loader,
        IndexMap::from_iter(vec![
            (
                "JWK".to_owned(),
                Arc::new(JWKDidMethod::new(key_algorithm_provider.clone())) as Arc<dyn DidMethod>,
            ),
            (
                "KEY".to_owned(),
                Arc::new(KeyDidMethod::new(key_algorithm_provider.clone())) as Arc<dyn DidMethod>,
            ),
        ]),
    ));

    let mut vct_metadata_cache = MockVctTypeMetadataFetcher::new();
    vct_metadata_cache
        .expect_get()
        .with(eq("credential-schema-id"))
        .return_once(|_| {
            Ok(Some(SdJwtVcTypeMetadataCacheItem {
                metadata: SdJwtVcTypeMetadataResponseDTO {
                    vct: "credential-schema-id".to_string(),
                    name: None,
                    display: vec![],
                    claims: vec![],
                    schema: None,
                    schema_uri: None,
                    layout_properties: None,
                },
                integrity: None,
            }))
        });
    let formatter = SDJWTVCFormatter::new(
        params,
        crypto,
        did_method_provider.clone(),
        Arc::new(vct_metadata_cache),
        Arc::new(MockCertificateValidator::new()),
        generic_config().core.datatype,
        Arc::new(MockHttpClient::new()),
    );

    let mut auth_fn = MockSignatureProvider::new();
    let public_key = key_pair.public.clone();
    let private_key = key_pair.private.clone();
    auth_fn
        .expect_sign()
        .returning(move |msg| EDDSASigner {}.sign(msg, &public_key.clone(), &private_key.clone()));
    auth_fn
        .expect_get_key_id()
        .returning(move || Some(format!("{issuer_did}#0")));
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
        certificate_validator: Arc::new(MockCertificateValidator::default()),
    });

    let token = formatter
        .format_credential(credential_data, Box::new(auth_fn))
        .await
        .unwrap();
    let result = formatter
        .extract_credentials(token.as_str(), None, key_verification, None)
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
