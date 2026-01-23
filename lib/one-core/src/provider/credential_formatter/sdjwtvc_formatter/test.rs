use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use maplit::hashmap;
use mockall::predicate::eq;
use one_crypto::hasher::sha256::SHA256;
use one_crypto::signer::eddsa::{EDDSASigner, KeyPair};
use one_crypto::{CryptoProviderImpl, Hasher, MockCryptoProvider, MockHasher, Signer};
use serde_json::json;
use shared_types::{CredentialSchemaId, DidValue, OrganisationId};
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config::core_config::KeyAlgorithmType;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::{CredentialSchemaClaim, LayoutType};
use crate::model::did::{Did, KeyRole};
use crate::model::identifier::Identifier;
use crate::model::key::Key;
use crate::proto::certificate_validator::MockCertificateValidator;
use crate::proto::http_client::{
    Method, MockHttpClient, Request, RequestBuilder, Response, StatusCode,
};
use crate::proto::jwt::model::{JWTPayload, ProofOfPossessionKey};
use crate::proto::key_verification::KeyVerification;
use crate::provider::caching_loader::vct::{
    MockVctTypeMetadataFetcher, SdJwtVcTypeMetadataCacheItem,
};
use crate::provider::credential_formatter::common::MockAuth;
use crate::provider::credential_formatter::model::{
    CredentialClaim, CredentialClaimValue, CredentialData, CredentialPresentation,
    CredentialSchema, CredentialStatus, IdentifierDetails, Issuer, MockSignatureProvider,
    MockTokenVerifier, PublicKeySource, PublishedClaim, PublishedClaimValue,
};
use crate::provider::credential_formatter::sdjwt::disclosures::DisclosureArray;
use crate::provider::credential_formatter::sdjwt::test::get_credential_data;
use crate::provider::credential_formatter::sdjwtvc_formatter::model::SdJwtVc;
use crate::provider::credential_formatter::sdjwtvc_formatter::{Params, SDJWTVCFormatter};
use crate::provider::credential_formatter::vcdm::{VcdmCredential, VcdmCredentialSubject};
use crate::provider::credential_formatter::{CredentialFormatter, nest_claims};
use crate::provider::data_type::provider::MockDataTypeProvider;
use crate::provider::did_method::error::DidMethodProviderError;
use crate::provider::did_method::jwk::JWKDidMethod;
use crate::provider::did_method::key::KeyDidMethod;
use crate::provider::did_method::model::DidDocument;
use crate::provider::did_method::provider::{DidMethodProvider, MockDidMethodProvider};
use crate::provider::did_method::{DidKeys, DidMethod};
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::eddsa::Eddsa;
use crate::provider::key_algorithm::provider::{KeyAlgorithmProvider, MockKeyAlgorithmProvider};
use crate::service::credential_schema::dto::CreateCredentialSchemaRequestDTO;
use crate::service::ssi_issuer::dto::SdJwtVcTypeMetadataResponseDTO;
use crate::service::test_utilities::{
    dummy_did, dummy_did_document, dummy_identifier, dummy_jwk, generic_config,
};
use crate::util::test_utilities::assert_time_diff_less_than;

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

    let holder_did = credential_data
        .holder_identifier
        .as_ref()
        .unwrap()
        .did
        .as_ref()
        .map(|did| did.did.clone())
        .unwrap();

    let did_document = dummy_did_document(&holder_did);
    did_method_provider
        .expect_resolve()
        .return_once(move |_| Ok(did_document));

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
            sd_array_elements: true,
        },
        Arc::new(crypto),
        Arc::new(did_method_provider),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(vct_metadata_cache),
        Arc::new(MockCertificateValidator::new()),
        generic_config().core.datatype,
        Arc::new(MockHttpClient::new()),
        Arc::new(MockDataTypeProvider::new()),
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
            r##"{"alg":"ES256","kid":"#key0","typ":"dc+sd-jwt"}"##
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

    assert_time_diff_less_than(
        &payload.expires_at.unwrap(),
        &(payload.issued_at.unwrap() + Duration::days(365 * 2)),
        &Duration::seconds(5),
    );
    assert_time_diff_less_than(
        &payload.invalid_before.unwrap(),
        &payload.issued_at.unwrap(),
        &Duration::seconds(5),
    );
    assert_eq!(
        payload.proof_of_possession_key,
        Some(ProofOfPossessionKey {
            key_id: None,
            jwk: dummy_jwk(),
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
            CredentialClaim {
                value: serde_json::Value::String(picture_value.clone())
                    .try_into()
                    .unwrap(),
                selectively_disclosable: true,
                metadata: false,
            },
        );
    credential_data.claims.push(PublishedClaim {
        key: "portrait".to_string(),
        value: PublishedClaimValue::String(picture_value),
        datatype: Some("SWIYU_PICTURE".to_string()),
        array_item: false,
    });
    let mut did_method_provider = MockDidMethodProvider::new();

    let holder_did = credential_data
        .holder_identifier
        .as_ref()
        .unwrap()
        .did
        .as_ref()
        .map(|did| did.did.clone())
        .unwrap();

    let holder_did_document = dummy_did_document(&holder_did);

    did_method_provider
        .expect_resolve()
        .return_once(move |_| Ok(holder_did_document));

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
            sd_array_elements: true,
        },
        Arc::new(crypto),
        Arc::new(did_method_provider),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(vct_metadata_cache),
        Arc::new(MockCertificateValidator::new()),
        generic_config().core.datatype,
        Arc::new(MockHttpClient::new()),
        Arc::new(MockDataTypeProvider::new()),
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

    assert_time_diff_less_than(
        &payload.expires_at.unwrap(),
        &(payload.issued_at.unwrap() + Duration::days(365 * 2)),
        &Duration::seconds(5),
    );
    assert_time_diff_less_than(
        &payload.invalid_before.unwrap(),
        &payload.issued_at.unwrap(),
        &Duration::seconds(5),
    );
    assert_eq!(
        payload.proof_of_possession_key,
        Some(ProofOfPossessionKey {
            key_id: None,
            jwk: dummy_jwk(),
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
            sd_array_elements: true,
        },
        Arc::new(crypto),
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(MockVctTypeMetadataFetcher::new()),
        Arc::new(MockCertificateValidator::new()),
        generic_config().core.datatype,
        Arc::new(MockHttpClient::new()),
        Arc::new(MockDataTypeProvider::new()),
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
    assert_eq!(
        credentials.issuance_date,
        Some(OffsetDateTime::from_unix_timestamp(1698151532).unwrap())
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
            "iat": 1698151532,
            "iss": "did:key:z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW",
            "sub": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Im9FTlZzeE9VaUg1NFg4d0pMYVZraWNDUmswMHdCSVE0c1JnYms1NE44TW8ifQ",
            "vct": "IdentityCredential",
        }
    );

    let claim_values_as_json: serde_json::Value =
        CredentialClaimValue::Object(credentials.claims.claims).into();

    assert_eq!(claim_values_as_json, expected_result);
}

#[tokio::test]
async fn test_extract_credentials_swiyu() {
    let jwt_token = "eyJ2ZXIiOiIxLjAiLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDp0ZHc6UW1QRVpQaERGUjRuRVlTRks1Yk1udkVDcWRwZjF0UFRQSnVXczlRck1qQ3VtdzppZGVudGlmaWVyLXJlZy50cnVzdC1pbmZyYS5zd2l5dS1pbnQuYWRtaW4uY2g6YXBpOnYxOmRpZDo5YTU1NTlmMC1iODFjLTQzNjgtYTE3MC1lN2I0YWU0MjQ1MjcjYXNzZXJ0LWtleS1mNGJjMDMyZi1iZmUwLTRiYWItYWNiMy1iYzNlZjdmYjM0MDAifQ.eyJfc2QiOlsiMF9ONVlvRlB3Uk9Gb0ZLNVdhVEV4eDlMOVRIWmZqTUZkOHd2dWFKR2FKRSIsIjEzT3ZoTjNHNjZsS1g3TTRTZmJ2bDVRWU5xVU83akFTVmdJcEFmRDYzdEkiLCI0WlFaOEN1eUlUQ2J4WHM4S1dzTXZwMHVxQllSSlRjOHQzTV9aQlJDRmV3IiwiNTJFamM4VXJSRXAwV0JDaC1YQm9sUURESmJYOUdHNmVBWXhJSURtaExfWSIsIjVsLTRlLTlQUkdiWUFxdW1qb0lyUmFNcGVBWm9jeHpyMF82ZXRyZWQtOWsiLCI5U3RwV00zTFJZNE9wM3JLSElNdDRlWVY1VzAwYWktdFFIbHBHckw3QTRnIiwiOXJDMEF1OXBCbGpMZGJmX0Z6RUxxRTU3d25UbFJVMkVrdVJsQTRwV3MzdyIsIkNJUTFvaktOQ293Mlp5ckNHRW1BR00wa2lrRFpDczg5X3RZOHlqMF8zME0iLCJDTnBMVFhaeEZaXzdxOE85WEdNSVpWNUQwemVWV2Jwc0RDSG1HdUh0b2hJIiwiRHFYZ1lldG1uQkZ3X3F6dUlpb0lGaVQ0aUpuaWRLT0lRdHpsakVUZnhKNCIsIkdYSk5Gb196cWxzMzdRT3lnRnNvMVhYa2NxRl9xYU1MZXNyaElDNmxGWHMiLCJIX3ctQkQwTkZWSkg2bGx6dzh1Vm9WdHNEVXRGSUlKNlRlZkpWQ2hNaEVJIiwiSWE0bUFqYmxsNmZwTXduakJncnBhc1JEQzRUSXUzRl9LbjBVNkRMbUYwcyIsIktOVk9hVEFyQ0cyMjlHZGZldFQya3JzTHhpaWdEUGRTdVpPU1J3VHFOcVUiLCJLdGlZcDh2VFJad3ZpaXpCaW9uRGpQcnBfZ25tSUxkOGZzalhXTy0wME5JIiwiT2RuUGNBeVNNcEhVQVM3SGMzU21heWhuSVphU0g2LTRIYmxTNkh0QWZFcyIsIl9CRHQwUFI3dnA0V082amN6T2dIc19uSjJMMG9mYTdFTk00MlR3QkFtcDQiLCJiVXVNeFl5YlZvYldPam5BREpWU21rUkFZV3V2LVRKWFRXdG9leFFhQWR3IiwiZDBUTWdQa0l4UVJxR2VpRWRfTXpDa0JnSEM0M0xLenFGeGExSU16Ny1MQSIsImlkVlRSWHY5MVpUOXk3clRUOUx5X20wal8wQnZzemlEMVd6MFFxOGlyNE0iLCJraF9zSlM5WG9mZ0tXc0JXbnM1ZFE1XzdQcWlPZ0FVQ09KbnRrYnU0MHNrIiwibU55TDBUTEhYQmhUay1ld0JWYlJGeFVDUnRrbmE4dEFzVjBiV0wyNmJDVSIsInl4MXdzNDF1TkxfTU9hbTEwMmktVE1sd3BpSk1PVUJQNzRRbl9TQ1pNRzQiXSwidmN0IjoiYmV0YWlkLXNkand0IiwiX3NkX2FsZyI6InNoYS0yNTYiLCJpc3MiOiJkaWQ6dGR3OlFtUEVaUGhERlI0bkVZU0ZLNWJNbnZFQ3FkcGYxdFBUUEp1V3M5UXJNakN1bXc6aWRlbnRpZmllci1yZWcudHJ1c3QtaW5mcmEuc3dpeXUtaW50LmFkbWluLmNoOmFwaTp2MTpkaWQ6OWE1NTU5ZjAtYjgxYy00MzY4LWExNzAtZTdiNGFlNDI0NTI3IiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlpwOXFMYVRKTWh1UC1kcE1hOXBMbHBxWmNRNGNoVkRKeVNXcmlzQUFpMmciLCJ5IjoieHVWdTVYZ1BOUUstUDBUc0RsaGE4cDVNZkFEZVpoU2dTNzdLVVYzaGN2RSJ9fSwiaWF0IjoxNzQ2NDU0MzU1LCJzdGF0dXMiOnsic3RhdHVzX2xpc3QiOnsidHlwZSI6IlN3aXNzVG9rZW5TdGF0dXNMaXN0LTEuMCIsImlkeCI6Nzk2NCwidXJpIjoiaHR0cHM6Ly9zdGF0dXMtcmVnLnRydXN0LWluZnJhLnN3aXl1LWludC5hZG1pbi5jaC9hcGkvdjEvc3RhdHVzbGlzdC8xOTNmZGM5OC0wYjEwLTRiNjUtODc2Yi1lZjQ0ZjdiMTAxOTAuand0In19fQ";
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
            sd_array_elements: true,
        },
        Arc::new(crypto),
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(MockVctTypeMetadataFetcher::new()),
        Arc::new(MockCertificateValidator::new()),
        generic_config().core.datatype,
        Arc::new(MockHttpClient::new()),
        Arc::new(MockDataTypeProvider::new()),
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
        format: "".into(),
        revocation_method: "".into(),
        key_storage_security: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: "".to_string(),
        imported_source_url: "".to_string(),
        allow_suspension: false,
        requires_app_attestation: false,
        claim_schemas: Some(vec![CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "portrait".to_string(),
                data_type: "SWIYU_PICTURE".to_string(),
                created_date: now,
                last_modified: now,
                array: false,
                metadata: false,
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
            "expiry_date": "2025-08-05",
            "iat": 1746454355,
            "iss": "did:tdw:QmPEZPhDFR4nEYSFK5bMnvECqdpf1tPTPJuWs9QrMjCumw:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:9a5559f0-b81c-4368-a170-e7b4ae424527",
            "sub": "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlpwOXFMYVRKTWh1UC1kcE1hOXBMbHBxWmNRNGNoVkRKeVNXcmlzQUFpMmciLCJ5IjoieHVWdTVYZ1BOUUstUDBUc0RsaGE4cDVNZkFEZVpoU2dTNzdLVVYzaGN2RSJ9",
            "vct": "betaid-sdjwt"
        }
    );

    let claim_values_as_json: serde_json::Value =
        CredentialClaimValue::Object(credentials.claims.claims).into();

    assert_eq!(claim_values_as_json, expected_result);
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
            sd_array_elements: true,
        },
        Arc::new(crypto),
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(MockVctTypeMetadataFetcher::new()),
        Arc::new(MockCertificateValidator::new()),
        generic_config().core.datatype,
        Arc::new(http_client),
        Arc::new(MockDataTypeProvider::new()),
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
fn test_schema_id_internal() {
    let formatter = SDJWTVCFormatter::new(
        Params {
            leeway: 45u64,
            embed_layout_properties: false,
            swiyu_mode: false,
            sd_array_elements: true,
        },
        Arc::new(MockCryptoProvider::default()),
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(MockVctTypeMetadataFetcher::new()),
        Arc::new(MockCertificateValidator::new()),
        generic_config().core.datatype,
        Arc::new(MockHttpClient::new()),
        Arc::new(MockDataTypeProvider::new()),
    );

    let request_dto = CreateCredentialSchemaRequestDTO {
        name: "".to_string(),
        format: "".into(),
        revocation_method: "".into(),
        organisation_id: OrganisationId::from(Uuid::new_v4()),
        claims: vec![],
        external_schema: false,
        key_storage_security: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: None,
        allow_suspension: None,
        requires_app_attestation: false,
    };

    let id = Uuid::new_v4();
    let result = formatter.credential_schema_id(id.into(), &request_dto, "https://example.com");
    assert!(result.is_ok());
    assert_eq!(
        result.unwrap(),
        format!(
            "https://example.com/ssi/vct/v1/{}/{id}",
            request_dto.organisation_id
        )
    )
}

#[test]
fn test_schema_id_external() {
    let formatter = SDJWTVCFormatter::new(
        Params {
            leeway: 45u64,
            embed_layout_properties: false,
            swiyu_mode: false,
            sd_array_elements: true,
        },
        Arc::new(MockCryptoProvider::default()),
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(MockVctTypeMetadataFetcher::new()),
        Arc::new(MockCertificateValidator::new()),
        generic_config().core.datatype,
        Arc::new(MockHttpClient::new()),
        Arc::new(MockDataTypeProvider::new()),
    );
    let vct = "https://example.com/vct/xyz%20some_vct_type";
    let request_dto = CreateCredentialSchemaRequestDTO {
        name: "".to_string(),
        format: "".into(),
        revocation_method: "".into(),
        organisation_id: OrganisationId::from(Uuid::new_v4()),
        claims: vec![],
        external_schema: true,
        key_storage_security: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: Some(vct.to_string()),
        allow_suspension: None,
        requires_app_attestation: false,
    };

    let result = formatter.credential_schema_id(
        CredentialSchemaId::from(Uuid::new_v4()),
        &request_dto,
        "https://core.base.com",
    );
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), vct)
}

#[tokio::test]
async fn test_format_extract_round_trip_non_sd_array_elements() {
    let now = OffsetDateTime::now_utc();
    let params = Params {
        leeway: 60,
        embed_layout_properties: false,
        swiyu_mode: false,
        sd_array_elements: false,
    };

    let (key_algorithm_provider, did_method_provider, formatter) = formatter_for_params(params);

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
        .unwrap()
        .with_id(holder_did.clone().into_url());

    let vcdm = VcdmCredential::new_v2(issuer, credential_subject)
        .add_credential_schema(schema)
        .with_valid_from(now)
        .with_valid_until(now + Duration::seconds(10));

    let holder_identifier = Identifier {
        did: Some(Did {
            did: holder_did.clone(),
            ..dummy_did()
        }),
        ..dummy_identifier()
    };

    let credential_data = CredentialData {
        vcdm,
        claims,
        holder_identifier: Some(holder_identifier),
        holder_key_id: Some(format!("{holder_did}#0")),
        issuer_certificate: None,
    };

    let auth_fn = test_auth_fn(key_pair, issuer_did);
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

    let expected: HashMap<String, CredentialClaim> = hashmap! {
        "object".into() => CredentialClaim {
            selectively_disclosable: true,
            metadata: false,
            value: CredentialClaimValue::Object(
                hashmap! {
                    "measurements".into() => CredentialClaim {
                            selectively_disclosable: true,
                            metadata: false,
                            value: json!([{"air pollution": 24.6}]).try_into().unwrap(),
                        },
                    "name".into() => CredentialClaim {
                            selectively_disclosable: true,
                            metadata: false,
                            value: json!("Mike").try_into().unwrap(),
                        },
                }
            )
        },
        "age".into() => CredentialClaim {
            selectively_disclosable: true,
            metadata: false,
            value: json!(22).try_into().unwrap(),
        },
        "is_over_18".into() => CredentialClaim {
            selectively_disclosable: true,
            metadata: false,
            value: json!(true).try_into().unwrap(),
        },
        "iss".into()=> CredentialClaim {
            selectively_disclosable: false,
            metadata: true,
            value: json!(
                result.issuer.did_value().unwrap().as_str()
            ).try_into().unwrap(),
        },
        "vct".into()=> CredentialClaim {
            selectively_disclosable: false,
            metadata: true,
            value: CredentialClaimValue::String("credential-schema-id".to_string()),
        },
        "nbf".into()=> CredentialClaim {
            selectively_disclosable: false,
            metadata: true,
            value: json!(result.invalid_before.unwrap().unix_timestamp()).try_into().unwrap(),

        },
        "iat".into()=> CredentialClaim {
            selectively_disclosable: false,
            metadata: true,
            value: json!(result.issuance_date.unwrap().unix_timestamp()).try_into().unwrap(),

        },
        "sub".into() => CredentialClaim {
            selectively_disclosable: false,
            metadata: true,
            value: CredentialClaimValue::String(
                "did:key:z6Mkv3HL52XJNh4rdtnPKPRndGwU8nAuVpE7yFFie5SNxZkX".to_owned(),
            ),
        },
        "exp".into()=> CredentialClaim {
            selectively_disclosable: false,
            metadata: true,
            value:
                json!(result.valid_until.unwrap().unix_timestamp()).try_into().unwrap(),
        },
    };
    assert_eq!(result.claims.claims, expected)
}

fn test_auth_fn(key_pair: KeyPair, issuer_did: DidValue) -> MockSignatureProvider {
    let mut auth_fn = MockSignatureProvider::new();
    let public_key = key_pair.public.clone();
    let private_key = key_pair.private.clone();
    auth_fn
        .expect_sign()
        .returning(move |msg| EDDSASigner {}.sign(msg, &public_key.clone(), &private_key.clone()));
    auth_fn
        .expect_get_key_id()
        .returning(move || Some(format!("{issuer_did}#0")));
    auth_fn
        .expect_get_public_key()
        .returning(move || key_pair.public.clone());
    auth_fn
        .expect_jose_alg()
        .returning(|| Some("EdDSA".to_string()));
    auth_fn
}

#[tokio::test]
async fn test_format_extract_round_trip_sd_array_elements() {
    let now = OffsetDateTime::now_utc();
    let params = Params {
        leeway: 60,
        embed_layout_properties: false,
        swiyu_mode: false,
        sd_array_elements: true,
    };

    let (key_algorithm_provider, did_method_provider, formatter) = formatter_for_params(params);

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
        .unwrap()
        .with_id(holder_did.clone().into_url());

    let vcdm = VcdmCredential::new_v2(issuer, credential_subject)
        .add_credential_schema(schema)
        .with_valid_from(now)
        .with_valid_until(now + Duration::seconds(10));

    let holder_identifier = Identifier {
        did: Some(Did {
            did: holder_did.clone(),
            ..dummy_did()
        }),
        ..dummy_identifier()
    };

    let credential_data = CredentialData {
        vcdm,
        claims,
        holder_identifier: Some(holder_identifier),
        holder_key_id: Some(format!("{holder_did}#0")),
        issuer_certificate: None,
    };

    let auth_fn = test_auth_fn(key_pair, issuer_did);
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

    let expected: HashMap<String, CredentialClaim> = hashmap! {
        "object".into() => CredentialClaim {
            selectively_disclosable: true,
            metadata: false,
            value: CredentialClaimValue::Object(
                hashmap! {
                    "measurements".into() => CredentialClaim {
                            selectively_disclosable: true,
                            metadata: false,
                            value: CredentialClaimValue::Array(vec![
                                CredentialClaim {
                                    selectively_disclosable: true,
                                    metadata: false,
                                    value: CredentialClaimValue::Object(
                                        hashmap! {
                                            "air pollution".into() => CredentialClaim {
                                                selectively_disclosable: true,
                                                metadata: false,
                                                value: json!(24.6).try_into().unwrap(),
                                            },
                                        }
                                    )
                                }
                            ])
                        },
                    "name".into() => CredentialClaim {
                            selectively_disclosable: true,
                            metadata: false,
                            value: json!("Mike").try_into().unwrap(),
                        },
                }
            )
        },
        "age".into() => CredentialClaim {
            selectively_disclosable: true,
            metadata: false,
            value: json!(22).try_into().unwrap(),
        },
        "is_over_18".into() => CredentialClaim {
            selectively_disclosable: true,
            metadata: false,
            value: json!(true).try_into().unwrap(),
        },
        "iss".into()=> CredentialClaim {
            selectively_disclosable: false,
            metadata: true,
            value: json!(
                result.issuer.did_value().unwrap().as_str()
            ).try_into().unwrap(),
        },
        "vct".into()=> CredentialClaim {
            selectively_disclosable: false,
            metadata: true,
            value: CredentialClaimValue::String("credential-schema-id".to_string()),
        },
        "nbf".into()=> CredentialClaim {
            selectively_disclosable: false,
            metadata: true,
            value: json!(result.invalid_before.unwrap().unix_timestamp()).try_into().unwrap(),

        },
        "iat".into()=> CredentialClaim {
            selectively_disclosable: false,
            metadata: true,
            value: json!(result.issuance_date.unwrap().unix_timestamp()).try_into().unwrap(),

        },
        "sub".into() => CredentialClaim {
            selectively_disclosable: false,
            metadata: true,
            value: CredentialClaimValue::String(
                "did:key:z6Mkv3HL52XJNh4rdtnPKPRndGwU8nAuVpE7yFFie5SNxZkX".to_owned(),
            ),
        },
        "exp".into()=> CredentialClaim {
            selectively_disclosable: false,
            metadata: true,
            value:
                json!(result.valid_until.unwrap().unix_timestamp()).try_into().unwrap(),
        },
    };
    assert_eq!(result.claims.claims, expected)
}

struct FakeDidMethodProvider(Arc<dyn KeyAlgorithmProvider>);

#[async_trait::async_trait]
impl DidMethodProvider for FakeDidMethodProvider {
    async fn resolve(&self, did: &DidValue) -> Result<DidDocument, DidMethodProviderError> {
        let method: Arc<dyn DidMethod> = if did.as_str().starts_with("did:key") {
            Arc::new(KeyDidMethod::new(self.0.clone()))
        } else {
            Arc::new(JWKDidMethod::new(self.0.clone()))
        };
        Ok(method.resolve(did).await.unwrap())
    }

    fn get_did_method(&self, _did_method_id: &str) -> Option<Arc<dyn DidMethod>> {
        unimplemented!()
    }

    fn get_did_method_id(&self, _did: &DidValue) -> Option<String> {
        unimplemented!()
    }

    fn get_did_method_by_method_name(
        &self,
        _method_name: &str,
    ) -> Option<(String, Arc<dyn DidMethod>)> {
        unimplemented!()
    }

    fn supported_method_names(&self) -> Vec<String> {
        unimplemented!()
    }
}

fn formatter_for_params(
    params: Params,
) -> (
    Arc<dyn KeyAlgorithmProvider>,
    Arc<dyn DidMethodProvider>,
    SDJWTVCFormatter,
) {
    let hashers = hashmap! {
        "sha-256".to_string() => Arc::new(SHA256 {}) as Arc<dyn Hasher>
    };
    let signers = hashmap! {
        "Ed25519".to_string() => Arc::new(EDDSASigner {}) as Arc<dyn Signer>,
    };
    let crypto = Arc::new(CryptoProviderImpl::new(hashers, signers));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .returning(|_| Some(Arc::new(Eddsa)));
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .returning(|_| Some((KeyAlgorithmType::Eddsa, Arc::new(Eddsa))));
    let key_algorithm_provider = Arc::new(key_algorithm_provider);

    let did_method_provider = Arc::new(FakeDidMethodProvider(key_algorithm_provider.clone()));

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
        key_algorithm_provider.clone(),
        Arc::new(vct_metadata_cache),
        Arc::new(MockCertificateValidator::new()),
        generic_config().core.datatype,
        Arc::new(MockHttpClient::new()),
        Arc::new(MockDataTypeProvider::new()),
    );
    (key_algorithm_provider, did_method_provider, formatter)
}

#[tokio::test]
async fn test_parse_credential_eudi() {
    const CREDENTIAL: &str = "eyJhbGciOiJFUzI1NiIsInR5cCI6InZjK3NkLWp3dCIsIng1YyI6WyJNSUlDK1RDQ0FxQ2dBd0lCQWdJVUQwaStTd0JnQjZ1b3QvSnFpUmc2VlMvZmprOHdDZ1lJS29aSXpqMEVBd0l3WERFZU1Cd0dBMVVFQXd3VlVFbEVJRWx6YzNWbGNpQkRRU0F0SUZWVUlEQXlNUzB3S3dZRFZRUUtEQ1JGVlVSSklGZGhiR3hsZENCU1pXWmxjbVZ1WTJVZ1NXMXdiR1Z0Wlc1MFlYUnBiMjR4Q3pBSkJnTlZCQVlUQWxWVU1CNFhEVEkxTURjeU1qRXpNemd3TjFvWERUSTNNRGN5TWpFek16Z3dObG93UlRFVU1CSUdBMVVFQXd3TFVISnZZMmwyYVhNZ1FVY3hDakFJQmdOVkJBVVRBVEF4RkRBU0JnTlZCQW9NQzFCeWIyTnBkbWx6SUVGSE1Rc3dDUVlEVlFRR0V3SlZWREJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTmFSWnBBTXlnNDJhUjZVWjFUMlJKaFViQTNSSTVpMEp5OVptK040Q0hPODVpZUhHTkdDOU94Y052NTBsZUxZemJibk82cjFWaWNPSXp6Ylh5T09hZHlqZ2dGVk1JSUJVVEFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGR0xIbEVjb3ZRK2lGaUNubXNKSmxFVHhBZFBITURrR0ExVWRFUVF5TURDQkUzTjFjSEJ2Y25SQWNISnZZMmwyYVhNdVkyaUNHV052Y21VdVpHVjJMbkJ5YjJOcGRtbHpMVzl1WlM1amIyMHdFZ1lEVlIwbEJBc3dDUVlIS0lHTVhRVUJCakJEQmdOVkhSOEVQREE2TURpZ05xQTBoakpvZEhSd2N6b3ZMM0J5WlhCeWIyUXVjR3RwTG1WMVpHbDNMbVJsZGk5amNtd3ZjR2xrWDBOQlgxVlVYekF5TG1OeWJEQWRCZ05WSFE0RUZnUVVwSktpd25LVDdTMXBEWEhabFU3TkNBTjAwcTR3RGdZRFZSMFBBUUgvQkFRREFnZUFNRjBHQTFVZEVnUldNRlNHVW1oMGRIQnpPaTh2WjJsMGFIVmlMbU52YlM5bGRTMWthV2RwZEdGc0xXbGtaVzUwYVhSNUxYZGhiR3hsZEM5aGNtTm9hWFJsWTNSMWNtVXRZVzVrTFhKbFptVnlaVzVqWlMxbWNtRnRaWGR2Y21zd0NnWUlLb1pJemowRUF3SURSd0F3UkFJZkk2RTRLcnYrcXFtMFVFajJRTFViWXljMklJTXlnelN1LzRTdTJrekhVQUloQUowd2ZOTzBjWmRXTFdleG5lOXlsV1lFRmtpRU51TGlWUUN2R3ZRdUhXZTUiXX0.eyJpYXQiOjE3NTc1NzczMjEsImV4cCI6MTgyMDY0OTMyMSwibmJmIjoxNzU3NTc3MzIxLCJpc3MiOiJodHRwczovL2NvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20vc3NpL29wZW5pZDR2Y2kvZHJhZnQtMTMvMjhhZWUwNjktNDhjMC00ZmY5LTljZTktNzU2MDFhZWM4MjZkIiwic3ViIjoiZGlkOmtleTp6RG5hZWJ2eVZwd0czUjdRajF6bnJWeTlydHNpNk44VGdqV1BLWmh5QmRhMnF2NTh3IiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6InF0N3BDelJjOHhCVFlkNDh0WWNuRWRZSVFVWE9HRnRZOXZxWkxEbklTNFEiLCJ5IjoiMnRHOTZlU3JPLU5KeFVhQldzUnhXaThrampDMUZKaEZxTmtRRzM1WnR1WSJ9fSwidmN0IjoidXJuOmV1ZGk6cGlkOjEiLCJfc2QiOlsiNUx0NTVNM2J5S0JlX0p1RkFKX3Rta09JVWV0VnZ1ZjVkY1BRODlnYVdQQSIsIjdwQTNtaUlGenRIVUJsQXM1UkFwVFZIMkN3TVNmMk1MeUtOMHFjWUp2LVUiLCJSS2w4YW90eU5kcHI3NTVfN0ZXY0dzOEVtYl93NlV2ZTR1S2dhU2VNZWRZIiwiZUw5dEhnMi1JQ3hUMk9OTE5iV0VlNzVqQWJJZURRV2c4Q1JRa1JSX3F0OCIsImtZMmVaM3VrTlVjdnlnN25UQnNmZ0JBaHBja2tFR2xEQUV0a3Q1SGFrT1EiLCJ1Rk1Gb2M5aXdfOXo0NnB1akpNWER0ZUEwT1MyNHZJaFhGdUZ0SzRMemNVIiwidmJ4d212alZEcnQ5U2tHU0p4OXMxOU1Ua2tzSjN3V0NwbHdQZXhpbWdOTSJdLCJfc2RfYWxnIjoic2hhLTI1NiIsInN0YXR1cyI6eyJzdGF0dXNfbGlzdCI6eyJpZHgiOjMwLCJ1cmkiOiJodHRwczovL2NvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20vc3NpL3Jldm9jYXRpb24vdjEvbGlzdC9mNWI1NGNhNS05NmVjLTQxZmQtYjRkMS0zODM0NDQ1NGNjY2EifX19.SoKrlj3ZQcDD0JpA2s50gJfPDL1eQpNg7TjchIIMERwJoNeYsm8fkk1ODzkiSLSxU3OFRa-FF-HQmoZJpryZyQ~WyJWS2Nqd1pIOFFBUVAyeUY1a1MtN0xnIiwiYmlydGhkYXRlIiwiMTk5MC0wMS0wMSJd~WyJ6Y0tDREgxcjlFSFJPVmhJQVhTN1pRIiwiZmFtaWx5X25hbWUiLCJNdXN0ZXIiXQ~WyJqOGVrVEtLWDhiLU9WYTdEcHFRZ013IiwiZ2l2ZW5fbmFtZSIsIk1heCJd~WyJ5TnplR1djT0xLY2lXNzcyR28wQjN3IiwiaXNzdWluZ19hdXRob3JpdHkiLCJUZXN0Il0~WyJzelhMdmwyUGJmTnFMdG9yNWduQTdBIiwiaXNzdWluZ19jb3VudHJ5IiwiQ0giXQ~WyJlZkQ2eGlXS2ZjQy1neTRGaEZGaVVRIiwiQ0giXQ~WyJESF9rNnVFQmhDNHJiVkNnVlFzVVlRIiwiSVQiXQ~WyI0SmNDT0tjeEEyQlJPOTZpcW9pWUl3IiwiREUiXQ~WyI3TTNvVVZ4c1ZKUlpEWWRWYnhGX0FBIiwibmF0aW9uYWxpdGllcyIsW3siLi4uIjoiZU9aTncxWEZIcERWWHZPUWcwYmJpWDFTUWJISlIwWFFfYnNjMXJMZWJsYyJ9LHsiLi4uIjoicXg0X3RaMV81XzlnRGMyMmd0TDFNdjViV3VCeWxVck5oMGRPaHhLek9VRSJ9LHsiLi4uIjoiQXA4X09NZ3ljbFhHME9jZC1HeEtJSENvMlFYOTVsdzhuTWlxTzNNVVhiQSJ9XV0~WyJ1eUxxOUFMNHkzNUoxcFpMMlZMbTF3IiwibG9jYWxpdHkiLCJDSCJd~WyJieTdYN3FmZXBiZHJhUzNGVHhkRHJnIiwicGxhY2Vfb2ZfYmlydGgiLHsiX3NkIjpbIjhzaVdNN2lmZnFSaXU3cDRvM1Z3b2ttOU1oTHFWakhJUGlSU1dlNWRjU1UiXX1d~";

    let params = Params {
        leeway: 60,
        embed_layout_properties: false,
        swiyu_mode: false,
        sd_array_elements: true,
    };
    let hashers = hashmap! {
        "sha-256".to_string() => Arc::new(SHA256) as Arc<dyn Hasher>
    };

    let crypto = Arc::new(CryptoProviderImpl::new(hashers, HashMap::new()));

    let mut certificate_validator = MockCertificateValidator::new();
    certificate_validator
        .expect_parse_pem_chain()
        .returning(|_, _| {
            use crate::proto::certificate_validator::ParsedCertificate;
            use crate::provider::key_algorithm::key::{
                KeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
            };
            use crate::service::certificate::dto::CertificateX509AttributesDTO;
            let now = OffsetDateTime::now_utc();
            Ok(ParsedCertificate {
                attributes: CertificateX509AttributesDTO {
                    serial_number: "test".to_string(),
                    not_before: now,
                    not_after: now,
                    issuer: "Test Issuer".to_string(),
                    subject: "Test Subject".to_string(),
                    fingerprint: "test".to_string(),
                    extensions: vec![],
                },
                subject_common_name: Some("Test".to_string()),
                subject_key_identifier: None,
                public_key: KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(Arc::new(
                    MockSignaturePublicKeyHandle::default(),
                ))),
            })
        });

    let mut datatype_provider = MockDataTypeProvider::new();
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

    let formatter = SDJWTVCFormatter::new(
        params,
        crypto,
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(MockVctTypeMetadataFetcher::new()),
        Arc::new(certificate_validator),
        generic_config().core.datatype,
        Arc::new(MockHttpClient::new()),
        Arc::new(datatype_provider),
    );

    let result = formatter.parse_credential(CREDENTIAL).await.unwrap();

    // Verify claims were parsed
    assert!(result.claims.is_some());
    let claims = result.claims.as_ref().unwrap();

    assert_eq!(claims.len(), 17);

    // Verify vct metadata claim
    let vct_claim = claims.iter().find(|c| c.path == "vct").unwrap();
    assert_eq!(vct_claim.value.as_deref(), Some("urn:eudi:pid:1"));
    assert_eq!(vct_claim.selectively_disclosable, false);
    let vct_schema = vct_claim.schema.as_ref().unwrap();
    assert_eq!(vct_schema.key, "vct");
    assert_eq!(vct_schema.data_type, "STRING");
    assert_eq!(vct_schema.array, false);
    assert_eq!(vct_schema.metadata, true);

    // Verify issuing_authority claim
    let issuing_authority_claim = claims
        .iter()
        .find(|c| c.path == "issuing_authority")
        .unwrap();
    assert_eq!(issuing_authority_claim.value.as_deref(), Some("Test"));
    assert_eq!(issuing_authority_claim.selectively_disclosable, true);
    assert_eq!(
        issuing_authority_claim.schema.as_ref().unwrap().key,
        "issuing_authority"
    );
    assert_eq!(
        issuing_authority_claim.schema.as_ref().unwrap().data_type,
        "STRING"
    );

    // Verify issuing_country claim
    let issuing_country_claim = claims.iter().find(|c| c.path == "issuing_country").unwrap();
    assert_eq!(issuing_country_claim.value.as_deref(), Some("CH"));
    assert_eq!(issuing_country_claim.selectively_disclosable, true);
    assert_eq!(
        issuing_country_claim.schema.as_ref().unwrap().key,
        "issuing_country"
    );
    assert_eq!(
        issuing_country_claim.schema.as_ref().unwrap().data_type,
        "STRING"
    );

    // Verify given_name claim
    let given_name_claim = claims.iter().find(|c| c.path == "given_name").unwrap();
    assert_eq!(given_name_claim.value.as_deref(), Some("Max"));
    assert_eq!(given_name_claim.selectively_disclosable, true);
    assert_eq!(given_name_claim.schema.as_ref().unwrap().key, "given_name");
    assert_eq!(
        given_name_claim.schema.as_ref().unwrap().data_type,
        "STRING"
    );

    // Verify family_name claim
    let family_name_claim = claims.iter().find(|c| c.path == "family_name").unwrap();
    assert_eq!(family_name_claim.value.as_deref(), Some("Muster"));
    assert_eq!(family_name_claim.selectively_disclosable, true);
    assert_eq!(
        family_name_claim.schema.as_ref().unwrap().key,
        "family_name"
    );
    assert_eq!(
        family_name_claim.schema.as_ref().unwrap().data_type,
        "STRING"
    );

    // Verify birthdate claim
    let birthdate_claim = claims.iter().find(|c| c.path == "birthdate").unwrap();
    assert_eq!(birthdate_claim.value.as_deref(), Some("1990-01-01"));
    assert_eq!(birthdate_claim.selectively_disclosable, true);
    assert_eq!(birthdate_claim.schema.as_ref().unwrap().key, "birthdate");
    assert_eq!(birthdate_claim.schema.as_ref().unwrap().data_type, "STRING");

    // Verify nationalities array claim
    let nationalities_claim = claims.iter().find(|c| c.path == "nationalities").unwrap();
    assert_eq!(nationalities_claim.value, None);
    assert_eq!(nationalities_claim.selectively_disclosable, true);
    let nationalities_schema = nationalities_claim.schema.as_ref().unwrap();
    assert_eq!(nationalities_schema.key, "nationalities");
    assert_eq!(nationalities_schema.data_type, "STRING");
    assert_eq!(nationalities_schema.array, true);
    assert_eq!(nationalities_schema.metadata, false);

    // Verify nationalities array elements (each is individually selectively disclosable)
    let nat0_claim = claims.iter().find(|c| c.path == "nationalities/0").unwrap();
    assert_eq!(nat0_claim.value.as_deref(), Some("CH"));
    assert_eq!(nat0_claim.selectively_disclosable, true);

    let nat1_claim = claims.iter().find(|c| c.path == "nationalities/1").unwrap();
    assert_eq!(nat1_claim.value.as_deref(), Some("IT"));
    assert_eq!(nat1_claim.selectively_disclosable, true);

    let nat2_claim = claims.iter().find(|c| c.path == "nationalities/2").unwrap();
    assert_eq!(nat2_claim.value.as_deref(), Some("DE"));
    assert_eq!(nat2_claim.selectively_disclosable, true);

    // Verify place_of_birth object claim
    let place_of_birth_claim = claims.iter().find(|c| c.path == "place_of_birth").unwrap();
    assert_eq!(place_of_birth_claim.value, None);
    assert_eq!(place_of_birth_claim.selectively_disclosable, true);
    let place_of_birth_schema = place_of_birth_claim.schema.as_ref().unwrap();
    assert_eq!(place_of_birth_schema.key, "place_of_birth");
    assert_eq!(place_of_birth_schema.data_type, "OBJECT");
    assert_eq!(place_of_birth_schema.array, false);
    assert_eq!(place_of_birth_schema.metadata, false);

    let locality_claim = claims
        .iter()
        .find(|c| c.path == "place_of_birth/locality")
        .unwrap();
    assert_eq!(locality_claim.value.as_deref(), Some("CH"));
    assert_eq!(locality_claim.selectively_disclosable, true);
    assert_eq!(
        locality_claim.schema.as_ref().unwrap().key,
        "place_of_birth/locality"
    );
    assert_eq!(locality_claim.schema.as_ref().unwrap().data_type, "STRING");

    // Verify claim_schemas were populated and deduplicated
    assert!(result.schema.is_some());
    let schema = result.schema.as_ref().unwrap();
    assert!(schema.claim_schemas.is_some());
    let claim_schemas = schema.claim_schemas.as_ref().unwrap();

    assert_eq!(claim_schemas.len(), 14);

    // Verify claim schema keys
    let schema_keys: Vec<(&str, bool)> = claim_schemas
        .iter()
        .map(|cs| (cs.schema.key.as_str(), cs.schema.array))
        .collect();

    // Metadata schemas
    assert!(schema_keys.contains(&("vct", false)));
    assert!(schema_keys.contains(&("iss", false)));
    assert!(schema_keys.contains(&("iat", false)));
    assert!(schema_keys.contains(&("exp", false)));
    assert!(schema_keys.contains(&("nbf", false)));
    assert!(schema_keys.contains(&("sub", false)));

    // User claim schemas
    assert!(schema_keys.contains(&("issuing_authority", false)));
    assert!(schema_keys.contains(&("issuing_country", false)));
    assert!(schema_keys.contains(&("given_name", false)));
    assert!(schema_keys.contains(&("family_name", false)));
    assert!(schema_keys.contains(&("birthdate", false)));
    assert!(schema_keys.contains(&("nationalities", true))); // only array schema, elements reuse same ID
    assert!(schema_keys.contains(&("place_of_birth", false)));
    assert!(schema_keys.contains(&("place_of_birth/locality", false)));

    // Verify array elements reuse the array schema's ID
    let nat_array_schema_id = claim_schemas
        .iter()
        .find(|cs| cs.schema.key == "nationalities" && cs.schema.array)
        .unwrap()
        .schema
        .id;
    let nat0_schema_id = claims
        .iter()
        .find(|c| c.path == "nationalities/0")
        .unwrap()
        .schema
        .as_ref()
        .unwrap()
        .id;
    assert_eq!(nat_array_schema_id, nat0_schema_id);
}

#[tokio::test]
async fn test_parse_credential() {
    const CREDENTIAL: &str = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRjK3NkLWp3dCIsICJraWQiOiAiZG9jLXNpZ25lci0wNS0yNS0yMDIyIn0.eyJfc2QiOiBbIjA5dktySk1PbHlUV00wc2pwdV9wZE9CVkJRMk0xeTNLaHBINTE1blhrcFkiLCAiMnJzakdiYUMwa3k4bVQwcEpyUGlvV1RxMF9kYXcxc1g3NnBvVWxnQ3diSSIsICJFa084ZGhXMGRIRUpidlVIbEVfVkNldUM5dVJFTE9pZUxaaGg3WGJVVHRBIiwgIklsRHpJS2VpWmREd3BxcEs2WmZieXBoRnZ6NUZnbldhLXNONndxUVhDaXciLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiamRyVEU4WWNiWTRFaWZ1Z2loaUFlX0JQZWt4SlFaSUNlaVVRd1k5UXF4SSIsICJqc3U5eVZ1bHdRUWxoRmxNXzNKbHpNYVNGemdsaFFHMERwZmF5UXdMVUs0Il0sICJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiaWF0IjogMTY4MzAwMDAwMCwgImV4cCI6IDE4ODMwMDAwMDAsICJ2Y3QiOiAiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIiwgIl9zZF9hbGciOiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIlRDQUVSMTladnUzT0hGNGo0VzR2ZlNWb0hJUDFJTGlsRGxzN3ZDZUdlbWMiLCAieSI6ICJaeGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1ZWNDRTZ0NGpUOUYySFpRIn19fQ.UjmuruClAiGb_73ZlUFbk8D47xZBfHrFDoshHyVYev2hotn_HUe9S-lOKHIaniLO5THEK52WWT1lcpQVE4rAXw~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImlzX292ZXJfNjUiLCB0cnVlXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgImlhdCI6IDE3NTc5NTQ1OTMsICJzZF9oYXNoIjogImlDVDUyYTZiQ3IzU2JIS0NmVGhXM0E5QWo4LXBKdWZnTG5TVWJ1a1JFV0EifQ.u5ysVyH__ALmpsfCMigshvjoDnFqGA8eepMoway-HH3Zbie_LFqxmA0cLx_j6SBtEUtqed-FGEGmV_j-EK4Yaw";
    const ISSUER_URL: &str = "https://example.com/.well-known/jwt-vc-issuer/issuer";
    let params = Params {
        leeway: 60,
        embed_layout_properties: false,
        swiyu_mode: false,
        sd_array_elements: true,
    };
    let hashers = hashmap! {
        "sha-256".to_string() => Arc::new(SHA256) as Arc<dyn Hasher>
    };
    let mut client = MockHttpClient::new();

    client.expect_get().with(eq(ISSUER_URL)).returning(|url| {
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

    let crypto = Arc::new(CryptoProviderImpl::new(hashers, HashMap::new()));

    let mut datatype_provider = MockDataTypeProvider::new();
    // Set up expectations for all claim extractions
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

    let formatter = SDJWTVCFormatter::new(
        params,
        crypto,
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(MockVctTypeMetadataFetcher::new()),
        Arc::new(MockCertificateValidator::new()),
        generic_config().core.datatype,
        Arc::new(client),
        Arc::new(datatype_provider),
    );

    let result = formatter.parse_credential(CREDENTIAL).await.unwrap();

    // Verify claims were parsed
    assert!(result.claims.is_some());
    let claims = result.claims.as_ref().unwrap();

    assert_eq!(claims.len(), 11);

    // Verify vct metadata claim
    let vct_claim = claims.iter().find(|c| c.path == "vct").unwrap();
    assert_eq!(
        vct_claim.value.as_deref(),
        Some("https://credentials.example.com/identity_credential")
    );
    assert_eq!(vct_claim.selectively_disclosable, false);
    let vct_schema = vct_claim.schema.as_ref().unwrap();
    assert_eq!(vct_schema.key, "vct");
    assert_eq!(vct_schema.data_type, "STRING");
    assert_eq!(vct_schema.array, false);
    assert_eq!(vct_schema.metadata, true);

    // Verify is_over_65 claim
    let is_over_65_claim = claims.iter().find(|c| c.path == "is_over_65").unwrap();
    assert_eq!(is_over_65_claim.value.as_deref(), Some("true"));
    assert_eq!(is_over_65_claim.selectively_disclosable, true);
    let is_over_65_schema = is_over_65_claim.schema.as_ref().unwrap();
    assert_eq!(is_over_65_schema.key, "is_over_65");
    assert_eq!(is_over_65_schema.data_type, "BOOLEAN");
    assert_eq!(is_over_65_schema.array, false);
    assert_eq!(is_over_65_schema.metadata, false);

    // Verify address object claim
    let address_claim = claims.iter().find(|c| c.path == "address").unwrap();
    assert_eq!(address_claim.value, None);
    assert_eq!(address_claim.selectively_disclosable, true);
    let address_schema = address_claim.schema.as_ref().unwrap();
    assert_eq!(address_schema.key, "address");
    assert_eq!(address_schema.data_type, "OBJECT");
    assert_eq!(address_schema.array, false);
    assert_eq!(address_schema.metadata, false);

    // Verify address nested fields
    let street_claim = claims
        .iter()
        .find(|c| c.path == "address/street_address")
        .unwrap();
    assert_eq!(street_claim.value.as_deref(), Some("123 Main St"));
    assert_eq!(street_claim.selectively_disclosable, false);
    assert_eq!(
        street_claim.schema.as_ref().unwrap().key,
        "address/street_address"
    );
    assert_eq!(street_claim.schema.as_ref().unwrap().data_type, "STRING");

    let locality_claim = claims
        .iter()
        .find(|c| c.path == "address/locality")
        .unwrap();
    assert_eq!(locality_claim.value.as_deref(), Some("Anytown"));
    assert_eq!(locality_claim.selectively_disclosable, false);
    assert_eq!(
        locality_claim.schema.as_ref().unwrap().key,
        "address/locality"
    );
    assert_eq!(locality_claim.schema.as_ref().unwrap().data_type, "STRING");

    let region_claim = claims.iter().find(|c| c.path == "address/region").unwrap();
    assert_eq!(region_claim.value.as_deref(), Some("Anystate"));
    assert_eq!(region_claim.selectively_disclosable, false);
    assert_eq!(region_claim.schema.as_ref().unwrap().key, "address/region");
    assert_eq!(region_claim.schema.as_ref().unwrap().data_type, "STRING");

    let country_claim = claims.iter().find(|c| c.path == "address/country").unwrap();
    assert_eq!(country_claim.value.as_deref(), Some("US"));
    assert_eq!(country_claim.selectively_disclosable, false);
    assert_eq!(
        country_claim.schema.as_ref().unwrap().key,
        "address/country"
    );
    assert_eq!(country_claim.schema.as_ref().unwrap().data_type, "STRING");

    // Verify claim_schemas were populated
    assert!(result.schema.is_some());
    let schema = result.schema.as_ref().unwrap();
    assert!(schema.claim_schemas.is_some());
    let claim_schemas = schema.claim_schemas.as_ref().unwrap();

    assert_eq!(claim_schemas.len(), 11);

    // Verify claim schema keys
    let schema_keys: Vec<&str> = claim_schemas
        .iter()
        .map(|cs| cs.schema.key.as_str())
        .collect();

    // Metadata schemas
    assert!(schema_keys.contains(&"vct"));
    assert!(schema_keys.contains(&"iss"));
    assert!(schema_keys.contains(&"iat"));
    assert!(schema_keys.contains(&"exp"));

    // User claim schemas
    assert!(schema_keys.contains(&"is_over_65"));
    assert!(schema_keys.contains(&"address"));
    assert!(schema_keys.contains(&"address/street_address"));
    assert!(schema_keys.contains(&"address/locality"));
    assert!(schema_keys.contains(&"address/region"));
    assert!(schema_keys.contains(&"address/country"));
}

#[tokio::test]
async fn test_format_presentation_mixed_sd_array_claim() {
    let params = Params {
        leeway: 60,
        embed_layout_properties: false,
        swiyu_mode: false,
        sd_array_elements: true,
    };
    let hashers = hashmap! {
        "sha-256".to_string() => Arc::new(SHA256) as Arc<dyn Hasher>
    };
    let crypto = Arc::new(CryptoProviderImpl::new(hashers, HashMap::new()));
    let formatter = SDJWTVCFormatter::new(
        params,
        crypto,
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(MockVctTypeMetadataFetcher::new()),
        Arc::new(MockCertificateValidator::new()),
        generic_config().core.datatype,
        Arc::new(MockHttpClient::new()),
        Arc::new(MockDataTypeProvider::new()),
    );

    let token = "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpqd2s6ZXlKcmRIa2lPaUpQUzFBaUxDSmpjbllpT2lKRlpESTFOVEU1SWl3aWVDSTZJbGhMU25sbWVtcDBSVlYyTTBocFZHNDVVVUpSWkdwS1oyUXlTMEpPTVhKMk5qRlVkRkJJZFVRNWFrRWlmUSMwIiwidHlwIjoidmMrc2Qtand0In0.eyJpYXQiOjE3NTcwNzU3MjgsImV4cCI6MTc1NzA3NTczOCwibmJmIjoxNzU3MDc1NzI4LCJpc3MiOiJkaWQ6andrOmV5SnJkSGtpT2lKUFMxQWlMQ0pqY25ZaU9pSkZaREkxTlRFNUlpd2llQ0k2SWxoTFNubG1lbXAwUlZWMk0waHBWRzQ1VVVKUlpHcEtaMlF5UzBKT01YSjJOakZVZEZCSWRVUTVha0VpZlEiLCJzdWIiOiJkaWQ6a2V5Ono2TWt2M0hMNTJYSk5oNHJkdG5QS1BSbmRHd1U4bkF1VnBFN3lGRmllNVNOeFprWCIsInZjdCI6ImNyZWRlbnRpYWwtc2NoZW1hLWlkIiwiX3NkIjpbIk9VamJWRlZ1RGhoRkRReXpJdllfd3AzQTJRVnBadjlsZ0JoRUdMYlVSTXMiLCJod1ZXdW9CeG1hcEd2RHZCdDJ1RGR6RmlfMjNIR3ZQd3hJT3lCdGNVRjZBIiwidVBCaWJWdzVOMFVqalF3cjJwSURPbTRwRlltS3MzbFVUdWQ4ZTRxajlCbyJdLCJfc2RfYWxnIjoic2hhLTI1NiJ9.4mDkXOv500AjcM-HtMLHsadP7-qb0kXlY10i6EfQzJCku4NypM_tQBlsbCQL5JJRxNqrm6BE2aetfPOmLjeABA~WyJpZWg1U1YwTjcwT2NkQkljMi00akxRIiwiYWdlIiwyMl0~WyJtY2p2TERkc1hsd2lDSDdXekd2aTVnIiwiaXNfb3Zlcl8xOCIsdHJ1ZV0~WyJSeExGd2VhQVdyeEp4XzRRVFF5VEJnIiwibWVhc3VyZW1lbnRzIixbeyJhaXIgcG9sbHV0aW9uIjoyNC42fV1d~WyJqWTFOM0R1cEJiczVuUUdRVUFCSmdRIiwibmFtZSIsIk1pa2UiXQ~WyJQWl9kRThIbXhKQ2xxVHVQUGhhOGhnIiwib2JqZWN0Iix7Il9zZCI6WyJBczVEX241c0pjaURMQlM5THNxaGlwc3doOGRzeVBrOEtiQjZERW94Q1NnIiwiWjBQaFV1V19jTnpVYnFEeC1kZFFXVV9yYzVZemxiWFlRYV9xN2FCZEpUQSJdfV0~";
    let expected_presentation = "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpqd2s6ZXlKcmRIa2lPaUpQUzFBaUxDSmpjbllpT2lKRlpESTFOVEU1SWl3aWVDSTZJbGhMU25sbWVtcDBSVlYyTTBocFZHNDVVVUpSWkdwS1oyUXlTMEpPTVhKMk5qRlVkRkJJZFVRNWFrRWlmUSMwIiwidHlwIjoidmMrc2Qtand0In0.eyJpYXQiOjE3NTcwNzU3MjgsImV4cCI6MTc1NzA3NTczOCwibmJmIjoxNzU3MDc1NzI4LCJpc3MiOiJkaWQ6andrOmV5SnJkSGtpT2lKUFMxQWlMQ0pqY25ZaU9pSkZaREkxTlRFNUlpd2llQ0k2SWxoTFNubG1lbXAwUlZWMk0waHBWRzQ1VVVKUlpHcEtaMlF5UzBKT01YSjJOakZVZEZCSWRVUTVha0VpZlEiLCJzdWIiOiJkaWQ6a2V5Ono2TWt2M0hMNTJYSk5oNHJkdG5QS1BSbmRHd1U4bkF1VnBFN3lGRmllNVNOeFprWCIsInZjdCI6ImNyZWRlbnRpYWwtc2NoZW1hLWlkIiwiX3NkIjpbIk9VamJWRlZ1RGhoRkRReXpJdllfd3AzQTJRVnBadjlsZ0JoRUdMYlVSTXMiLCJod1ZXdW9CeG1hcEd2RHZCdDJ1RGR6RmlfMjNIR3ZQd3hJT3lCdGNVRjZBIiwidVBCaWJWdzVOMFVqalF3cjJwSURPbTRwRlltS3MzbFVUdWQ4ZTRxajlCbyJdLCJfc2RfYWxnIjoic2hhLTI1NiJ9.4mDkXOv500AjcM-HtMLHsadP7-qb0kXlY10i6EfQzJCku4NypM_tQBlsbCQL5JJRxNqrm6BE2aetfPOmLjeABA~WyJQWl9kRThIbXhKQ2xxVHVQUGhhOGhnIiwib2JqZWN0Iix7Il9zZCI6WyJBczVEX241c0pjaURMQlM5THNxaGlwc3doOGRzeVBrOEtiQjZERW94Q1NnIiwiWjBQaFV1V19jTnpVYnFEeC1kZFFXVV9yYzVZemxiWFlRYV9xN2FCZEpUQSJdfV0~WyJSeExGd2VhQVdyeEp4XzRRVFF5VEJnIiwibWVhc3VyZW1lbnRzIixbeyJhaXIgcG9sbHV0aW9uIjoyNC42fV1d~";
    let credential_presentation = CredentialPresentation {
        token: token.to_string(),
        disclosed_keys: vec!["object/measurements/0/air pollution".to_string()],
    };
    let presentation = formatter
        .prepare_selective_disclosure(credential_presentation)
        .await
        .expect("failed to format presentation");
    // Order of disclosures does not matter
    assert_eq!(
        presentation.split('~').collect::<HashSet<_>>(),
        expected_presentation.split('~').collect::<HashSet<_>>()
    );
}

// Adapted from https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-22.html#name-complex-structured-sd-jwt
// with added `vct` claim to make parsing work.
const COMPLEX_TEST_VECTOR: &str = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJfc2QiOiBbIi1hU3puSWQ5bVdNOG9jdVFvbENsbHN4VmdncTEtdkhXNE90bmhVdFZtV3ciLCAiSUticllObjN2QTdXRUZyeXN2YmRCSmpERFVfRXZRSXIwVzE4dlRScFVTZyIsICJvdGt4dVQxNG5CaXd6TkozTVBhT2l0T2w5cFZuWE9hRUhhbF94a3lOZktJIl0sInZjdCI6ICJkdW1teSIsICJpc3MiOiAiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20iLCAiaWF0IjogMTY4MzAwMDAwMCwgImV4cCI6IDE4ODMwMDAwMDAsICJ2ZXJpZmllZF9jbGFpbXMiOiB7InZlcmlmaWNhdGlvbiI6IHsiX3NkIjogWyI3aDRVRTlxU2N2REtvZFhWQ3VvS2ZLQkpwVkJmWE1GX1RtQUdWYVplM1NjIiwgInZUd2UzcmFISUZZZ0ZBM3hhVUQyYU14Rno1b0RvOGlCdTA1cUtsT2c5THciXSwgInRydXN0X2ZyYW1ld29yayI6ICJkZV9hbWwiLCAiZXZpZGVuY2UiOiBbeyIuLi4iOiAidFlKMFREdWN5WlpDUk1iUk9HNHFSTzV2a1BTRlJ4RmhVRUxjMThDU2wzayJ9XX0sICJjbGFpbXMiOiB7Il9zZCI6IFsiUmlPaUNuNl93NVpIYWFka1FNcmNRSmYwSnRlNVJ3dXJSczU0MjMxRFRsbyIsICJTXzQ5OGJicEt6QjZFYW5mdHNzMHhjN2NPYW9uZVJyM3BLcjdOZFJtc01vIiwgIldOQS1VTks3Rl96aHNBYjlzeVdPNklJUTF1SGxUbU9VOHI4Q3ZKMGNJTWsiLCAiV3hoX3NWM2lSSDliZ3JUQkppLWFZSE5DTHQtdmpoWDFzZC1pZ09mXzlsayIsICJfTy13SmlIM2VuU0I0Uk9IbnRUb1FUOEptTHR6LW1oTzJmMWM4OVhvZXJRIiwgImh2RFhod21HY0pRc0JDQTJPdGp1TEFjd0FNcERzYVUwbmtvdmNLT3FXTkUiXX19LCAiX3NkX2FsZyI6ICJzaGEtMjU2In0.QoWYWtikm-AtjmPnNVshbGXQl5raEz15PByTmZwfTQg9W2O3oR6j2tMmysTZZawdo6mNLR_PsZSI25qrUpiNTg~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInRpbWUiLCAiMjAxMi0wNC0yM1QxODoyNVoiXQ~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgInZlcmlmaWNhdGlvbl9wcm9jZXNzIiwgImYyNGM2Zi02ZDNmLTRlYzUtOTczZS1iMGQ4NTA2ZjNiYzciXQ~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInR5cGUiLCAiZG9jdW1lbnQiXQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgIm1ldGhvZCIsICJwaXBwIl0~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInRpbWUiLCAiMjAxMi0wNC0yMlQxMTozMFoiXQ~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImRvY3VtZW50IiwgeyJ0eXBlIjogImlkY2FyZCIsICJpc3N1ZXIiOiB7Im5hbWUiOiAiU3RhZHQgQXVnc2J1cmciLCAiY291bnRyeSI6ICJERSJ9LCAibnVtYmVyIjogIjUzNTU0NTU0IiwgImRhdGVfb2ZfaXNzdWFuY2UiOiAiMjAxMC0wMy0yMyIsICJkYXRlX29mX2V4cGlyeSI6ICIyMDIwLTAzLTIyIn1d~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgeyJfc2QiOiBbIjl3cGpWUFd1RDdQSzBuc1FETDhCMDZsbWRnVjNMVnliaEh5ZFFwVE55TEkiLCAiRzVFbmhPQU9vVTlYXzZRTU52ekZYanBFQV9SYy1BRXRtMWJHX3djYUtJayIsICJJaHdGcldVQjYzUmNacTl5dmdaMFhQYzdHb3doM08ya3FYZUJJc3dnMUI0IiwgIldweFE0SFNvRXRjVG1DQ0tPZURzbEJfZW11Y1lMejJvTzhvSE5yMWJFVlEiXX1d~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgImdpdmVuX25hbWUiLCAiTWF4Il0~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImZhbWlseV9uYW1lIiwgIk1cdTAwZmNsbGVyIl0~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIm5hdGlvbmFsaXRpZXMiLCBbIkRFIl1d~WyI1YlBzMUlxdVpOYTBoa2FGenp6Wk53IiwgImJpcnRoZGF0ZSIsICIxOTU2LTAxLTI4Il0~WyI1YTJXMF9OcmxFWnpmcW1rXzdQcS13IiwgInBsYWNlX29mX2JpcnRoIiwgeyJjb3VudHJ5IjogIklTIiwgImxvY2FsaXR5IjogIlx1MDBkZXlra3ZhYlx1MDBlNmphcmtsYXVzdHVyIn1d~WyJ5MXNWVTV3ZGZKYWhWZGd3UGdTN1JRIiwgImFkZHJlc3MiLCB7ImxvY2FsaXR5IjogIk1heHN0YWR0IiwgInBvc3RhbF9jb2RlIjogIjEyMzQ0IiwgImNvdW50cnkiOiAiREUiLCAic3RyZWV0X2FkZHJlc3MiOiAiV2VpZGVuc3RyYVx1MDBkZmUgMjIifV0~WyJIYlE0WDhzclZXM1FEeG5JSmRxeU9BIiwgImJpcnRoX21pZGRsZV9uYW1lIiwgIlRpbW90aGV1cyJd~WyJDOUdTb3VqdmlKcXVFZ1lmb2pDYjFBIiwgInNhbHV0YXRpb24iLCAiRHIuIl0~WyJreDVrRjE3Vi14MEptd1V4OXZndnR3IiwgIm1zaXNkbiIsICI0OTEyMzQ1Njc4OSJd~";
#[tokio::test]
async fn test_format_presentation_complex_test_vector_sd_array_element() {
    // Adapted from https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-22.html#appendix-A.2-39
    // with added `vct` claim to make parsing work.
    let expected_presentation = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJfc2QiOiBbIi1hU3puSWQ5bVdNOG9jdVFvbENsbHN4VmdncTEtdkhXNE90bmhVdFZtV3ciLCAiSUticllObjN2QTdXRUZyeXN2YmRCSmpERFVfRXZRSXIwVzE4dlRScFVTZyIsICJvdGt4dVQxNG5CaXd6TkozTVBhT2l0T2w5cFZuWE9hRUhhbF94a3lOZktJIl0sInZjdCI6ICJkdW1teSIsICJpc3MiOiAiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20iLCAiaWF0IjogMTY4MzAwMDAwMCwgImV4cCI6IDE4ODMwMDAwMDAsICJ2ZXJpZmllZF9jbGFpbXMiOiB7InZlcmlmaWNhdGlvbiI6IHsiX3NkIjogWyI3aDRVRTlxU2N2REtvZFhWQ3VvS2ZLQkpwVkJmWE1GX1RtQUdWYVplM1NjIiwgInZUd2UzcmFISUZZZ0ZBM3hhVUQyYU14Rno1b0RvOGlCdTA1cUtsT2c5THciXSwgInRydXN0X2ZyYW1ld29yayI6ICJkZV9hbWwiLCAiZXZpZGVuY2UiOiBbeyIuLi4iOiAidFlKMFREdWN5WlpDUk1iUk9HNHFSTzV2a1BTRlJ4RmhVRUxjMThDU2wzayJ9XX0sICJjbGFpbXMiOiB7Il9zZCI6IFsiUmlPaUNuNl93NVpIYWFka1FNcmNRSmYwSnRlNVJ3dXJSczU0MjMxRFRsbyIsICJTXzQ5OGJicEt6QjZFYW5mdHNzMHhjN2NPYW9uZVJyM3BLcjdOZFJtc01vIiwgIldOQS1VTks3Rl96aHNBYjlzeVdPNklJUTF1SGxUbU9VOHI4Q3ZKMGNJTWsiLCAiV3hoX3NWM2lSSDliZ3JUQkppLWFZSE5DTHQtdmpoWDFzZC1pZ09mXzlsayIsICJfTy13SmlIM2VuU0I0Uk9IbnRUb1FUOEptTHR6LW1oTzJmMWM4OVhvZXJRIiwgImh2RFhod21HY0pRc0JDQTJPdGp1TEFjd0FNcERzYVUwbmtvdmNLT3FXTkUiXX19LCAiX3NkX2FsZyI6ICJzaGEtMjU2In0.QoWYWtikm-AtjmPnNVshbGXQl5raEz15PByTmZwfTQg9W2O3oR6j2tMmysTZZawdo6mNLR_PsZSI25qrUpiNTg~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInRpbWUiLCAiMjAxMi0wNC0yM1QxODoyNVoiXQ~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgeyJfc2QiOiBbIjl3cGpWUFd1RDdQSzBuc1FETDhCMDZsbWRnVjNMVnliaEh5ZFFwVE55TEkiLCAiRzVFbmhPQU9vVTlYXzZRTU52ekZYanBFQV9SYy1BRXRtMWJHX3djYUtJayIsICJJaHdGcldVQjYzUmNacTl5dmdaMFhQYzdHb3doM08ya3FYZUJJc3dnMUI0IiwgIldweFE0SFNvRXRjVG1DQ0tPZURzbEJfZW11Y1lMejJvTzhvSE5yMWJFVlEiXX1d~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgIm1ldGhvZCIsICJwaXBwIl0~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgImdpdmVuX25hbWUiLCAiTWF4Il0~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImZhbWlseV9uYW1lIiwgIk1cdTAwZmNsbGVyIl0~WyJ5MXNWVTV3ZGZKYWhWZGd3UGdTN1JRIiwgImFkZHJlc3MiLCB7ImxvY2FsaXR5IjogIk1heHN0YWR0IiwgInBvc3RhbF9jb2RlIjogIjEyMzQ0IiwgImNvdW50cnkiOiAiREUiLCAic3RyZWV0X2FkZHJlc3MiOiAiV2VpZGVuc3RyYVx1MDBkZmUgMjIifV0~";
    let params = Params {
        leeway: 60,
        embed_layout_properties: false,
        swiyu_mode: false,
        sd_array_elements: true,
    };
    let hashers = hashmap! {
        "sha-256".to_string() => Arc::new(SHA256) as Arc<dyn Hasher>
    };
    let crypto = Arc::new(CryptoProviderImpl::new(hashers, HashMap::new()));
    let formatter = SDJWTVCFormatter::new(
        params,
        crypto,
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(MockVctTypeMetadataFetcher::new()),
        Arc::new(MockCertificateValidator::new()),
        generic_config().core.datatype,
        Arc::new(MockHttpClient::new()),
        Arc::new(MockDataTypeProvider::new()),
    );

    let credential_presentation = CredentialPresentation {
        token: COMPLEX_TEST_VECTOR.to_string(),
        disclosed_keys: vec![
            "verified_claims/verification/evidence/0/method".to_string(),
            "verified_claims/verification/time".to_string(),
            "verified_claims/claims/given_name".to_string(),
            "verified_claims/claims/family_name".to_string(),
            "verified_claims/claims/address".to_string(),
        ],
    };
    let presentation = formatter
        .prepare_selective_disclosure(credential_presentation)
        .await
        .expect("failed to format presentation");
    // Order of disclosures does not matter
    assert_eq!(
        presentation.split('~').collect::<HashSet<_>>(),
        expected_presentation.split('~').collect::<HashSet<_>>()
    );
}
