use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use maplit::hashset;
use shared_types::{CredentialSchemaId, DidValue, OrganisationId};
use similar_asserts::assert_eq;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use super::model::VcClaim;
use super::{JWTFormatter, Params};
use crate::config::core_config::KeyAlgorithmType;
use crate::model::claim::Claim;
use crate::model::credential::CredentialRole;
use crate::model::credential_schema::{CredentialSchemaClaim, LayoutProperties, LayoutType};
use crate::model::did::Did;
use crate::model::identifier::Identifier;
use crate::proto::jwt::model::JWTPayload;
use crate::provider::credential_formatter::common::MockAuth;
use crate::provider::credential_formatter::model::{
    CredentialData, CredentialPresentation, CredentialSchema, CredentialSchemaMetadata,
    CredentialStatus, IdentifierDetails, Issuer, MockTokenVerifier, PublicKeySource,
    PublishedClaim,
};
use crate::provider::credential_formatter::vcdm::{
    ContextType, VcdmCredential, VcdmCredentialSubject,
};
use crate::provider::credential_formatter::{CredentialFormatter, nest_claims};
use crate::provider::data_type::model::ExtractedClaim;
use crate::provider::data_type::provider::MockDataTypeProvider;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::service::credential_schema::dto::CreateCredentialSchemaRequestDTO;
use crate::service::test_utilities::{dummy_did, dummy_identifier};

fn get_credential_data(status: CredentialStatus, core_base_url: &str) -> CredentialData {
    let issuance_date: OffsetDateTime = OffsetDateTime::now_utc();
    let valid_for = time::Duration::days(365 * 2);

    let schema_context: ContextType = format!("{core_base_url}/ssi/context/v1/{}", Uuid::new_v4())
        .parse::<Url>()
        .unwrap()
        .into();
    let schema = CredentialSchema {
        id: "CredentialSchemaId".to_owned(),
        r#type: "TestType".to_owned(),
        metadata: Some(CredentialSchemaMetadata {
            layout_properties: LayoutProperties {
                background: None,
                logo: None,
                primary_attribute: Some("name".into()),
                secondary_attribute: None,
                picture_attribute: None,
                code: None,
            },
            layout_type: LayoutType::Card,
        }),
    };

    let holder_did: DidValue = "did:example:123".parse().unwrap();
    let claims = vec![
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
    ];

    let credential_subject = VcdmCredentialSubject::new(nest_claims(claims.clone()).unwrap())
        .unwrap()
        .with_id(holder_did.clone().into_url());

    let vcdm = VcdmCredential::new_v2(
        Issuer::Url("did:issuer:test".parse().unwrap()),
        credential_subject,
    )
    .add_context(schema_context)
    .with_valid_from(issuance_date)
    .with_valid_until(issuance_date + valid_for)
    .add_credential_schema(schema)
    .add_credential_status(status);

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
        holder_key_id: None,
        issuer_certificate: None,
    }
}

fn get_credential_data_with_array(status: CredentialStatus, core_base_url: &str) -> CredentialData {
    let schema_context: ContextType = format!("{core_base_url}/ssi/context/v1/CredentialSchemaId")
        .parse::<Url>()
        .unwrap()
        .into();

    let schema = CredentialSchema {
        id: "CredentialSchemaId".to_owned(),
        r#type: "TestType".to_owned(),
        metadata: None,
    };

    let issuance_date = OffsetDateTime::now_utc();
    let valid_for = time::Duration::days(365 * 2);

    let holder_did: DidValue = "did:example:123".parse().unwrap();
    let claims = vec![
        PublishedClaim {
            key: "root_item".into(),
            value: "root_item".into(),
            datatype: Some("STRING".to_owned()),
            array_item: false,
        },
        PublishedClaim {
            key: "root/nested".into(),
            value: "nested_item".into(),
            datatype: Some("STRING".to_owned()),
            array_item: false,
        },
        PublishedClaim {
            key: "root/array/0".into(),
            value: "array_item".into(),
            datatype: Some("STRING".to_owned()),
            array_item: false,
        },
    ];

    let credential_subject = VcdmCredentialSubject::new(nest_claims(claims.clone()).unwrap())
        .unwrap()
        .with_id(holder_did.clone().into_url());

    let vcdm = VcdmCredential::new_v2(
        Issuer::Url("did:issuer:test".parse().unwrap()),
        credential_subject,
    )
    .add_context(schema_context)
    .with_valid_from(issuance_date)
    .with_valid_until(issuance_date + valid_for)
    .add_credential_schema(schema)
    .add_credential_status(status);

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
        holder_key_id: None,
        issuer_certificate: None,
    }
}

#[tokio::test]
async fn test_format_credential() {
    let leeway = 45u64;

    let formatter = JWTFormatter {
        params: Params {
            leeway,
            embed_layout_properties: false,
        },
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
        data_type_provider: Arc::new(MockDataTypeProvider::new()),
    };

    let mut credential_data = get_credential_data(
        CredentialStatus {
            id: Some("did:status:id".parse().unwrap()),
            r#type: "TYPE".to_string(),
            status_purpose: Some("PURPOSE".to_string()),
            additional_fields: HashMap::from([("Field1".to_owned(), "Val1".into())]),
        },
        "http://base_url",
    );

    let context: ContextType = "http://context.com".parse::<Url>().unwrap().into();
    credential_data.vcdm = credential_data.vcdm.add_context(context).add_type("Type1");

    let auth_fn = MockAuth(|_| vec![65u8, 66, 67]);

    let result = formatter
        .format_credential(credential_data, Box::new(auth_fn))
        .await;

    assert!(result.is_ok());

    let token = result.unwrap();

    let jwt_parts: Vec<&str> = token.splitn(3, '.').collect();

    assert_eq!(
        jwt_parts[0],
        &Base64UrlSafeNoPadding::encode_to_string(r##"{"alg":"ES256","kid":"#key0","typ":"JWT"}"##)
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
    assert_eq!(payload.invalid_before, payload.issued_at,);

    assert_eq!(payload.issuer, Some(String::from("did:issuer:test")));
    assert_eq!(payload.subject, Some(String::from("did:example:123")));

    let vc = payload.custom.vc;

    assert!(vc.credential_schema.unwrap()[0].metadata.is_none());

    assert!(
        vc.credential_subject
            .iter()
            .flat_map(|v| v.claims.iter())
            .all(|claim| ["name", "age"].contains(&claim.0.as_str()))
    );

    assert!(
        vc.context
            .contains(&ContextType::Url("http://context.com".parse().unwrap()))
    );
    assert!(vc.r#type.contains(&String::from("Type1")));

    assert_eq!(1, vc.credential_status.len());
    let credential_status = vc.credential_status.first().unwrap();
    assert_eq!(
        &credential_status.id,
        &Some("did:status:id".parse().unwrap())
    );
    assert_eq!(&credential_status.r#type, "TYPE");
    assert_eq!(credential_status.status_purpose.as_deref(), Some("PURPOSE"));

    let field1 = credential_status.additional_fields.get("Field1").unwrap();
    assert_eq!(field1, "Val1");
}

#[tokio::test]
async fn test_format_credential_with_layout_properties() {
    let leeway = 45u64;

    let formatter = JWTFormatter {
        params: Params {
            leeway,
            embed_layout_properties: true,
        },
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
        data_type_provider: Arc::new(MockDataTypeProvider::new()),
    };

    let mut credential_data = get_credential_data(
        CredentialStatus {
            id: Some("did:status:id".parse().unwrap()),
            r#type: "TYPE".to_string(),
            status_purpose: Some("PURPOSE".to_string()),
            additional_fields: HashMap::from([("Field1".to_owned(), "Val1".into())]),
        },
        "http://base_url",
    );

    let context: ContextType = "https://custom-context.org".parse::<Url>().unwrap().into();
    credential_data.vcdm = credential_data.vcdm.add_context(context).add_type("Type1");

    let auth_fn = MockAuth(|_| vec![65u8, 66, 67]);

    let result = formatter
        .format_credential(credential_data, Box::new(auth_fn))
        .await;

    assert!(result.is_ok());

    let token = result.unwrap();

    let jwt_parts: Vec<&str> = token.splitn(3, '.').collect();

    assert_eq!(
        jwt_parts[0],
        &Base64UrlSafeNoPadding::encode_to_string(r##"{"alg":"ES256","kid":"#key0","typ":"JWT"}"##)
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
    assert_eq!(payload.invalid_before, payload.issued_at,);

    assert_eq!(payload.issuer, Some(String::from("did:issuer:test")));
    assert_eq!(payload.subject, Some(String::from("did:example:123")));

    let vc = payload.custom.vc;

    assert!(vc.credential_schema.unwrap()[0].metadata.is_some());

    assert!(
        vc.credential_subject
            .iter()
            .flat_map(|v| v.claims.iter())
            .all(|claim| ["name", "age"].contains(&claim.0.as_str()))
    );

    assert!(vc.context.contains(&ContextType::Url(
        "https://custom-context.org".parse().unwrap()
    )));
    assert!(vc.r#type.contains(&String::from("Type1")));

    assert_eq!(1, vc.credential_status.len());
    let credential_status = vc.credential_status.first().unwrap();
    assert_eq!(
        &credential_status.id,
        &Some("did:status:id".parse().unwrap())
    );
    assert_eq!(&credential_status.r#type, "TYPE");
    assert_eq!(credential_status.status_purpose.as_deref(), Some("PURPOSE"));

    let field1 = credential_status.additional_fields.get("Field1").unwrap();
    assert_eq!(field1, "Val1");
}

#[tokio::test]
async fn test_format_credential_nested_array() {
    let leeway = 45u64;

    let sd_formatter = JWTFormatter {
        params: Params {
            leeway,
            embed_layout_properties: false,
        },
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
        data_type_provider: Arc::new(MockDataTypeProvider::new()),
    };

    let credential_data = get_credential_data_with_array(
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

    let jwt_parts: Vec<&str> = token.splitn(3, '.').collect();

    assert_eq!(
        jwt_parts[0],
        &Base64UrlSafeNoPadding::encode_to_string(r##"{"alg":"ES256","kid":"#key0","typ":"JWT"}"##)
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
    assert_eq!(payload.invalid_before, payload.issued_at,);

    let vc = payload.custom.vc;

    let root_item = vc.credential_subject[0].claims.get("root_item").unwrap();
    assert_eq!(root_item.value.as_str(), Some("root_item"));

    let root = vc.credential_subject[0].claims.get("root").unwrap();
    let nested = root.value.as_object().unwrap().get("nested").unwrap();
    assert_eq!(nested.value.as_str(), Some("nested_item"));

    let array = root
        .value
        .as_object()
        .unwrap()
        .get("array")
        .unwrap()
        .value
        .as_array()
        .unwrap();
    assert_eq!(array[0].value.as_str(), Some("array_item"));
}

#[tokio::test]
async fn test_extract_credentials() {
    let jwt_token = "ewogICJhbGciOiAiYWxnb3JpdGhtIiwKICAidHlwIjogIkpXVCIKfQ.ewogICJpYXQiOiAxNjk5MzU0MjI4LAogICJleHAiOiAxNzYyNDI2MjI4LAogICJuYmYiOiAxNjk5MzU0MTgzLAogICJpc3MiOiAiZGlkOmlzc3Vlcjp0ZXN0IiwKICAic3ViIjogImRpZDpob2xkZXI6dGVzdCIsCiAgImp0aSI6ICI5YTQxNGE2MC05ZTZiLTQ3NTctODAxMS05YWE4NzBlZjQ3ODgiLAogICJ2YyI6IHsKICAgICJAY29udGV4dCI6IFsKICAgICAgImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwKICAgICAgImh0dHBzOi8vdGVzdGNvbnRleHQuY29tL3YxIgogICAgXSwKICAgICJ0eXBlIjogWwogICAgICAiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLAogICAgICAiVHlwZTEiCiAgICBdLAogICAgImNyZWRlbnRpYWxTdWJqZWN0IjogewogICAgICAiYWdlIjogIjQyIiwKICAgICAgIm5hbWUiOiAiSm9obiIKICAgIH0sCiAgICAiY3JlZGVudGlhbFN0YXR1cyI6IHsKICAgICAgImlkIjogImh0dHBzOi8vcHJvY2l2aXMuY2gvc3RhdHVzL2lkIiwKICAgICAgInR5cGUiOiAiVFlQRSIsCiAgICAgICJzdGF0dXNQdXJwb3NlIjogIlBVUlBPU0UiLAogICAgICAiRmllbGQxIjogIlZhbDEiCiAgICB9CiAgfQp9";

    let token = format!("{jwt_token}.QUJD");

    let leeway = 45u64;

    let jwt_formatter = JWTFormatter {
        params: Params {
            leeway,
            embed_layout_properties: false,
        },
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
        data_type_provider: Arc::new(MockDataTypeProvider::new()),
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

    let result = jwt_formatter
        .extract_credentials(&token, None, Box::new(verify_mock), None)
        .await;

    let credentials = result.unwrap();

    assert_eq!(
        credentials.issuer,
        IdentifierDetails::Did("did:issuer:test".parse().unwrap()),
    );
    assert_eq!(
        credentials.subject,
        Some(IdentifierDetails::Did("did:holder:test".parse().unwrap()))
    );
    assert_eq!(
        credentials.issuance_date,
        Some(OffsetDateTime::from_unix_timestamp(1699354228).unwrap())
    );

    assert_eq!(1, credentials.status.len());

    let first_credential_status = credentials.status.first().unwrap();
    assert_eq!(
        first_credential_status.id,
        Some("https://procivis.ch/status/id".parse().unwrap())
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
}

#[tokio::test]
async fn test_extract_credentials_nested_array() {
    let jwt_token = "ewogICJhbGciOiAiYWxnb3JpdGhtIiwKICAia2lkIjogIiNrZXkwIiwKICAidHlwIjogIkpXVCIKfQ.ewogICJpYXQiOiAxNzE4MjU5ODU2LAogICJleHAiOiAxNzgxMzMxODU2LAogICJuYmYiOiAxNzE4MjU5ODExLAogICJpc3MiOiAiZGlkOmlzc3Vlcjp0ZXN0IiwKICAic3ViIjogImRpZDpob2xkZXI6dGVzdCIsCiAgImp0aSI6ICJodHRwOi8vYmFzZV91cmwvc3NpL2NyZWRlbnRpYWwvdjEvOWE0MTRhNjAtOWU2Yi00NzU3LTgwMTEtOWFhODcwZWY0Nzg4IiwKICAidmMiOiB7CiAgICAiQGNvbnRleHQiOiBbCiAgICAgICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsCiAgICAgICJodHRwczovL3R5cGUxY29udGV4dC5vcmciCiAgICBdLAogICAgInR5cGUiOiBbCiAgICAgICJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsCiAgICAgICJUeXBlMSIKICAgIF0sCiAgICAiaWQiOiAiaHR0cDovL2Jhc2VfdXJsL3NzaS9jcmVkZW50aWFsL3YxLzlhNDE0YTYwLTllNmItNDc1Ny04MDExLTlhYTg3MGVmNDc4OCIsCiAgICAiY3JlZGVudGlhbFN1YmplY3QiOiB7CiAgICAgICJyb290IjogewogICAgICAgICJhcnJheSI6IFsKICAgICAgICAgICJhcnJheV9pdGVtIgogICAgICAgIF0sCiAgICAgICAgIm5lc3RlZCI6ICJuZXN0ZWRfaXRlbSIKICAgICAgfSwKICAgICAgInJvb3RfaXRlbSI6ICJyb290X2l0ZW0iCiAgICB9LAogICAgImNyZWRlbnRpYWxTdGF0dXMiOiB7CiAgICAgICJpZCI6ICJodHRwczovL3Byb2NpdmlzLmNoL3N0YXR1cy9pZCIsCiAgICAgICJ0eXBlIjogIlRZUEUiLAogICAgICAic3RhdHVzUHVycG9zZSI6ICJQVVJQT1NFIiwKICAgICAgIkZpZWxkMSI6ICJWYWwxIgogICAgfSwKICAgICJjcmVkZW50aWFsU2NoZW1hIjogewogICAgICAiaWQiOiAiaHR0cHM6Ly9wcm9jaXZpcy5jaC9jcmVkZW50aWFsLXNjaGVtYS9pZCIsCiAgICAgICJ0eXBlIjogIlByb2NpdmlzT25lU2NoZW1hMjAyNCIKICAgIH0KICB9Cn0";

    let token = format!("{jwt_token}.QUJD");

    let leeway = 45u64;

    let jwt_formatter = JWTFormatter {
        params: Params {
            leeway,
            embed_layout_properties: false,
        },
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
        data_type_provider: Arc::new(MockDataTypeProvider::new()),
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
        .return_once(|_, _, _, _| Ok(()));

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

    let result = jwt_formatter
        .extract_credentials(&token, None, Box::new(verify_mock), None)
        .await;

    let credentials = result.unwrap();

    assert_eq!(
        credentials.issuer,
        IdentifierDetails::Did("did:issuer:test".parse().unwrap()),
    );
    assert_eq!(
        credentials.subject,
        Some(IdentifierDetails::Did("did:holder:test".parse().unwrap())),
    );

    assert_eq!(1, credentials.status.len());

    let first_credential_status = credentials.status.first().unwrap();
    assert_eq!(
        first_credential_status.id,
        Some("https://procivis.ch/status/id".parse().unwrap())
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

    let root_item = credentials.claims.claims.get("root_item").unwrap();
    assert_eq!(root_item.value.as_str(), Some("root_item"));

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
async fn test_format_credential_presentation() {
    let jwt_token = "eyJhbGciOiJhbGdvcml0aG0iLCJ0eXAiOiJTREpXVCJ9.\
        eyJpYXQiOjE2OTkyNzAyNjYsImV4cCI6MTc2MjM0MjI2NiwibmJmIjoxNjk5Mjcw\
        MjIxLCJpc3MiOiJJc3N1ZXIgRElEIiwic3ViIjoiaG9sZGVyX2RpZCIsImp0aSI6\
        IjlhNDE0YTYwLTllNmItNDc1Ny04MDExLTlhYTg3MGVmNDc4OCIsInZjIjp7IkBj\
        b250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3Yx\
        IiwiQ29udGV4dDEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlR5\
        cGUxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Il9zZCI6WyJZV0pqTVRJeiIsIllX\
        SmpNVEl6Il19LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiU1RBVFVTX0lEIiwi\
        dHlwZSI6IlRZUEUiLCJzdGF0dXNQdXJwb3NlIjoiUFVSUE9TRSIsIkZpZWxkMSI6\
        IlZhbDEifX0sIl9zZF9hbGciOiJzaGEtMjU2In0.QUJD";

    let jwt_formatter = JWTFormatter {
        params: Params {
            leeway: 45,
            embed_layout_properties: false,
        },
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
        data_type_provider: Arc::new(MockDataTypeProvider::new()),
    };

    // Both
    let credential_presentation = CredentialPresentation {
        token: jwt_token.to_owned(),
        disclosed_keys: vec!["name".to_string(), "age".to_string()],
    };

    let result = jwt_formatter
        .format_credential_presentation(credential_presentation, None, None)
        .await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), jwt_token);

    // Just name
    let credential_presentation = CredentialPresentation {
        token: jwt_token.to_owned(),
        disclosed_keys: vec!["name".to_string()],
    };

    let result = jwt_formatter
        .format_credential_presentation(credential_presentation, None, None)
        .await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), jwt_token);
}

#[test]
fn test_get_capabilities() {
    let jwt_formatter = JWTFormatter {
        params: Params {
            leeway: 123u64,
            embed_layout_properties: false,
        },
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
        data_type_provider: Arc::new(MockDataTypeProvider::new()),
    };

    assert_eq!(2, jwt_formatter.get_capabilities().features.len());
}

#[test]
fn test_schema_id() {
    let formatter = JWTFormatter {
        params: Params {
            leeway: 123u64,
            embed_layout_properties: false,
        },
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
        data_type_provider: Arc::new(MockDataTypeProvider::new()),
    };
    let request_dto = CreateCredentialSchemaRequestDTO {
        name: "".to_string(),
        format: "".to_string(),
        revocation_method: "".to_string(),
        organisation_id: OrganisationId::from(Uuid::new_v4()),
        external_schema: false,
        claims: vec![],
        key_storage_security: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: None,
        allow_suspension: None,
        requires_app_attestation: false,
    };

    let id = CredentialSchemaId::from(Uuid::new_v4());
    let result = formatter.credential_schema_id(id, &request_dto, "https://example.com");
    assert!(result.is_ok());
    assert_eq!(
        result.unwrap(),
        format!("https://example.com/ssi/schema/v1/{id}")
    )
}

#[tokio::test]
async fn test_parse_credential() {
    const TOKEN: &str = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDp3ZWI6Y29yZS5kZXYucHJvY2l2aXMtb25lLmNvbTpzc2k6ZGlkLXdlYjp2MTpmNjI4MzMwNS02NjdhLTQ3NGItYTdlMy0wMmM0YmE5OTg3OTYja2V5LWYwYjQ2YWI5LTcxZGItNDJmNi04YWI2LWYwOWVlMDFiMGJlNyIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3NjA2NzIyMDksImV4cCI6MTgyMzc0NDIwOSwibmJmIjoxNzYwNjcyMjA5LCJpc3MiOiJkaWQ6d2ViOmNvcmUuZGV2LnByb2NpdmlzLW9uZS5jb206c3NpOmRpZC13ZWI6djE6ZjYyODMzMDUtNjY3YS00NzRiLWE3ZTMtMDJjNGJhOTk4Nzk2Iiwic3ViIjoiZGlkOmtleTp6RG5hZW9rVzd4SllXRkxOazV5QThXOUxWVnE3RWUydFlUUXdNSzJkSnlDNGUzckNyIiwidmMiOnsiaXNzdWVyIjoiZGlkOndlYjpjb3JlLmRldi5wcm9jaXZpcy1vbmUuY29tOnNzaTpkaWQtd2ViOnYxOmY2MjgzMzA1LTY2N2EtNDc0Yi1hN2UzLTAyYzRiYTk5ODc5NiIsInZhbGlkRnJvbSI6IjIwMjUtMTAtMTdUMDM6MzY6NDkuMzk5ODIyNjg4WiIsInZhbGlkVW50aWwiOiIyMDI3LTEwLTE3VDAzOjM2OjQ5LjM5OTgyMjY4OFoiLCJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL2NvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20vc3NpL2NvbnRleHQvdjEvYjc5YjdiNWItMjBmOS00MzRiLWIyNDctYjBkMTljYzE1MWRhIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCI3NTQzTmVzdGVkIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImFyciI6WyIxIiwiMiJdLCJvYmoiOnsibmVzdGVkU3RyIjoibiJ9LCJzdHIiOiJzIn0sImNyZWRlbnRpYWxTdGF0dXMiOlt7ImlkIjoidXJuOnV1aWQ6MTZlYmI3MmItOWFkYi00MzNiLWFiYjQtYjllZjdhYjk0NzQyIiwidHlwZSI6IkJpdHN0cmluZ1N0YXR1c0xpc3RFbnRyeSIsInN0YXR1c1B1cnBvc2UiOiJyZXZvY2F0aW9uIiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwczovL2NvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20vc3NpL3Jldm9jYXRpb24vdjEvbGlzdC8zMjdmZjU3YS1iYWRkLTRlMDYtYTRmZC0yNTdhNGU1MGZkYzkiLCJzdGF0dXNMaXN0SW5kZXgiOiI0MCJ9LHsiaWQiOiJ1cm46dXVpZDo0MzZjZWRjZC1jYTA2LTQ2NzMtYWU0ZS1hN2UzNTY5ZTgyYWMiLCJ0eXBlIjoiQml0c3RyaW5nU3RhdHVzTGlzdEVudHJ5Iiwic3RhdHVzUHVycG9zZSI6InN1c3BlbnNpb24iLCJzdGF0dXNMaXN0Q3JlZGVudGlhbCI6Imh0dHBzOi8vY29yZS5kZXYucHJvY2l2aXMtb25lLmNvbS9zc2kvcmV2b2NhdGlvbi92MS9saXN0LzJkYjEwY2E2LTIzZGUtNDU4MC04Nzk3LWY0M2ZiNWEwOGY5MiIsInN0YXR1c0xpc3RJbmRleCI6IjQwIn1dLCJjcmVkZW50aWFsU2NoZW1hIjp7ImlkIjoiaHR0cHM6Ly9jb3JlLmRldi5wcm9jaXZpcy1vbmUuY29tL3NzaS9zY2hlbWEvdjEvYjc5YjdiNWItMjBmOS00MzRiLWIyNDctYjBkMTljYzE1MWRhIiwidHlwZSI6IlByb2NpdmlzT25lU2NoZW1hMjAyNCJ9fX0.5_w7xY87jAZJ2N9zhr5xcisb5H-SslFBkll4U_ogLt3kZXHYR4v8131JMbeCKpbQgBupguhospBvHHxp_qrVHQ";

    let mut datatype_provider = MockDataTypeProvider::new();
    datatype_provider
        .expect_extract_json_claim()
        .returning(|_| {
            Ok(ExtractedClaim {
                data_type: "STRING".to_string(),
                value: "value".to_string(),
            })
        });

    let jwt_formatter = JWTFormatter {
        params: Params {
            leeway: 45,
            embed_layout_properties: false,
        },
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
        data_type_provider: Arc::new(datatype_provider),
    };

    let credential = jwt_formatter.parse_credential(TOKEN).await.unwrap();

    assert_eq!(credential.role, CredentialRole::Holder);
    assert_eq!(
        credential.issuance_date.unwrap(),
        datetime!(2025-10-17 03:36:49 UTC)
    );

    let issuer = credential.issuer_identifier.as_ref().unwrap();
    assert_eq!(
        issuer.did.as_ref().unwrap().did.to_string(),
        "did:web:core.dev.procivis-one.com:ssi:did-web:v1:f6283305-667a-474b-a7e3-02c4ba998796"
    );

    let holder = credential.holder_identifier.as_ref().unwrap();
    assert_eq!(
        holder.did.as_ref().unwrap().did.to_string(),
        "did:key:zDnaeokW7xJYWFLNk5yA8W9LVVq7Ee2tYTQwMK2dJyC4e3rCr"
    );

    let schema = credential.schema.as_ref().unwrap();
    assert_eq!(schema.format, "JWT");
    assert_eq!(schema.revocation_method, "BITSTRINGSTATUSLIST");
    assert_eq!(schema.name, "7543Nested");
    assert_eq!(
        schema.schema_id,
        "https://core.dev.procivis-one.com/ssi/schema/v1/b79b7b5b-20f9-434b-b247-b0d19cc151da"
    );

    let claims = credential.claims.as_ref().unwrap();
    assert_eq!(claims.len(), 15);

    let get_claim_paths = |filter: &dyn Fn(&Claim) -> bool| {
        HashSet::from_iter(
            claims
                .iter()
                .filter(|claim| filter(claim))
                .map(|claim| claim.path.as_str()),
        )
    };

    // intermediary
    assert_eq!(
        get_claim_paths(&|claim| claim.value.is_none() && !claim.schema.as_ref().unwrap().metadata),
        hashset! { "arr", "obj" }
    );
    // leaf
    assert_eq!(
        get_claim_paths(&|claim| claim.value == Some("value".to_string())
            && !claim.schema.as_ref().unwrap().metadata),
        hashset! { "str", "obj/nestedStr", "arr/0", "arr/1" }
    );
    // metadata
    assert_eq!(
        get_claim_paths(&|claim| claim.schema.as_ref().unwrap().metadata),
        hashset! { "iat", "nbf", "iss", "sub", "exp", "vc", "vc/type", "vc/type/0", "vc/type/1" }
    );

    let claim_schemas = schema.claim_schemas.as_ref().unwrap();
    assert_eq!(claim_schemas.len(), 11);

    let get_claim_schema_keys = |filter: &dyn Fn(&CredentialSchemaClaim) -> bool| {
        HashSet::from_iter(
            claim_schemas
                .iter()
                .filter(|schema| filter(schema))
                .map(|schema| schema.schema.key.as_str()),
        )
    };

    assert_eq!(
        get_claim_schema_keys(&|schema| !schema.schema.metadata),
        hashset! { "str", "arr", "obj", "obj/nestedStr" }
    );

    assert_eq!(
        get_claim_schema_keys(&|schema| schema.schema.metadata),
        hashset! { "exp", "iss", "iat", "sub", "nbf", "vc", "vc/type" }
    );
}
