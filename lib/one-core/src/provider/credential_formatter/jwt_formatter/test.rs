use std::collections::HashMap;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use shared_types::{CredentialSchemaId, DidValue, OrganisationId};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::JWTFormatter;
use crate::model::credential_schema::{LayoutProperties, LayoutType};
use crate::provider::credential_formatter::common::MockAuth;
use crate::provider::credential_formatter::json_ld::model::ContextType;
use crate::provider::credential_formatter::jwt::model::JWTPayload;
use crate::provider::credential_formatter::jwt_formatter::model::{VerifiableCredential, VC, VP};
use crate::provider::credential_formatter::jwt_formatter::Params;
use crate::provider::credential_formatter::model::{
    CredentialData, CredentialPresentation, CredentialSchemaData, CredentialSchemaMetadata,
    CredentialStatus, ExtractPresentationCtx, Issuer, MockTokenVerifier, PublishedClaim,
};
use crate::provider::credential_formatter::CredentialFormatter;
use crate::service::credential_schema::dto::CreateCredentialSchemaRequestDTO;

fn get_credential_data(status: Vec<CredentialStatus>, core_base_url: &str) -> CredentialData {
    let id = Some(Uuid::new_v4().urn().to_string());
    let issuance_date = OffsetDateTime::now_utc();
    let valid_for = time::Duration::days(365 * 2);
    let schema = CredentialSchemaData {
        id: Some("CredentialSchemaId".to_owned()),
        r#type: Some("TestType".to_owned()),
        context: Some(format!("{core_base_url}/ssi/context/v1/{}", Uuid::new_v4())),
        name: "".to_owned(),
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

#[tokio::test]
async fn test_format_credential() {
    let leeway = 45u64;

    let formatter = JWTFormatter {
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

    let result = formatter
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

    let payload: JWTPayload<VC> = serde_json::from_str(
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

    assert!(vc.credential_schema.unwrap().metadata.is_none());

    assert!(vc
        .credential_subject
        .values
        .iter()
        .all(|claim| ["name", "age"].contains(&claim.0.as_str())));

    assert!(vc
        .context
        .contains(&ContextType::Url("http://context.com".parse().unwrap())));
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

    let result = formatter
        .format_credentials(
            credential_data,
            &Some(DidValue::from("holder_did".to_string())),
            vec![ContextType::Url(
                "https://custom-context.org".parse().unwrap(),
            )],
            vec!["Type1".to_string()],
            Box::new(auth_fn),
        )
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

    let payload: JWTPayload<VC> = serde_json::from_str(
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

    assert!(vc.credential_schema.unwrap().metadata.is_some());

    assert!(vc
        .credential_subject
        .values
        .iter()
        .all(|claim| ["name", "age"].contains(&claim.0.as_str())));

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

    let payload: JWTPayload<VC> = serde_json::from_str(
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

    let vc = payload.custom.vc;

    let root_item = vc.credential_subject.values.get("root_item").unwrap();
    assert_eq!(root_item.as_str(), Some("root_item"));

    let root = vc.credential_subject.values.get("root").unwrap();
    let nested = root.get("nested").unwrap();
    assert_eq!(nested.as_str(), Some("nested_item"));

    let array = root.get("array").unwrap().as_array().unwrap();
    assert_eq!(array[0].as_str(), Some("array_item"));
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

    let result = jwt_formatter
        .extract_credentials(&token, Box::new(verify_mock))
        .await;

    let credentials = result.unwrap();

    assert_eq!(
        credentials.issuer_did,
        Some(DidValue::from("did:issuer:test".to_owned())),
    );
    assert_eq!(
        credentials.subject,
        Some(DidValue::from("did:holder:test".to_owned()))
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

    assert_eq!(credentials.claims.values.get("name").unwrap(), "John");
    assert_eq!(credentials.claims.values.get("age").unwrap(), "42");
}

#[tokio::test]
async fn test_extract_credentials_nested_array() {
    let jwt_token = "ewogICJhbGciOiAiYWxnb3JpdGhtIiwKICAia2lkIjogIiNrZXkwIiwKICAidHlwIjogIkpXVCIKfQ.ewogICJpYXQiOiAxNzE4MjU5ODU2LAogICJleHAiOiAxNzgxMzMxODU2LAogICJuYmYiOiAxNzE4MjU5ODExLAogICJpc3MiOiAiZGlkOmlzc3Vlcjp0ZXN0IiwKICAic3ViIjogImhvbGRlcl9kaWQiLAogICJqdGkiOiAiaHR0cDovL2Jhc2VfdXJsL3NzaS9jcmVkZW50aWFsL3YxLzlhNDE0YTYwLTllNmItNDc1Ny04MDExLTlhYTg3MGVmNDc4OCIsCiAgInZjIjogewogICAgIkBjb250ZXh0IjogWwogICAgICAiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLAogICAgICAiaHR0cHM6Ly90eXBlMWNvbnRleHQub3JnIgogICAgXSwKICAgICJ0eXBlIjogWwogICAgICAiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLAogICAgICAiVHlwZTEiCiAgICBdLAogICAgImlkIjogImh0dHA6Ly9iYXNlX3VybC9zc2kvY3JlZGVudGlhbC92MS85YTQxNGE2MC05ZTZiLTQ3NTctODAxMS05YWE4NzBlZjQ3ODgiLAogICAgImNyZWRlbnRpYWxTdWJqZWN0IjogewogICAgICAicm9vdCI6IHsKICAgICAgICAiYXJyYXkiOiBbCiAgICAgICAgICAiYXJyYXlfaXRlbSIKICAgICAgICBdLAogICAgICAgICJuZXN0ZWQiOiAibmVzdGVkX2l0ZW0iCiAgICAgIH0sCiAgICAgICJyb290X2l0ZW0iOiAicm9vdF9pdGVtIgogICAgfSwKICAgICJjcmVkZW50aWFsU3RhdHVzIjogewogICAgICAiaWQiOiAiaHR0cHM6Ly9wcm9jaXZpcy5jaC9zdGF0dXMvaWQiLAogICAgICAidHlwZSI6ICJUWVBFIiwKICAgICAgInN0YXR1c1B1cnBvc2UiOiAiUFVSUE9TRSIsCiAgICAgICJGaWVsZDEiOiAiVmFsMSIKICAgIH0sCiAgICAiY3JlZGVudGlhbFNjaGVtYSI6IHsKICAgICAgImlkIjogImh0dHBzOi8vcHJvY2l2aXMuY2gvY3JlZGVudGlhbC1zY2hlbWEvaWQiLAogICAgICAidHlwZSI6ICJQcm9jaXZpc09uZVNjaGVtYTIwMjQiCiAgICB9CiAgfQp9";

    let token = format!("{jwt_token}.QUJD");

    let leeway = 45u64;

    let jwt_formatter = JWTFormatter {
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

    let result = jwt_formatter
        .extract_credentials(&token, Box::new(verify_mock))
        .await;

    let credentials = result.unwrap();

    assert_eq!(
        credentials.issuer_did,
        Some(DidValue::from("did:issuer:test".to_owned())),
    );
    assert_eq!(
        credentials.subject,
        Some(DidValue::from("holder_did".to_owned()))
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

    let root_item = credentials.claims.values.get("root_item").unwrap();
    assert_eq!(root_item.as_str(), Some("root_item"));

    let root = credentials.claims.values.get("root").unwrap();
    let nested = root.get("nested").unwrap();
    assert_eq!(nested.as_str(), Some("nested_item"));

    let array = root.get("array").unwrap().as_array().unwrap();
    assert_eq!(array[0].as_str(), Some("array_item"));
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
    };

    // Both
    let credential_presentation = CredentialPresentation {
        token: jwt_token.to_owned(),
        disclosed_keys: vec!["name".to_string(), "age".to_string()],
    };

    let result = jwt_formatter
        .format_credential_presentation(credential_presentation)
        .await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), jwt_token);

    // Just name
    let credential_presentation = CredentialPresentation {
        token: jwt_token.to_owned(),
        disclosed_keys: vec!["name".to_string()],
    };

    let result = jwt_formatter
        .format_credential_presentation(credential_presentation)
        .await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), jwt_token);
}

#[tokio::test]
async fn test_format_presentation() {
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

    let leeway = 45u64;

    let jwt_formatter = JWTFormatter {
        params: Params {
            leeway,
            embed_layout_properties: false,
        },
    };

    let auth_fn = MockAuth(|_| vec![65u8, 66, 67]);

    let result = jwt_formatter
        .format_presentation(
            &[jwt_token.to_owned()],
            &DidValue::from("holder_did".to_string()),
            "ES256",
            Box::new(auth_fn),
            Default::default(),
        )
        .await;

    assert!(result.is_ok());

    let presentation_token = result.unwrap();

    let jwt_parts: Vec<&str> = presentation_token.splitn(3, '.').collect();

    assert_eq!(
        jwt_parts[0],
        &Base64UrlSafeNoPadding::encode_to_string(r##"{"alg":"ES256","kid":"#key0","typ":"JWT"}"##)
            .unwrap()
    );
    assert_eq!(
        jwt_parts[2],
        &Base64UrlSafeNoPadding::encode_to_string(r#"ABC"#).unwrap()
    );

    let payload: JWTPayload<VP> = serde_json::from_str(
        &String::from_utf8(Base64UrlSafeNoPadding::decode_to_vec(jwt_parts[1], None).unwrap())
            .unwrap(),
    )
    .unwrap();

    assert_eq!(
        payload.expires_at,
        Some(payload.issued_at.unwrap() + Duration::minutes(5)),
    );
    assert_eq!(
        payload.invalid_before,
        Some(payload.issued_at.unwrap() - Duration::seconds(leeway as i64)),
    );

    assert_eq!(payload.issuer, Some(String::from("holder_did")));
    assert_eq!(payload.subject, Some(String::from("holder_did")));

    let vp = payload.custom.vp;

    assert_eq!(vp.verifiable_credential.len(), 1);
    assert_eq!(
        vp.verifiable_credential[0],
        VerifiableCredential::Token(jwt_token.to_string())
    );
}

#[tokio::test]
async fn test_extract_presentation() {
    let jwt_token = "eyJhbGciOiJhbGdvcml0aG0iLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE2OTkzNTc1ODIsI\
        mV4cCI6MTY5OTM1Nzg4MiwibmJmIjoxNjk5MzU3NTM3LCJpc3MiOiJob2xkZXJfZGlkIiwic3ViIjoiaG9sZGVy\
        X2RpZCIsImp0aSI6IjY2YWFiNmE2LWQxNWMtNDNkYi1iMDk1LTM5MWE3NWFmYzc4ZSIsInZwIjp7IkBjb250ZXh\
        0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZV\
        ByZXNlbnRhdGlvbiJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6WyJleUpoYkdjaU9pSmhiR2R2Y21sMGFHMGlMQ\
        0owZVhBaU9pSlRSRXBYVkNKOS5leUpwWVhRaU9qRTJPVGt5TnpBeU5qWXNJbVY0Y0NJNk1UYzJNak0wTWpJMk5p\
        d2libUptSWpveE5qazVNamN3TWpJeExDSnBjM01pT2lKSmMzTjFaWElnUkVsRUlpd2ljM1ZpSWpvaWFHOXNaR1Z\
        5WDJScFpDSXNJbXAwYVNJNklqbGhOREUwWVRZd0xUbGxObUl0TkRjMU55MDRNREV4TFRsaFlUZzNNR1ZtTkRjNE\
        9DSXNJblpqSWpwN0lrQmpiMjUwWlhoMElqcGJJbWgwZEhCek9pOHZkM2QzTG5jekxtOXlaeTh5TURFNEwyTnlaV\
        1JsYm5ScFlXeHpMM1l4SWl3aVEyOXVkR1Y0ZERFaVhTd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdW\
        dWRHbGhiQ0lzSWxSNWNHVXhJbDBzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0lsOXpaQ0k2V3lKWlYwcHF\
        UVlJKZWlJc0lsbFhTbXBOVkVsNklsMTlMQ0pqY21Wa1pXNTBhV0ZzVTNSaGRIVnpJanA3SW1sa0lqb2lVMVJCVk\
        ZWVFgwbEVJaXdpZEhsd1pTSTZJbFJaVUVVaUxDSnpkR0YwZFhOUWRYSndiM05sSWpvaVVGVlNVRTlUUlNJc0lrW\
        nBaV3hrTVNJNklsWmhiREVpZlgwc0lsOXpaRjloYkdjaU9pSnphR0V0TWpVMkluMC5RVUpEIl19fQ";
    let presentation_token = format!("{jwt_token}.QUJD");

    let leeway = 45u64;

    let jwt_formatter = JWTFormatter {
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

    let result = jwt_formatter
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
        Some(DidValue::from("holder_did".to_owned()))
    );
}

#[test]
fn test_get_capabilities() {
    let jwt_formatter = JWTFormatter {
        params: Params {
            leeway: 123u64,
            embed_layout_properties: false,
        },
    };

    assert_eq!(1, jwt_formatter.get_capabilities().features.len());
}

#[test]
fn test_schema_id() {
    let formatter = JWTFormatter {
        params: Params {
            leeway: 123u64,
            embed_layout_properties: false,
        },
    };
    let request_dto = CreateCredentialSchemaRequestDTO {
        name: "".to_string(),
        format: "".to_string(),
        revocation_method: "".to_string(),
        organisation_id: OrganisationId::from(Uuid::new_v4()),
        claims: vec![],
        wallet_storage_type: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: None,
        allow_suspension: None,
    };

    let id = CredentialSchemaId::from(Uuid::new_v4());
    let result = formatter.credential_schema_id(id, &request_dto, "https://example.com");
    assert!(result.is_ok());
    assert_eq!(
        result.unwrap(),
        format!("https://example.com/ssi/schema/v1/{id}")
    )
}
