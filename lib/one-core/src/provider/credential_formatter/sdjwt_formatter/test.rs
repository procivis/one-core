use std::{collections::HashMap, sync::Arc};

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use mockall::predicate::eq;
use time::Duration;

use super::{prepare_sd_presentation, SDJWTFormatter};

use crate::{
    crypto::{hasher::MockHasher, MockCryptoProvider},
    provider::credential_formatter::{
        jwt::model::JWTPayload,
        model::{CredentialPresentation, CredentialStatus},
        sdjwt_formatter::{model::Sdvc, Params},
        test_utilities::{
            test_credential_detail_response_dto, test_credential_detail_response_dto_with_array,
        },
        CredentialData, CredentialFormatter, ExtractPresentationCtx, MockAuth, MockTokenVerifier,
    },
};

#[tokio::test]
async fn test_format_credential() {
    let mut hasher = MockHasher::default();
    hasher
        .expect_hash_base64()
        .times(2) // Number of claims
        .returning(|_| Ok(String::from("YWJjMTIz")));
    let hasher = Arc::new(hasher);

    let mut crypto = MockCryptoProvider::default();

    crypto
        .expect_get_hasher()
        .once()
        .with(eq("sha-256"))
        .returning(move |_| Ok(hasher.clone()));

    crypto
        .expect_generate_salt_base64()
        .times(2) // Number of claims
        .returning(|| String::from("MTIzYWJj"));

    let leeway = 45u64;

    let sd_formatter = SDJWTFormatter {
        crypto: Arc::new(crypto),
        params: Params { leeway },
    };

    let credential_details = test_credential_detail_response_dto();
    let credential_data = CredentialData::from_credential_detail_response(
        credential_details,
        "http://base_url",
        vec![CredentialStatus {
            id: "STATUS_ID".to_string(),
            r#type: "TYPE".to_string(),
            status_purpose: Some("PURPOSE".to_string()),
            additional_fields: HashMap::from([("Field1".to_owned(), "Val1".to_owned())]),
        }],
    )
    .unwrap();

    let auth_fn = MockAuth(|_| vec![65u8, 66, 67]);

    let result = sd_formatter
        .format_credentials(
            credential_data,
            &"holder_did".parse().unwrap(),
            "algorithm",
            vec!["Context1".to_string()],
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

    assert_eq!(
        parts[1],
        &Base64UrlSafeNoPadding::encode_to_string(r#"["MTIzYWJj","name","John"]"#).unwrap()
    );
    assert_eq!(
        parts[2],
        &Base64UrlSafeNoPadding::encode_to_string(r#"["MTIzYWJj","age","42"]"#).unwrap()
    );

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

    assert_eq!(payload.issuer, Some(String::from("Issuer DID")));
    assert_eq!(payload.subject, Some(String::from("holder_did")));

    let vc = payload.custom.vc;

    assert!(vc
        .credential_subject
        .claims
        .iter()
        .all(|hashed_claim| hashed_claim == "YWJjMTIz"));

    assert!(vc.context.contains(&String::from("Context1")));
    assert!(vc.r#type.contains(&String::from("Type1")));

    assert_eq!(1, vc.credential_status.len());
    let first_credential_status = vc.credential_status.first().unwrap();
    assert_eq!(first_credential_status.id, "STATUS_ID");
    assert_eq!(first_credential_status.r#type, "TYPE");
    assert_eq!(
        first_credential_status.status_purpose.as_deref(),
        Some("PURPOSE")
    );
    assert_eq!(
        first_credential_status.additional_fields.get("Field1"),
        Some(&"Val1".to_string())
    );
}

#[tokio::test]
async fn test_format_credential_with_array() {
    let mut hasher = MockHasher::default();
    hasher
        .expect_hash_base64()
        .times(3) // Number of claims
        .returning(|_| Ok(String::from("YWJjMTIz")));
    let hasher = Arc::new(hasher);

    let mut crypto = MockCryptoProvider::default();

    crypto
        .expect_get_hasher()
        .once()
        .with(eq("sha-256"))
        .returning(move |_| Ok(hasher.clone()));

    crypto
        .expect_generate_salt_base64()
        .times(3) // Number of claims
        .returning(|| String::from("MTIzYWJj"));

    let leeway = 45u64;

    let sd_formatter = SDJWTFormatter {
        crypto: Arc::new(crypto),
        params: Params { leeway },
    };

    let credential_details = test_credential_detail_response_dto_with_array();
    let credential_data = CredentialData::from_credential_detail_response(
        credential_details,
        "http://base_url",
        vec![CredentialStatus {
            id: "STATUS_ID".to_string(),
            r#type: "TYPE".to_string(),
            status_purpose: Some("PURPOSE".to_string()),
            additional_fields: HashMap::new(),
        }],
    )
    .unwrap();

    let auth_fn = MockAuth(|_| vec![65u8, 66, 67]);

    let result = sd_formatter
        .format_credentials(
            credential_data,
            &"holder_did".parse().unwrap(),
            "algorithm",
            vec!["Context1".to_string()],
            vec!["Type1".to_string()],
            Box::new(auth_fn),
            None,
            None,
        )
        .await;

    assert!(result.is_ok());

    let token = result.unwrap();

    let parts: Vec<&str> = token.splitn(4, '~').collect();

    assert_eq!(parts.len(), 4);

    // WARNING! It's not in line with the standard but we will adjust the implementation
    // to the standard in a separate ticket.
    assert_eq!(
        parts[1],
        &Base64UrlSafeNoPadding::encode_to_string(r#"["MTIzYWJj","root/array/0","array_item"]"#)
            .unwrap()
    );
    assert_eq!(
        parts[2],
        &Base64UrlSafeNoPadding::encode_to_string(r#"["MTIzYWJj","root/nested","nested_item"]"#)
            .unwrap()
    );
    assert_eq!(
        parts[3],
        &Base64UrlSafeNoPadding::encode_to_string(r#"["MTIzYWJj","root_item","root_item"]"#)
            .unwrap()
    );

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

    assert_eq!(payload.issuer, Some(String::from("Issuer DID")));
    assert_eq!(payload.subject, Some(String::from("holder_did")));

    let vc = payload.custom.vc;

    assert!(vc
        .credential_subject
        .claims
        .iter()
        .all(|hashed_claim| hashed_claim == "YWJjMTIz"));
}

#[tokio::test]
async fn test_extract_credentials() {
    let jwt_token = "eyJhbGciOiJhbGdvcml0aG0iLCJ0eXAiOiJTREpXVCJ9.\
        eyJpYXQiOjE2OTkyNzAyNjYsImV4cCI6MTc2MjM0MjI2NiwibmJmIjoxNjk5Mjcw\
        MjIxLCJpc3MiOiJJc3N1ZXIgRElEIiwic3ViIjoiaG9sZGVyX2RpZCIsImp0aSI6\
        IjlhNDE0YTYwLTllNmItNDc1Ny04MDExLTlhYTg3MGVmNDc4OCIsInZjIjp7IkBj\
        b250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3Yx\
        IiwiQ29udGV4dDEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlR5\
        cGUxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Il9zZCI6WyJZV0pqTVRJeiIsIllX\
        SmpNVEl6Il19LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiU1RBVFVTX0lEIiwi\
        dHlwZSI6IlRZUEUiLCJzdGF0dXNQdXJwb3NlIjoiUFVSUE9TRSIsIkZpZWxkMSI6\
        IlZhbDEifX0sIl9zZF9hbGciOiJzaGEtMjU2In0";
    let token = format!(
        "{jwt_token}.QUJD~WyJNVEl6WVdKaiIsIm5hbWUiLCJKb2huIl0~WyJNVEl6WVdKaiIsImFnZSIsIjQyIl0"
    );

    let mut hasher = MockHasher::default();
    hasher
        .expect_hash_base64()
        .times(2) // Number of claims
        .returning(|_| Ok(String::from("YWJjMTIz")));
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
        params: Params { leeway },
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

    let result = sd_formatter
        .extract_credentials(&token, Box::new(verify_mock))
        .await;

    let credentials = result.unwrap();

    assert_eq!(credentials.issuer_did, Some("Issuer DID".parse().unwrap()));
    assert_eq!(credentials.subject, Some("holder_did".parse().unwrap()));

    assert_eq!(1, credentials.status.len());
    let first_credential_status = credentials.status.first().unwrap();
    assert_eq!(first_credential_status.id, "STATUS_ID");
    assert_eq!(first_credential_status.r#type, "TYPE");
    assert_eq!(
        first_credential_status.status_purpose.as_deref(),
        Some("PURPOSE")
    );
    assert_eq!(
        first_credential_status.additional_fields.get("Field1"),
        Some(&"Val1".to_string())
    );

    assert_eq!(credentials.claims.values.get("name").unwrap(), "John");
    assert_eq!(credentials.claims.values.get("age").unwrap(), "42");
}

#[tokio::test]
async fn test_extract_credentials_with_array() {
    let jwt_token = "eyJhbGciOiJhbGdvcml0aG0iLCJraWQiOiIja2V5MCIsInR5cCI6IlNESldUIn0\
        .eyJpYXQiOjE3MTgzNTkwNjMsImV4cCI6MTc4MTQzMTA2MywibmJmIjoxNzE4MzU5MDE4LCJpc3MiOiJJc\
        3N1ZXIgRElEIiwic3ViIjoiaG9sZGVyX2RpZCIsImp0aSI6Imh0dHA6Ly9iYXNlX3VybC9zc2kvY3JlZGV\
        udGlhbC92MS85YTQxNGE2MC05ZTZiLTQ3NTctODAxMS05YWE4NzBlZjQ3ODgiLCJ2YyI6eyJAY29udGV4d\
        CI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsIkNvbnRleHQxIl0sImlkIjo\
        iaHR0cDovL2Jhc2VfdXJsL3NzaS9jcmVkZW50aWFsL3YxLzlhNDE0YTYwLTllNmItNDc1Ny04MDExLTlhY\
        Tg3MGVmNDc4OCIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJUeXBlMSJdLCJjcmVkZW50aWF\
        sU3ViamVjdCI6eyJfc2QiOlsiWVdKak1USXoiLCJZV0pqTVRJeiIsIllXSmpNVEl6Il19LCJjcmVkZW50a\
        WFsU3RhdHVzIjp7ImlkIjoiU1RBVFVTX0lEIiwidHlwZSI6IlRZUEUiLCJzdGF0dXNQdXJwb3NlIjoiUFV\
        SUE9TRSJ9LCJjcmVkZW50aWFsU2NoZW1hIjp7ImlkIjoiQ3JlZGVudGlhbFNjaGVtYUlkIiwidHlwZSI6I\
        lByb2NpdmlzT25lU2NoZW1hMjAyNCJ9fSwiX3NkX2FsZyI6InNoYS0yNTYifQ";
    let token = format!(
        "{jwt_token}.QUJD~WyJNVEl6WVdKaiIsInJvb3QvYXJyYXkvMCIsImFycmF5X2l0ZW0iXQ~WyJNVEl6W\
            VdKaiIsInJvb3QvbmVzdGVkIiwibmVzdGVkX2l0ZW0iXQ~WyJNVEl6WVdKaiIsInJvb3RfaXRlbSIs\
            InJvb3RfaXRlbSJd"
    );

    let mut hasher = MockHasher::default();
    hasher
        .expect_hash_base64()
        .times(3) // Number of claims
        .returning(|_| Ok(String::from("YWJjMTIz")));
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
        params: Params { leeway },
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

    let result = sd_formatter
        .extract_credentials(&token, Box::new(verify_mock))
        .await;

    let credentials = result.unwrap();

    let root_item = credentials.claims.values.get("root_item").unwrap();
    assert_eq!(root_item.as_str(), Some("root_item"));

    let root = credentials.claims.values.get("root").unwrap();
    let nested = root.get("nested").unwrap();
    assert_eq!(nested.as_str(), Some("nested_item"));

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
        params: Params { leeway },
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
            ExtractPresentationCtx::empty(),
        )
        .await;

    assert!(result.is_ok());

    let presentation = result.unwrap();

    assert_eq!(
        presentation.expires_at,
        Some(presentation.issued_at.unwrap() + Duration::minutes(5)),
    );

    assert_eq!(presentation.credentials.len(), 1);
    assert_eq!(presentation.issuer_did, Some("holder_did".parse().unwrap()));
}

#[test]
fn test_prepare_sd_presentation() {
    let jwt_token = "eyJhbGciOiJhbGdvcml0aG0iLCJ0eXAiOiJTREpXVCJ9.\
    eyJpYXQiOjE2OTkyNzAyNjYsImV4cCI6MTc2MjM0MjI2NiwibmJmIjoxNjk5Mjcw\
    MjIxLCJpc3MiOiJJc3N1ZXIgRElEIiwic3ViIjoiaG9sZGVyX2RpZCIsImp0aSI6\
    IjlhNDE0YTYwLTllNmItNDc1Ny04MDExLTlhYTg3MGVmNDc4OCIsInZjIjp7IkBj\
    b250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3Yx\
    IiwiQ29udGV4dDEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlR5\
    cGUxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Il9zZCI6WyJZV0pqTVRJeiIsIllX\
    SmpNVEl6Il19LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiU1RBVFVTX0lEIiwi\
    dHlwZSI6IlRZUEUiLCJzdGF0dXNQdXJwb3NlIjoiUFVSUE9TRSIsIkZpZWxkMSI6\
    IlZhbDEifX0sIl9zZF9hbGciOiJzaGEtMjU2In0";

    let key_name = "WyJNVEl6WVdKaiIsIm5hbWUiLCJKb2huIl0";
    let key_age = "WyJNVEl6WVdKaiIsImFnZSIsIjQyIl0";

    let token = format!("{jwt_token}.QUJD~{key_name}~{key_age}");

    // Take name and age
    let presentation = CredentialPresentation {
        token: token.clone(),
        disclosed_keys: vec!["name".to_string(), "age".to_string()],
    };

    let result = prepare_sd_presentation(presentation);
    assert!(result.is_ok_and(|token| token.contains(key_name) && token.contains(key_age)));

    // Take name
    let presentation = CredentialPresentation {
        token: token.clone(),
        disclosed_keys: vec!["name".to_string()],
    };

    let result = prepare_sd_presentation(presentation);
    assert!(result.is_ok_and(|token| token.contains(key_name) && !token.contains(key_age)));

    // Take age
    let presentation = CredentialPresentation {
        token: token.clone(),
        disclosed_keys: vec!["age".to_string()],
    };

    let result = prepare_sd_presentation(presentation);
    assert!(result.is_ok_and(|token| !token.contains(key_name) && token.contains(key_age)));

    // Take none
    let presentation = CredentialPresentation {
        token,
        disclosed_keys: vec![],
    };

    let result = prepare_sd_presentation(presentation);
    assert!(result.is_ok_and(|token| !token.contains(key_name) && !token.contains(key_age)));
}

#[test]
fn test_get_capabilities() {
    let sd_formatter = SDJWTFormatter {
        crypto: Arc::new(MockCryptoProvider::default()),
        params: Params { leeway: 123u64 },
    };

    assert_eq!(
        vec!["SELECTIVE_DISCLOSURE".to_string()],
        sd_formatter.get_capabilities().features
    );
}
